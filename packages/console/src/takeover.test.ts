// 接管（把 MCP server 包进网关）的测试。
//
// 这是唯一会改写**用户配置文件**的路径，所以测试重点不是"能不能改"，
// 而是四条边界：不改非目标文件、pod 不在 PATH 就拒绝、备份能还原、
// 已有零权限策略不被 allow-all 模板覆盖。
import { describe, expect, it } from 'vitest';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { loadAuditFile } from '@podsec/audit';
import {
  applyTakeover,
  findTakeoverForHarness,
  planTakeover,
  readTakeover,
  revertTakeover,
  takeoverStatePath,
} from './takeover.js';

/** 造一个"pod 可执行文件"给 preflight 用（不真的执行它） */
function fakePodBin(dir: string): string {
  const path = join(dir, 'pod');
  writeFileSync(path, '#!/bin/sh\nexit 0\n', 'utf8');
  chmodSync(path, 0o755);
  return path;
}

function makeHome(): { home: string; config: string; podBin: string } {
  const home = mkdtempSync(join(tmpdir(), 'pod-takeover-'));
  mkdirSync(join(home, '.claude'), { recursive: true });
  const config = join(home, '.claude.json');
  writeFileSync(
    config,
    JSON.stringify({
      mcpServers: {
        github: { command: 'npx', args: ['-y', 'pkg'] },
        fs: { command: 'mcp-server-filesystem', args: ['/tmp'] },
      },
    }),
    'utf8',
  );
  return { home, config, podBin: fakePodBin(home) };
}

function readServers(config: string): Record<string, { command: string; args: string[] }> {
  const parsed = JSON.parse(readFileSync(config, 'utf8')) as {
    mcpServers: Record<string, { command: string; args: string[] }>;
  };
  return parsed.mcpServers;
}

/** 控制平面事件落在被接管 agent 的链上（见 enroll.ts 的说明：否则上不了云） */
function controlEntries(home: string, agent = 'claude-code') {
  const path = join(home, '.pod/audit', agent, 'control.jsonl');
  if (!existsSync(path)) return [];
  return loadAuditFile(path, 'control').entries;
}

describe('planTakeover', () => {
  it('给出改前/改后、备份路径与策略路径（不改任何文件）', () => {
    const { home, config, podBin } = makeHome();
    const plan = planTakeover({ home, podHome: join(home, '.pod'), harness: 'claude-code', podBin });
    expect(plan.applicable).toBe(true);
    expect(plan.entries).toHaveLength(1);
    const entry = plan.entries[0]!;
    expect(entry.configPath).toBe(config);
    expect(entry.servers.map((s) => s.name).sort()).toEqual(['fs', 'github']);
    expect(entry.servers[0]!.from).toContain('npx');
    expect(entry.servers[0]!.to).toContain('serve --record-only');
    expect(entry.backupPath).toContain('.pod-backup-');
    expect(plan.policyPath.endsWith('onboard-claude-code.json')).toBe(true);
    // 只读：计划阶段不能有任何改动
    expect(readServers(config).github!.command).toBe('npx');
    expect(existsSync(entry.backupPath)).toBe(false);
  });

  it('pod 不在 PATH/不是文件时拒绝执行（否则会写出一份跑不起来的配置）', () => {
    const { home, config } = makeHome();
    const plan = planTakeover({
      home,
      podHome: join(home, '.pod'),
      harness: 'claude-code',
      podBin: join(home, 'nope-pod'),
    });
    expect(plan.applicable).toBe(false);
    expect(plan.blockedReason).toContain('找不到');
    expect(() =>
      applyTakeover({
        home,
        podHome: join(home, '.pod'),
        harness: 'claude-code',
        podBin: join(home, 'nope-pod'),
      }),
    ).toThrow();
    expect(readServers(config).github!.command).toBe('npx');
  });

  it('TOML 配置（Codex）明确标注不支持自动改写，而不是报解析错', () => {
    const home = mkdtempSync(join(tmpdir(), 'pod-takeover-toml-'));
    mkdirSync(join(home, '.codex'), { recursive: true });
    writeFileSync(join(home, '.codex/config.toml'), '[mcp_servers.x]\ncommand = "node"\n', 'utf8');
    const plan = planTakeover({ home, podHome: join(home, '.pod'), harness: 'codex' });
    expect(plan.entries).toHaveLength(0);
    expect(plan.unsupported.join(' ')).toContain('TOML');
    expect(plan.applicable).toBe(false);
  });

  it('已包装过的 server 跳过，不再二次包装', () => {
    const { home, config, podBin } = makeHome();
    const servers = readServers(config);
    servers.github = {
      command: 'pod',
      args: ['serve', '--record-only', '--agent', 'claude-code', '--server', 'github', '--policy', 'p.json', '--command', 'npx'],
    };
    writeFileSync(config, JSON.stringify({ mcpServers: servers }), 'utf8');
    const plan = planTakeover({ home, podHome: join(home, '.pod'), harness: 'claude-code', podBin });
    expect(plan.entries[0]!.servers.map((s) => s.name)).toEqual(['fs']);
    expect(plan.skipped.join(' ')).toContain('已经指向 pod');
  });
});

describe('applyTakeover / revertTakeover', () => {
  it('备份 + 改写配置 + 写包装策略 + 入链，还原后回到原样', () => {
    const { home, config, podBin } = makeHome();
    const before = readServers(config);
    const result = applyTakeover({
      home,
      podHome: join(home, '.pod'),
      harness: 'claude-code',
      podBin,
      actor: 'pod ui',
    });

    expect(result.changed).toHaveLength(1);
    const backup = result.changed[0]!.backup;
    expect(existsSync(backup)).toBe(true);
    const after = readServers(config);
    expect(after.github!.command).toBe(podBin);
    expect(after.github!.args).toContain('--record-only');
    expect(after.fs!.args).toContain('--record-only');
    expect(existsSync(result.policyPath)).toBe(true);

    const entries = controlEntries(home);
    expect(entries.map((e) => e.tool)).toEqual(['takeover']);
    expect(entries[0]!.reason).toContain('console:takeover:claude-code');

    const state = readTakeover(takeoverStatePath(join(home, '.pod')));
    expect(findTakeoverForHarness(state, 'claude-code')?.configs).toHaveLength(1);

    const revert = revertTakeover({ home, podHome: join(home, '.pod'), agent: 'claude-code' });
    expect(revert.restored).toHaveLength(1);
    expect(readServers(config)).toEqual(before);
    expect(readTakeover(takeoverStatePath(join(home, '.pod'))).agents['claude-code']).toBeUndefined();
    expect(controlEntries(home).map((e) => e.tool)).toEqual(['takeover', 'revert']);
  });

  it('不覆盖用户已有的零权限策略（沿用而不是写 allow-all 模板）', () => {
    const { home, config, podBin } = makeHome();
    const policyDir = join(home, '.pod/policies');
    mkdirSync(policyDir, { recursive: true });
    const ownPolicy = join(policyDir, 'claude-code.json');
    writeFileSync(
      ownPolicy,
      JSON.stringify({ version: '0.1.0', agent: 'claude-code', defaultDecision: 'deny', servers: {} }),
      'utf8',
    );

    const plan = planTakeover({ home, podHome: join(home, '.pod'), harness: 'claude-code', podBin });
    expect(plan.reusesExistingPolicy).toBe(true);
    expect(plan.policyPath).toBe(ownPolicy);

    applyTakeover({ home, podHome: join(home, '.pod'), harness: 'claude-code', podBin });
    const policy = JSON.parse(readFileSync(ownPolicy, 'utf8')) as {
      defaultDecision: string;
      servers: Record<string, unknown>;
    };
    expect(policy.defaultDecision).toBe('deny');
    expect(Object.keys(policy.servers)).toHaveLength(0);
    expect(existsSync(join(policyDir, 'onboard-claude-code.json'))).toBe(false);
    // 包装命令指向的正是用户那份策略
    expect(readServers(config).github!.args.join(' ')).toContain(ownPolicy);
  });

  it('不碰其它 harness 的配置', () => {
    const { home, config, podBin } = makeHome();
    mkdirSync(join(home, '.cursor'), { recursive: true });
    const cursorConfig = join(home, '.cursor/mcp.json');
    writeFileSync(cursorConfig, JSON.stringify({ mcpServers: { c: { command: 'node', args: ['c.js'] } } }), 'utf8');
    applyTakeover({ home, podHome: join(home, '.pod'), harness: 'claude-code', podBin });
    expect(readServers(cursorConfig).c!.command).toBe('node');
    expect(readServers(config).github!.command).toBe(podBin);
  });

  it('没有可改写的 server 时拒绝执行，不留空策略', () => {
    const home = mkdtempSync(join(tmpdir(), 'pod-takeover-empty-'));
    const plan = planTakeover({ home, podHome: join(home, '.pod'), harness: 'claude-code' });
    expect(plan.applicable).toBe(false);
    expect(existsSync(join(home, '.pod/policies'))).toBe(false);
  });
});
