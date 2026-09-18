// 切执法 / 回到只录不拦的测试。
//
// 这一步的产品风险是"看起来生效了，其实没有保护"，所以测试重点在前置检查：
// 没有编译好的策略、或策略是 allow:["*"] 的模板，都必须拒绝执行。
import { describe, expect, it } from 'vitest';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { loadAuditFile } from '@podsec/audit';
import {
  applyEnforcement,
  applyTakeover,
  planEnforcement,
  readTakeover,
  revertTakeover,
  takeoverStatePath,
} from './takeover.js';

function fakePodBin(dir: string): string {
  const path = join(dir, 'pod');
  writeFileSync(path, '#!/bin/sh\nexit 0\n', 'utf8');
  chmodSync(path, 0o755);
  return path;
}

function readArgs(config: string): string[] {
  const parsed = JSON.parse(readFileSync(config, 'utf8')) as {
    mcpServers: Record<string, { args: string[] }>;
  };
  return parsed.mcpServers.github!.args;
}

/** 控制平面事件落在被接管 agent 的链上（见 enroll.ts 的说明：否则上不了云） */
function controlEntries(home: string, agent = 'claude-code') {
  const path = join(home, '.pod/audit', agent, 'control.jsonl');
  if (!existsSync(path)) return [];
  return loadAuditFile(path, 'control').entries;
}

/** 建一个"已接管（只录不拦）"的环境 */
function takenOver(): { home: string; config: string; podBin: string } {
  const home = mkdtempSync(join(tmpdir(), 'pod-enforce-'));
  mkdirSync(join(home, '.claude'), { recursive: true });
  const config = join(home, '.claude.json');
  writeFileSync(
    config,
    JSON.stringify({ mcpServers: { github: { command: 'npx', args: ['-y', 'pkg'] } } }),
    'utf8',
  );
  const podBin = fakePodBin(home);
  applyTakeover({ home, podHome: join(home, '.pod'), harness: 'claude-code', podBin });
  return { home, config, podBin };
}

function writePolicy(home: string, file: string, body: unknown): string {
  const dir = join(home, '.pod/policies');
  mkdirSync(dir, { recursive: true });
  const path = join(dir, file);
  writeFileSync(path, JSON.stringify(body), 'utf8');
  return path;
}

describe('planEnforcement 的前置检查', () => {
  it('没有编译好的策略时拒绝执行，并给出要跑的命令与语料量', () => {
    const { home } = takenOver();
    const plan = planEnforcement({ home, podHome: join(home, '.pod'), harness: 'claude-code', mode: 'enforce' });
    expect(plan.applicable).toBe(false);
    expect(plan.blockedReason).toContain('pod policy draft');
    expect(plan.blockedReason).toContain('语料');
    expect(plan.corpus).toBe(0);
    expect(() =>
      applyEnforcement({ home, podHome: join(home, '.pod'), harness: 'claude-code', mode: 'enforce' }),
    ).toThrow();
  });

  it('零权限策略（servers 空表）不算"编译好的策略"', () => {
    const { home } = takenOver();
    writePolicy(home, 'claude-code.json', {
      version: '0.1.0',
      agent: 'claude-code',
      defaultDecision: 'deny',
      servers: {},
    });
    const plan = planEnforcement({ home, podHome: join(home, '.pod'), harness: 'claude-code', mode: 'enforce' });
    expect(plan.applicable).toBe(false);
  });

  it('allow:["*"] 的 record 模板被拒（否则等于假保护）', () => {
    const { home } = takenOver();
    // 把它伪装成一份"有 server 规则"的策略，但规则是 allow-all
    writePolicy(home, 'draft.json', {
      version: '0.1.0',
      agent: 'claude-code',
      defaultDecision: 'deny',
      servers: { github: { allow: ['*'] } },
    });
    const plan = planEnforcement({ home, podHome: join(home, '.pod'), harness: 'claude-code', mode: 'enforce' });
    expect(plan.applicable).toBe(false);
    expect(plan.blockedReason).toContain('allow');
  });

  it('onboard-*.json（接管时的包装策略）不参与执法选型', () => {
    const { home } = takenOver();
    const plan = planEnforcement({ home, podHome: join(home, '.pod'), harness: 'claude-code', mode: 'enforce' });
    expect(plan.policyPath).toBeNull();
    expect(plan.applicable).toBe(false);
  });

  it('计划里带着"改前/改后"与策略概要，且不写任何文件', () => {
    const { home, config } = takenOver();
    const policy = writePolicy(home, 'draft.json', {
      version: '0.1.0',
      agent: 'claude-code',
      defaultDecision: 'deny',
      servers: { github: { allow: ['search'], approve: ['create_issue'], deny: ['delete_repo'] } },
    });
    const before = readFileSync(config, 'utf8');
    const plan = planEnforcement({ home, podHome: join(home, '.pod'), harness: 'claude-code', mode: 'enforce' });
    expect(plan.applicable).toBe(true);
    expect(plan.policyPath).toBe(policy);
    expect(plan.policySummary).toEqual({
      servers: 1,
      tools: 3,
      allow: 1,
      approve: 1,
      deny: 1,
      allowAll: false,
    });
    const entry = plan.entries[0]!;
    expect(entry.servers[0]!.from).toContain('--record-only');
    expect(entry.servers[0]!.to).not.toContain('--record-only');
    expect(entry.servers[0]!.to).toContain(policy);
    expect(readFileSync(config, 'utf8')).toBe(before);
  });
});

describe('applyEnforcement（切执法 / 回到只录不拦）', () => {
  it('切执法：去掉 --record-only、指向编译好的策略、备份、入链', () => {
    const { home, config } = takenOver();
    const policy = writePolicy(home, 'draft.json', {
      version: '0.1.0',
      agent: 'claude-code',
      defaultDecision: 'deny',
      servers: { github: { allow: ['search'] } },
    });
    const result = applyEnforcement({
      home,
      podHome: join(home, '.pod'),
      harness: 'claude-code',
      mode: 'enforce',
    });
    expect(result.mode).toBe('enforce');
    const args = readArgs(config);
    expect(args).not.toContain('--record-only');
    expect(args[args.indexOf('--policy') + 1]).toBe(policy);
    expect(existsSync(result.changed[0]!.backup)).toBe(true);
    expect(controlEntries(home).map((e) => e.tool)).toEqual(['takeover', 'enforce']);
    expect(readTakeover(takeoverStatePath(join(home, '.pod'))).agents['claude-code']!.mode).toBe('enforce');
  });

  it('回到只录不拦：把 --record-only 加回来，策略不变', () => {
    const { home, config } = takenOver();
    const policy = writePolicy(home, 'draft.json', {
      version: '0.1.0',
      agent: 'claude-code',
      defaultDecision: 'deny',
      servers: { github: { allow: ['search'] } },
    });
    applyEnforcement({ home, podHome: join(home, '.pod'), harness: 'claude-code', mode: 'enforce' });
    const back = applyEnforcement({
      home,
      podHome: join(home, '.pod'),
      harness: 'claude-code',
      mode: 'record-only',
    });
    expect(back.mode).toBe('record-only');
    const args = readArgs(config);
    expect(args).toContain('--record-only');
    expect(args[args.indexOf('--policy') + 1]).toBe(policy);
    expect(controlEntries(home).map((e) => e.tool)).toEqual(['takeover', 'enforce', 'record-only']);
  });

  it('已经在该模式下时拒绝执行（不制造无意义的备份与事件）', () => {
    const { home } = takenOver();
    const plan = planEnforcement({ home, podHome: join(home, '.pod'), harness: 'claude-code', mode: 'record-only' });
    expect(plan.applicable).toBe(false);
    expect(plan.blockedReason).toContain('只录不拦');
  });

  it('「还原配置」是逐步撤销：先退回只录不拦，再恢复到接管之前', () => {
    const { home, config } = takenOver();
    const original = readFileSync(config, 'utf8');
    writePolicy(home, 'draft.json', {
      version: '0.1.0',
      agent: 'claude-code',
      defaultDecision: 'deny',
      servers: { github: { allow: ['search'] } },
    });
    applyEnforcement({ home, podHome: join(home, '.pod'), harness: 'claude-code', mode: 'enforce' });
    expect(readArgs(config)).not.toContain('--record-only');

    const first = revertTakeover({ home, podHome: join(home, '.pod'), agent: 'claude-code' });
    expect(first.restored).toHaveLength(1);
    expect(readArgs(config)).toContain('--record-only');
    expect(readTakeover(takeoverStatePath(join(home, '.pod'))).agents['claude-code']).toBeTruthy();

    const second = revertTakeover({ home, podHome: join(home, '.pod'), agent: 'claude-code' });
    expect(second.restored).toHaveLength(1);
    expect(readFileSync(config, 'utf8')).toBe(original);
    expect(readTakeover(takeoverStatePath(join(home, '.pod'))).agents['claude-code']).toBeUndefined();
  });
});
