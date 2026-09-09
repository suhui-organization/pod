/**
 * pod onboard 测试：发现 → dry-run 计划 → 接管改写 + 备份 + 策略 → 回滚。
 */
import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { applyOnboard, buildWrapArgs, computeCoverage, discoverTargets, isPodCommand, revertOnboard } from '../src/onboard.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const CLI_INDEX = join(HERE, '../src/index.ts');

function makeHome(): { home: string; dsh: string; claude: string } {
  const home = mkdtempSync(join(tmpdir(), 'pod-onboard-'));
  mkdirSync(join(home, '.dsh'), { recursive: true });
  const dsh = join(home, '.dsh', 'mcp-manager.json');
  writeFileSync(
    dsh,
    JSON.stringify({
      servers: [
        { name: 'filesystem', transport: 'stdio', command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystem', '/tmp'] },
        { name: 'remote', transport: 'sse', command: 'node', args: ['server.js'] },
      ],
    }),
    'utf8',
  );
  const claude = join(home, '.claude.json');
  writeFileSync(
    claude,
    JSON.stringify({
      mcpServers: {
        github: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-github'], env: { GITHUB_TOKEN: 'x' } },
      },
    }),
    'utf8',
  );
  return { home, dsh, claude };
}

describe('isPodCommand / buildWrapArgs', () => {
  it('detects already-wrapped servers', () => {
    expect(isPodCommand('pod', ['serve', '--agent', 'a'])).toBe(true);
    expect(isPodCommand('/usr/local/bin/pod', ['record'])).toBe(true);
    expect(isPodCommand('node', ['/Users/x/.pod/pod-serve-codex-stdio.sh'])).toBe(true);
    expect(isPodCommand('node', ['/Users/x/pod/apps/cli/src/index.ts', 'record', '--config', 'x'])).toBe(true);
    expect(isPodCommand('npx', ['-y', 'server'])).toBe(false);
    expect(isPodCommand('node', ['server.js', 'record'])).toBe(false);
    expect(isPodCommand('npx', ['-y', 'podcast-server'])).toBe(false);
    expect(isPodCommand('pod', ['scan'])).toBe(false);
  });

  it('builds a record-only wrap that preserves the original command and args', () => {
    const server = { name: 'fs', command: 'npx', args: ['-y', 'pkg', '/tmp'], location: { kind: 'array' as const, index: 0 }, wrapped: false };
    const wrap = buildWrapArgs(server, 'dsh', '/home/.pod/policies/onboard-dsh.json');
    expect(wrap.command).toBe('pod');
    expect(wrap.args).toContain('--record-only');
    expect(wrap.args).toContain('--server');
    expect(wrap.args).toContain('fs');
    expect(wrap.args.join(' ')).toContain('--command npx');
    expect(wrap.args.join(' ')).toContain('--arg -y');
    expect(wrap.args.join(' ')).toContain('--arg /tmp');
  });

  it('honors a custom pod binary path', () => {
    const server = { name: 'fs', command: 'npx', args: ['-y', 'pkg'], location: { kind: 'array' as const, index: 0 }, wrapped: false };
    const wrap = buildWrapArgs(server, 'dsh', '/p.json', '/opt/homebrew/bin/pod');
    expect(wrap.command).toBe('/opt/homebrew/bin/pod');
  });
});

describe('discoverTargets / applyOnboard / revertOnboard', () => {
  it('discovers DSH and Claude configs', () => {
    const { home } = makeHome();
    const targets = discoverTargets({ home });
    expect(targets.map((t) => t.format).sort()).toEqual(['claude', 'dsh']);
    const dsh = targets.find((t) => t.format === 'dsh')!;
    expect(dsh.servers.map((s) => s.name)).toEqual(['filesystem', 'remote']);
  });

  it('dry-run reports a plan but writes nothing', () => {
    const { home, dsh } = makeHome();
    const before = readFileSync(dsh, 'utf8');
    const policyDir = join(home, 'policies');
    const result = applyOnboard(discoverTargets({ home }), { policyDir, dryRun: true });
    expect(result.changes.length).toBe(2);
    expect(readFileSync(dsh, 'utf8')).toBe(before);
    expect(existsSync(policyDir)).toBe(false);
  });

  it('applies the wrap, keeps env, writes policy and creates a backup', () => {
    const { home, dsh, claude } = makeHome();
    const policyDir = join(home, 'policies');
    const result = applyOnboard(discoverTargets({ home }), { policyDir, dryRun: false, timestamp: 'test' });

    const rewrittenDsh = JSON.parse(readFileSync(dsh, 'utf8'));
    const fsEntry = rewrittenDsh.servers.find((s: { name: string }) => s.name === 'filesystem');
    expect(fsEntry.command).toBe('pod');
    expect(fsEntry.args).toContain('--record-only');
    expect(fsEntry.args).toContain('--command');

    const rewrittenClaude = JSON.parse(readFileSync(claude, 'utf8'));
    expect(rewrittenClaude.mcpServers.github.command).toBe('pod');
    expect(rewrittenClaude.mcpServers.github.env.GITHUB_TOKEN).toBe('x');

    expect(existsSync(`${dsh}.pod-backup-test`)).toBe(true);
    expect(existsSync(`${claude}.pod-backup-test`)).toBe(true);
    expect(result.policies.some((p) => p.endsWith('onboard-dsh.json'))).toBe(true);
    expect(result.policies.some((p) => p.endsWith('onboard-claude-code.json'))).toBe(true);
    expect(result.skipped.join('\n')).toContain('transport=sse');

    // 回滚后内容与备份一致
    const restored = revertOnboard({ home });
    expect(restored.length).toBe(2);
    expect(JSON.parse(readFileSync(dsh, 'utf8')).servers[0].command).toBe('npx');
  });
});

describe('pod onboard (CLI)', () => {
  it('dry-run prints a plan and --yes applies it, --revert restores', () => {
    const { home, dsh } = makeHome();
    const policyDir = join(home, 'policies');

    const dry = spawnSync(
      process.execPath,
      ['--import', 'tsx', CLI_INDEX, 'onboard', '--config', dsh, '--policy-dir', policyDir],
      { encoding: 'utf8' },
    );
    expect(dry.status).toBe(0);
    expect(dry.stderr).toContain('dry-run');
    expect(JSON.parse(readFileSync(dsh, 'utf8')).servers[0].command).toBe('npx');

    const apply = spawnSync(
      process.execPath,
      ['--import', 'tsx', CLI_INDEX, 'onboard', '--config', dsh, '--policy-dir', policyDir, '--yes'],
      { encoding: 'utf8' },
    );
    expect(apply.status).toBe(0);
    expect(JSON.parse(readFileSync(dsh, 'utf8')).servers[0].command).toBe('pod');

    const revert = spawnSync(
      process.execPath,
      ['--import', 'tsx', CLI_INDEX, 'onboard', '--config', dsh, '--revert'],
      { encoding: 'utf8' },
    );
    expect(revert.status).toBe(0);
    expect(revert.stderr).toContain('已恢复');
    expect(JSON.parse(readFileSync(dsh, 'utf8')).servers[0].command).toBe('npx');
  });
});

describe('computeCoverage / pod coverage', () => {
  function makeMixedHome(): string {
    const home = mkdtempSync(join(tmpdir(), 'pod-coverage-'));
    mkdirSync(join(home, '.dsh'), { recursive: true });
    writeFileSync(
      join(home, '.dsh', 'mcp-manager.json'),
      JSON.stringify({
        servers: [
          { name: 'managed', transport: 'stdio', command: 'pod', args: ['serve', '--server', 'managed'] },
          { name: 'loose', transport: 'stdio', command: 'npx', args: ['-y', 'some-mcp'] },
          { name: 'remote', transport: 'sse', command: 'node', args: ['server.js'] },
        ],
      }),
      'utf8',
    );
    return home;
  }

  it('classifies managed / unmanaged / unsupported servers', () => {
    const home = makeMixedHome();
    const coverage = computeCoverage(discoverTargets({ home }));
    expect(coverage.managed.map((m) => m.server)).toEqual(['managed']);
    expect(coverage.unmanaged.map((m) => m.server)).toEqual(['loose']);
    expect(coverage.unsupported.map((m) => m.server)).toEqual(['remote']);
  });

  it('pod coverage --strict exits 1 when an unmanaged server exists', () => {
    const home = makeMixedHome();
    const res = spawnSync(
      process.execPath,
      ['--import', 'tsx', CLI_INDEX, 'coverage', '--strict'],
      { encoding: 'utf8', env: { ...process.env, HOME: home } },
    );
    expect(res.status).toBe(1);
    expect(res.stdout).toContain('loose');
    expect(res.stdout).toContain('remote');
  });
});
