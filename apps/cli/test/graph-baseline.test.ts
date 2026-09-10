import { describe, expect, it } from 'vitest';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { lintPolicy } from '@podsec/policy';
import { AuditLog, writeAuditFile, type NewAuditEntry } from '@podsec/audit';

const HERE = dirname(fileURLToPath(import.meta.url));
const CLI = join(HERE, '../src/index.ts');
const DANGER = join(HERE, 'fixtures/graph/danger-server.ts');

function entry(tool: string, extra: Partial<NewAuditEntry> = {}): NewAuditEntry {
  return {
    agent: 'claude-code',
    session: 's',
    server: 'demo',
    tool,
    argsHash: 'h',
    decision: 'allow',
    outcome: 'ok',
    policyVersion: '0.1.0',
    ...extra,
  };
}

describe('pod graph baseline', () => {
  it('generates a least-privilege policy per agent', () => {
    const home = mkdtempSync(join(tmpdir(), 'pod-baseline-'));
    writeFileSync(
      join(home, '.claude.json'),
      JSON.stringify({ mcpServers: { demo: { command: process.execPath, args: ['--import', 'tsx', DANGER] } } }),
      'utf8',
    );
    const auditDir = join(home, 'audit');
    const log = new AuditLog('0.1.0');
    log.append(entry('read_file', { reason: 'argument hits sensitive path pattern ".env" (secrets-input)' }));
    log.append(entry('read_file'));
    log.append(entry('send_email'));
    log.append(entry('shadow_tool'));
    writeAuditFile(join(auditDir, 'claude-code', 'demo.jsonl'), log);
    const outDir = join(home, '.pod', 'graph');

    const build = spawnSync(process.execPath, ['--import', 'tsx', CLI, 'graph', 'build', '--home', home], {
      timeout: 30_000,
    });
    expect(build.status).toBe(0);
    const observe = spawnSync(
      process.execPath,
      ['--import', 'tsx', CLI, 'graph', 'observe', '--audit-dir', auditDir, '--out', join(outDir, 'observed.json')],
      { timeout: 30_000 },
    );
    expect(observe.status).toBe(0);

    const res = spawnSync(
      process.execPath,
      ['--import', 'tsx', CLI, 'graph', 'baseline', '--agent', 'claude-code', '--out-dir', outDir],
      { encoding: 'utf8', timeout: 30_000 },
    );
    expect(res.status).toBe(0);
    const policyPath = join(outDir, 'baselines', 'claude-code.json');
    expect(existsSync(policyPath)).toBe(true);
    const policy = JSON.parse(readFileSync(policyPath, 'utf8'));
    expect(policy.defaultDecision).toBe('deny');
    expect(policy.servers.demo.approve).toEqual(expect.arrayContaining(['read_file', 'send_email', 'shadow_tool']));
    expect(policy.servers.demo.allow).toBeUndefined();
    expect(policy.capabilityMap['demo.send_email']).toContain('external-communication');
    // 权限过载工具不进入策略
    expect(JSON.stringify(policy.servers.demo)).not.toContain('execute_command');
    expect(JSON.stringify(policy.servers.demo)).not.toContain('delete_file');
    expect(lintPolicy(policy).filter((issue) => issue.severity === 'error')).toEqual([]);
  });
});
