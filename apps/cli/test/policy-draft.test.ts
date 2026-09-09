/**
 * pod policy draft 测试：语料 → 最小权限草稿的语义分档与落盘。
 */
import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { AuditLog, writeAuditFile, type NewAuditEntry } from '@podsec/audit';
import { classifyTool, draftPolicyFromEntries, tokenizeToolName } from '../src/policy-draft.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const CLI_INDEX = join(HERE, '../src/index.ts');

function entry(tool: string, extra: Partial<NewAuditEntry> = {}): NewAuditEntry {
  return {
    agent: 'test-agent',
    session: 'test',
    server: 'demo',
    tool,
    argsHash: 'hash',
    decision: 'allow',
    outcome: 'ok',
    policyVersion: '0.1.0',
    ...extra,
  };
}

describe('tokenizeToolName / classifyTool', () => {
  it('tokenizes snake_case, kebab-case, camelCase and dot.case', () => {
    expect(tokenizeToolName('write_file')).toEqual(['write', 'file']);
    expect(tokenizeToolName('delete-repository')).toEqual(['delete', 'repository']);
    expect(tokenizeToolName('createPullRequest')).toEqual(['create', 'pull', 'request']);
    expect(tokenizeToolName('fs.read')).toEqual(['fs', 'read']);
  });

  it('classifies destructive / write / read-only tools', () => {
    expect(classifyTool('danger_delete').proposed).toBe('deny');
    expect(classifyTool('write_file').proposed).toBe('approve');
    expect(classifyTool('createPullRequest').proposed).toBe('approve');
    expect(classifyTool('read_file').proposed).toBe('allow');
    expect(classifyTool('now').proposed).toBe('allow');
  });
});

describe('draftPolicyFromEntries', () => {
  it('proposes allow/approve/deny by observed tool names', () => {
    const result = draftPolicyFromEntries(
      [
        {
          server: 'filesystem',
          entries: [
            entry('read_file'),
            entry('read_file'),
            entry('write_file'),
            entry('danger_delete'),
          ],
        },
      ],
      { agent: 'test-agent' },
    );
    expect(result.policy.servers!.filesystem!.allow).toEqual(['read_file']);
    expect(result.policy.servers!.filesystem!.approve).toEqual(['write_file']);
    expect(result.policy.servers!.filesystem!.deny).toEqual(['danger_delete']);
    expect(result.policy.defaultDecision).toBe('deny');
    expect(result.stats.find((s) => s.tool === 'read_file')!.calls).toBe(2);
  });

  it('forces deny when a tool ever hit a sensitive path', () => {
    const result = draftPolicyFromEntries(
      [
        {
          server: 'filesystem',
          entries: [
            entry('read_file', { reason: 'argument hits sensitive path pattern ".env" (secrets-input)' }),
          ],
        },
      ],
      { agent: 'test-agent' },
    );
    expect(result.policy.servers!.filesystem!.deny).toEqual(['read_file']);
    expect(result.stats[0]!.sensitive).toBe(1);
    expect(result.notes.join('\n')).toContain('强制 deny');
  });

  it('counts outcomes and separates servers', () => {
    const result = draftPolicyFromEntries(
      [
        { server: 'a', entries: [entry('echo'), entry('echo', { outcome: 'error' })] },
        { server: 'b', entries: [entry('now')] },
      ],
      { agent: 'test-agent' },
    );
    const echo = result.stats.find((s) => s.tool === 'echo')!;
    expect(echo.ok).toBe(1);
    expect(echo.errors).toBe(1);
    expect(Object.keys(result.policy.servers!).sort()).toEqual(['a', 'b']);
  });
});

describe('pod policy draft (CLI)', () => {
  it('reads an audit file and writes a draft policy + report', () => {
    const dir = mkdtempSync(join(tmpdir(), 'pod-draft-'));
    const auditDir = join(dir, 'audit');
    const out = join(dir, 'draft.json');
    const log = new AuditLog('0.1.0');
    log.append(entry('read_file'));
    log.append(entry('write_file'));
    log.append(entry('danger_delete'));
    writeAuditFile(join(auditDir, 'demo.jsonl'), log);

    const res = spawnSync(
      process.execPath,
      ['--import', 'tsx', CLI_INDEX, 'policy', 'draft', '--audit-dir', auditDir, '--agent', 'test-agent', '--out', out],
      { encoding: 'utf8' },
    );
    expect(res.status).toBe(0);
    expect(res.stdout).toContain('read_file');
    expect(res.stdout).toContain('write_file');
    expect(res.stdout).toContain('danger_delete');
    expect(existsSync(out)).toBe(true);
    const policy = JSON.parse(readFileSync(out, 'utf8'));
    expect(policy.agent).toBe('test-agent');
    expect(policy.defaultDecision).toBe('deny');
    expect(policy.servers.demo.allow).toEqual(['read_file']);
    expect(policy.servers.demo.approve).toEqual(['write_file']);
    expect(policy.servers.demo.deny).toEqual(['danger_delete']);
  });

  it('exits non-zero when there is no corpus', () => {
    const dir = mkdtempSync(join(tmpdir(), 'pod-draft-empty-'));
    const res = spawnSync(
      process.execPath,
      ['--import', 'tsx', CLI_INDEX, 'policy', 'draft', '--audit-dir', join(dir, 'missing')],
      { encoding: 'utf8' },
    );
    expect(res.status).toBe(1);
    expect(res.stderr).toContain('no audit records');
  });
});
