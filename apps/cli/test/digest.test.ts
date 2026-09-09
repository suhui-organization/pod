/**
 * pod digest 测试：审计聚合、告警归类、审批统计、覆盖率提示。
 */
import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { AuditLog, writeAuditFile, type AuditEntry, type NewAuditEntry } from '@podsec/audit';
import { buildDigest, renderDigest } from '../src/digest.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const CLI_INDEX = join(HERE, '../src/index.ts');

function entry(over: Partial<NewAuditEntry> = {}, ts = '2026-01-02T00:00:00.000Z'): AuditEntry {
  const log = new AuditLog('0.1.0', { now: () => new Date(ts) });
  return log.append({
    agent: 'a',
    session: 's',
    server: 'demo',
    tool: 'echo',
    argsHash: 'h',
    decision: 'allow',
    outcome: 'ok',
    policyVersion: '0.1.0',
    ...over,
  });
}

const WINDOW = { from: '2026-01-01T00:00:00.000Z', to: '2026-01-08T00:00:00.000Z' };

describe('buildDigest', () => {
  it('aggregates totals, alerts, approvals and highlights', () => {
    const d = buildDigest(
      [
        {
          server: 'demo',
          entries: [
            entry(),
            entry({ decision: 'deny', outcome: 'blocked', reason: 'tool "x" is denied' }),
            entry({ decision: 'approve', outcome: 'ok', approver: 'walden' }),
            entry({ decision: 'approve', outcome: 'blocked', reason: 'denied by approver' }),
            entry({ decision: 'approve', outcome: 'blocked', reason: 'approval timed out after 5s (fail-closed)' }),
            entry({ decision: 'allow', outcome: 'blocked', reason: 'secret_leak: output matched pattern ghp_' }),
          ],
        },
      ],
      WINDOW,
    );
    expect(d.totals.calls).toBe(6);
    expect(d.totals.deny).toBe(1);
    expect(d.totals.approve).toBe(3);
    expect(d.alerts.map((a) => a.kind).sort()).toEqual(['approval_timeout', 'deny', 'secret_leak']);
    expect(d.approvals).toMatchObject({ total: 3, approved: 1, denied: 1, timeout: 1 });
    expect(d.approvals.approvers).toEqual(['walden']);
    const text = d.highlights.join('\n');
    expect(text).toContain('拦截');
    expect(text).toContain('密钥外泄');
    expect(text).toContain('人工审批');
  });

  it('excludes entries outside the window', () => {
    const outside = entry({}, '2025-12-01T00:00:00.000Z');
    const d = buildDigest([{ server: 'demo', entries: [outside, entry()] }], WINDOW);
    expect(d.totals.calls).toBe(1);
  });

  it('flags unmanaged servers and broken chains in highlights', () => {
    const d = buildDigest([{ server: 'demo', entries: [entry()] }], {
      ...WINDOW,
      chain: [{ server: 'demo', ok: false, entries: 1 }],
      coverage: { managed: [], unmanaged: ['github'] },
    });
    const text = d.highlights.join('\n');
    expect(text).toContain('未受管');
    expect(text).toContain('哈希链异常');
  });
});

describe('renderDigest', () => {
  it('renders the human-facing report sections', () => {
    const d = buildDigest([{ server: 'demo', entries: [entry()] }], WINDOW);
    const md = renderDigest(d);
    expect(md).toContain('# pod 本地安全周报');
    expect(md).toContain('## 调用总览');
    expect(md).toContain('## 审批与拦截');
    expect(md).toContain('只读本地审计');
  });
});

describe('pod digest (CLI)', () => {
  it('prints a markdown digest and supports --json', () => {
    const dir = mkdtempSync(join(tmpdir(), 'pod-digest-'));
    const log = new AuditLog('0.1.0');
    log.append({ agent: 'a', session: 's', server: 'demo', tool: 'read_file', argsHash: 'h', decision: 'allow', outcome: 'ok', policyVersion: '0.1.0' });
    log.append({ agent: 'a', session: 's', server: 'demo', tool: 'write_file', argsHash: 'h', decision: 'approve', outcome: 'blocked', approver: 'walden', policyVersion: '0.1.0' });
    writeAuditFile(join(dir, 'demo.jsonl'), log);

    const md = spawnSync(
      process.execPath,
      ['--import', 'tsx', CLI_INDEX, 'digest', '--audit-dir', dir, '--since', '7d'],
      { encoding: 'utf8' },
    );
    expect(md.status).toBe(0);
    expect(md.stdout).toContain('# pod 本地安全周报');
    expect(md.stdout).toContain('read_file');

    const json = spawnSync(
      process.execPath,
      ['--import', 'tsx', CLI_INDEX, 'digest', '--audit-dir', dir, '--since', '7d', '--json'],
      { encoding: 'utf8' },
    );
    expect(json.status).toBe(0);
    const parsed = JSON.parse(json.stdout);
    expect(parsed.totals.calls).toBe(2);
    expect(parsed.totals.approve).toBe(1);
  });
});
