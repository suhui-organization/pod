/**
 * 证据链三件套测试：timeline / verify-audit / export-evidence。
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { AuditLog } from '@podsec/audit';
import {
  buildTimeline,
  verifyAll,
  exportEvidence,
  verifyEvidenceBundle,
  parseSince,
} from '../src/evidence.js';

function makeAudit(dir: string, server: string, count: number, agent = 'openclaw-main', toolBase = 'read_file'): AuditLog {
  const log = new AuditLog('0.1.0');
  for (let i = 0; i < count; i++) {
    log.append({
      agent,
      session: 's',
      server,
      tool: i % 3 === 2 ? 'write_file' : toolBase,
      argsHash: `h${i}`.padEnd(64, '0'),
      decision: i % 3 === 2 ? 'approve' : 'allow',
      outcome: 'ok',
      approver: i % 3 === 2 ? 'walden' : undefined,
      reason: i % 3 === 2 ? 'manual ok' : undefined,
      policyVersion: '0.1.0',
    });
  }
  writeFileSync(join(dir, `${server}.jsonl`), log.toJSONL(), 'utf8');
  return log;
}

describe('evidence toolkit (P0 black box)', () => {
  let dir: string;
  let auditDir: string;

  beforeAll(() => {
    dir = mkdtempSync(join(tmpdir(), 'pod-evidence-'));
    auditDir = join(dir, 'audit');
    mkdirSync(auditDir, { recursive: true });
    makeAudit(auditDir, 'filesystem', 4);
    makeAudit(auditDir, 'github', 3, 'openclaw-main', 'create_issue');
  });

  it('parseSince handles relative and ISO forms', () => {
    expect(parseSince('2h')).not.toBeNull();
    expect(parseSince('30m')).not.toBeNull();
    expect(parseSince('7d')).not.toBeNull();
    expect(parseSince('2026-01-01T00:00:00Z')).toBe('2026-01-01T00:00:00.000Z');
    expect(parseSince('garbage')).toBeNull();
  });

  it('timeline merges servers, sorts by ts, and filters', () => {
    const all = buildTimeline({ auditDir });
    expect(all.entries).toHaveLength(7);
    expect(all.broken).toHaveLength(0);
    // 按 ts 升序
    const ts = all.entries.map((e) => e.ts);
    expect([...ts].sort()).toEqual(ts);

    const filtered = buildTimeline({ auditDir, server: 'github', tool: 'create_issue' });
    expect(filtered.entries).toHaveLength(2); // github 3 条中 1 条是 write_file

    const limited = buildTimeline({ auditDir, limit: 3 });
    expect(limited.entries).toHaveLength(3);
  });

  it('timeline marks broken chains and skips them', () => {
    const badDir = join(dir, 'bad-audit');
    mkdirSync(badDir, { recursive: true });
    makeAudit(badDir, 'ok-server', 2);
    const log = new AuditLog('0.1.0');
    log.append({ agent: 'a', session: 's', server: 'bad', tool: 'x', argsHash: 'h'.padEnd(64, '0'), decision: 'allow', outcome: 'ok', policyVersion: '0.1.0' });
    const entry = { ...log.entries[0]!, outcome: 'error' as const }; // 篡改
    const bad = new AuditLog('0.1.0');
    (bad as unknown as { entries: unknown[] }).entries = [entry];
    writeFileSync(join(badDir, 'bad.jsonl'), bad.toJSONL(), 'utf8');

    const r = buildTimeline({ auditDir: badDir });
    expect(r.broken).toContain('bad');
    expect(r.entries).toHaveLength(2); // 只含 ok-server
  });

  it('verify-audit reports chain status per server', () => {
    const results = verifyAll(auditDir);
    expect(results).toHaveLength(2);
    expect(results.every((r) => r.ok)).toBe(true);
    expect(results[0]!.entries).toBe(4);
    expect(results[0]!.headHash).toMatch(/^[0-9a-f]{64}$/);
  });

  it('export-evidence produces a self-verifying bundle', () => {
    const out = join(dir, 'evidence.json');
    const bundle = exportEvidence({ auditDir, policyDir: join(dir, 'policies'), outPath: out });
    expect(bundle.format).toBe('pod-evidence-v1');
    expect(Object.keys(bundle.audits)).toHaveLength(2);
    expect(bundle.top_level_hash).toMatch(/^[0-9a-f]{64}$/);
    // 自校验
    expect(verifyEvidenceBundle(out)).toEqual({ ok: true });
    // 篡改检测
    const raw = readFileSync(out, 'utf8');
    writeFileSync(out, raw.replace('"ok": true', '"ok": false'), 'utf8');
    const r = verifyEvidenceBundle(out);
    expect(r.ok).toBe(false);
  });
});
