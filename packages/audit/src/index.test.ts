import { describe, it, expect } from 'vitest';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import {
  AuditLog,
  hashValue,
  stableStringify,
  appendToAuditFile,
  loadAuditFile,
  type AuditEntry,
} from './index.js';

const FIXED_NOW = () => new Date('2026-09-01T00:00:00.000Z');

function makeLog(policyVersion = '0.1.0', entries: Array<Partial<AuditEntry>> = []) {
  const log = new AuditLog(policyVersion, { now: FIXED_NOW });
  for (const e of entries) {
    log.append({
      agent: 'test-agent',
      session: 'sess-1',
      server: 'demo',
      tool: 'echo',
      argsHash: hashValue({ message: 'hi' }),
      decision: 'allow',
      outcome: 'ok',
      policyVersion,
      ...e,
    });
  }
  return log;
}

describe('stableStringify', () => {
  it('serializes object keys in sorted order regardless of insertion order', () => {
    const a = stableStringify({ b: 1, a: 2 });
    const b = stableStringify({ a: 2, b: 1 });
    expect(a).toBe(b);
    expect(a).toBe('{"a":2,"b":1}');
  });

  it('preserves array order', () => {
    expect(stableStringify([1, 2])).not.toBe(stableStringify([2, 1]));
  });

  it('handles nesting and primitives', () => {
    expect(stableStringify({ x: [1, { y: 2 }], z: null })).toBe('{"x":[1,{"y":2}],"z":null}');
  });
});

describe('hashValue', () => {
  it('is deterministic and order-independent', () => {
    expect(hashValue({ a: 1, b: 2 })).toBe(hashValue({ b: 2, a: 1 }));
    expect(hashValue({ a: 1, b: 2 })).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe('AuditLog', () => {
  it('chains entries: each hash covers the previous hash', () => {
    const log = makeLog('0.1.0', [{}, {}, {}]);
    expect(log.entries).toHaveLength(3);
    expect(log.entries[0]!.prevHash).toBe('');
    expect(log.entries[1]!.prevHash).toBe(log.entries[0]!.hash);
    expect(log.entries[2]!.prevHash).toBe(log.entries[1]!.hash);
    expect(log.verify()).toEqual({ ok: true });
  });

  it('assigns sequential seq and ISO timestamps', () => {
    const log = makeLog('0.1.0', [{}, {}]);
    expect(log.entries.map((e) => e.seq)).toEqual([1, 2]);
    expect(log.entries[0]!.ts).toBe('2026-09-01T00:00:00.000Z');
  });

  it('detects tampering of a middle entry', () => {
    const log = makeLog('0.1.0', [{}, {}, {}]);
    const victim = log.entries[1]!;
    (victim as { outcome: string }).outcome = 'error'; // 篡改
    const check = log.verify();
    expect(check.ok).toBe(false);
    expect(check.firstBrokenSeq).toBe(2);
  });

  it('detects a modified hash field', () => {
    const log = makeLog('0.1.0', [{}, {}]);
    log.entries[0]!.hash = '0'.repeat(64);
    expect(log.verify().ok).toBe(false);
  });

  it('round-trips through JSONL without breaking the chain', () => {
    const log = makeLog('0.1.0', [{ tool: 'echo' }, { tool: 'now', decision: 'deny', outcome: 'blocked' }]);
    const restored = AuditLog.fromJSONL(log.toJSONL(), '0.1.0');
    expect(restored.entries).toEqual(log.entries);
    expect(restored.verify()).toEqual({ ok: true });
  });

  it('empty log verifies ok and serializes to empty string', () => {
    const log = new AuditLog('0.1.0');
    expect(log.verify()).toEqual({ ok: true });
    expect(log.toJSONL()).toBe('');
  });

  it('invokes onAppend callback after each append', () => {
    const seen: AuditEntry[] = [];
    const log = new AuditLog('0.1.0', { onAppend: (e) => seen.push(e) });
    log.append({
      agent: 'a', session: 's', server: 'demo', tool: 'echo',
      argsHash: 'h', decision: 'allow', outcome: 'ok', policyVersion: '0.1.0',
    });
    expect(seen).toHaveLength(1);
    expect(seen[0]!.seq).toBe(1);
  });
});

describe('audit file helpers', () => {
  it('appendToAuditFile + loadAuditFile round-trips and verifies', () => {
    const dir = mkdtempSync(join(tmpdir(), 'pod-audit-'));
    const path = join(dir, 'audit.jsonl');
    const log = makeLog('0.1.0', [{}, {}]);
    for (const e of log.entries) appendToAuditFile(path, e);
    const loaded = loadAuditFile(path, '0.1.0');
    expect(loaded.entries).toEqual(log.entries);
    expect(loaded.verify()).toEqual({ ok: true });
  });

  it('loadAuditFile throws when the file was tampered with', () => {
    const dir = mkdtempSync(join(tmpdir(), 'pod-audit-'));
    const path = join(dir, 'audit.jsonl');
    const log = makeLog('0.1.0', [{}, {}]);
    for (const e of log.entries) appendToAuditFile(path, e);
    // 篡改文件内容
    const raw = readFileSync(path, 'utf8').split('\n');
    raw[1] = raw[1]!.replace('"outcome":"ok"', '"outcome":"error"');
    writeFileSync(path, raw.join('\n'), 'utf8');
    expect(() => loadAuditFile(path, '0.1.0')).toThrow(/audit chain broken/);
  });
});

describe('undefined optional fields never break the chain (regression)', () => {
  it('append with undefined-valued keys round-trips and verifies', () => {
    const log = new AuditLog('0.1.0');
    log.append({
      agent: 'a',
      session: 's',
      server: 'demo',
      tool: 'echo',
      argsHash: 'h',
      decision: 'allow',
      outcome: 'blocked',
      reason: 'secret_leak',
      approver: undefined as unknown as string, // 键存在但值为 undefined
      policyVersion: '0.1.0',
    });
    const restored = AuditLog.fromJSONL(log.toJSONL(), '0.1.0');
    expect(restored.verify()).toEqual({ ok: true });
    expect(restored.entries[0]!.hash).toBe(log.entries[0]!.hash);
  });
});
