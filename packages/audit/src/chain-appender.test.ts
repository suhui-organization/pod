import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { AuditLog, hashValue, loadAuditFile, type NewAuditEntry } from './index.js';
import { ChainAppender } from './index.js';

let dir: string;
let path: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'pod-appender-'));
  path = join(dir, 'filesystem.jsonl');
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

let seq = 0;
function entry(tool: string): NewAuditEntry {
  seq += 1;
  return {
    agent: 'codex',
    session: 's',
    server: 'filesystem',
    tool,
    argsHash: hashValue({ tool, i: seq }),
    decision: 'allow',
    outcome: 'ok',
    policyVersion: '0.1.0',
  };
}

describe('ChainAppender', () => {
  it('两个写入器（两个网关进程）交替写同一文件，链保持连续', () => {
    const a = new ChainAppender(path, '0.1.0');
    const b = new ChainAppender(path, '0.1.0');
    for (let i = 0; i < 5; i++) {
      a.append(entry(`a${i}`));
      b.append(entry(`b${i}`));
    }
    const log = loadAuditFile(path, '0.1.0');
    expect(log.entries).toHaveLength(10);
    expect(log.entries.map((e) => e.seq)).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    expect(log.verify()).toEqual({ ok: true });
  });

  it('对照：两个内存 AuditLog 各自追加会分叉（这就是修复前的行为）', () => {
    const a = new AuditLog('0.1.0', { onAppend: (e) => writeFileSync(path, JSON.stringify(e) + '\n', { flag: 'a' }) });
    const b = new AuditLog('0.1.0', { onAppend: (e) => writeFileSync(path, JSON.stringify(e) + '\n', { flag: 'a' }) });
    a.append(entry('a'));
    b.append(entry('b'));
    // 读原始文件（loadAuditFile 会因为断链直接抛错，这里要看的就是"它是断的"）
    const log = AuditLog.fromJSONL(readFileSync(path, 'utf8'), '0.1.0');
    expect(log.entries.map((e) => e.seq)).toEqual([1, 1]); // 两个进程都以为自己是第一条
    expect(log.verify().ok).toBe(false);
  });

  it('链断裂时 preflight 抛错（网关宁可不启动，也不往坏链里写）', () => {
    const a = new ChainAppender(path, '0.1.0');
    a.append(entry('first'));
    // 制造断链：把唯一一条记录的 prevHash 改掉
    const broken = { ...JSON.parse(loadAuditFile(path, '0.1.0').toJSONL().trim()), prevHash: 'deadbeef' };
    writeFileSync(path, JSON.stringify(broken) + '\n', 'utf8');
    expect(() => new ChainAppender(path, '0.1.0').preflight()).toThrow(/audit chain broken/);
  });
});
