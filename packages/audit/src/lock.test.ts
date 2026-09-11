import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { LockTimeoutError, withFileLock } from './lock.js';

let dir: string;
let lockPath: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'pod-lock-'));
  lockPath = join(dir, 'a.jsonl.lock');
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

describe('withFileLock', () => {
  it('拿锁→执行→释放；结束后锁文件不残留', () => {
    const out = withFileLock(lockPath, {}, () => 'done');
    expect(out).toBe('done');
    expect(existsSync(lockPath)).toBe(false);
  });

  it('持有者进程已消失时接管（崩溃后不能让审计永久停摆）', () => {
    // 999999 几乎不可能是存活进程
    writeFileSync(lockPath, '999999\n', 'utf8');
    const out = withFileLock(lockPath, { timeoutMs: 500 }, () => 'took-over');
    expect(out).toBe('took-over');
    expect(existsSync(lockPath)).toBe(false);
  });

  it('持有者还活着时不抢锁：超时抛错而不是写坏链', () => {
    writeFileSync(lockPath, `${process.pid}\n`, 'utf8');
    expect(() => withFileLock(lockPath, { timeoutMs: 120, pollMs: 20 }, () => 'never')).toThrow(LockTimeoutError);
    // 超时后不能把别人的锁删掉
    expect(existsSync(lockPath)).toBe(true);
  });

  it('fn 抛错也会释放锁（否则后续写入全被卡死）', () => {
    expect(() =>
      withFileLock(lockPath, {}, () => {
        throw new Error('boom');
      }),
    ).toThrow('boom');
    expect(existsSync(lockPath)).toBe(false);
  });
});
