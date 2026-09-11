/**
 * 跨进程文件锁：审计链的"读链尾 → 追加"必须互斥。
 *
 * 为什么需要它（真实事故）：Codex 的 PostToolUse 钩子每次工具调用起一个
 * `pod ingest` 进程。两个进程同时读到同一个链尾，就各自算出同一个 seq 与
 * 同一个 prevHash，各写一条——链从此分叉，云端按连续性校验直接拒绝（409），
 * 而且后续追加会因为"链已损坏"全部失败。审计链的正确性不能依赖调用方记得串行。
 *
 * 实现用文件存在性当锁（`open(..., 'wx')` 是原子的），不引入依赖：
 * - 拿不到锁就轮询等待，超时**拒绝写入**（宁可不写，也不写进一条无法证明的链）；
 * - 死锁自愈：持锁进程崩了，锁文件会留下。按"PID 已不存在"或"锁龄超过 staleMs"
 *   接管，避免一次崩溃让审计永久停摆。
 */
import { closeSync, mkdirSync, openSync, readFileSync, statSync, unlinkSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';

export interface LockOptions {
  /** 等待锁的上限（毫秒），超时抛错 */
  timeoutMs?: number;
  /** 超过这个年龄的锁视为陈旧，可接管（毫秒） */
  staleMs?: number;
  /** 轮询间隔（毫秒） */
  pollMs?: number;
}

/** 同步睡眠：Node 没有 sleepSync，用 Atomics.wait 阻塞当前线程 */
function sleepSync(ms: number): void {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

/** 持锁进程是否还活着；解析不出 PID 时当作"未知"，交由锁龄判断 */
function holderPid(lockPath: string): number | null {
  try {
    const pid = Number.parseInt(readFileSync(lockPath, 'utf8').trim(), 10);
    return Number.isFinite(pid) && pid > 0 ? pid : null;
  } catch {
    return null;
  }
}

function pidAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    // EPERM = 进程存在但不属于我们，仍算活着；ESRCH = 已消失
    return (err as NodeJS.ErrnoException).code === 'EPERM';
  }
}

export class LockTimeoutError extends Error {}

export function withFileLock<T>(lockPath: string, opts: LockOptions, fn: () => T): T {
  const timeoutMs = opts.timeoutMs ?? 5_000;
  const staleMs = opts.staleMs ?? 30_000;
  const pollMs = opts.pollMs ?? 15;
  const deadline = Date.now() + timeoutMs;

  mkdirSync(dirname(lockPath), { recursive: true });
  for (;;) {
    try {
      closeSync(openSync(lockPath, 'wx'));
      writeFileSync(lockPath, `${process.pid}\n`, 'utf8');
      break;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== 'EEXIST') throw err;
      // 锁被占用：先判断持有者是不是已经死了，避免崩溃后永久卡死
      const pid = holderPid(lockPath);
      let stale = false;
      try {
        stale = Date.now() - statSync(lockPath).mtimeMs > staleMs;
      } catch {
        continue; // 锁刚好被释放，立刻重试
      }
      if ((pid !== null && !pidAlive(pid)) || stale) {
        try {
          unlinkSync(lockPath);
        } catch {
          // 别人抢先清理了，下一轮重试即可
        }
        continue;
      }
      if (Date.now() >= deadline) {
        throw new LockTimeoutError(
          `获取审计链锁超时（${lockPath}，等待 ${timeoutMs}ms，持有者 pid=${pid ?? '未知'}）——` +
            `为避免写坏链，本次不写入`,
        );
      }
      sleepSync(pollMs);
    }
  }

  try {
    return fn();
  } finally {
    try {
      unlinkSync(lockPath);
    } catch {
      // 锁文件已不在（被陈旧清理接管）——不掩盖 fn 的结果
    }
  }
}
