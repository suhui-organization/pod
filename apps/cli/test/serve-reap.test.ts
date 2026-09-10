/**
 * stdio 网关必须在 agent 消失后退出。
 *
 * 不退出的话，每个 agent 会话结束都会留下一个孤儿进程，各自还挂着审计文件句柄
 * （dogfood 机器上曾留下 5 个从 9/7 起就没有客户端的 stdio 网关）。
 * 这里覆盖两条退出路径：stdin EOF（正常收敛）与 PPID 迁移（agent 被强杀、fd 被继承，EOF 不会到）。
 */
import { describe, expect, it } from 'vitest';
import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const CLI_INDEX = join(HERE, '../src/index.ts');
const DEMO_SERVER = join(HERE, '../../../packages/gateway/src/demo-server.ts');
const ORPHAN_HELPER = join(HERE, 'fixtures/spawn-then-orphan.mjs');

function serveArgs(workDir: string): string[] {
  const policyFile = join(workDir, 'policy.json');
  writeFileSync(
    policyFile,
    JSON.stringify({ version: '0.1.0', agent: 'reap-agent', servers: { demo: { allow: ['echo'] } } }),
    'utf8',
  );
  return [
    '--import', 'tsx', CLI_INDEX, 'serve',
    '--agent', 'reap-agent', '--server', 'demo', '--policy', policyFile,
    '--command', process.execPath, '--arg', '--import', '--arg', 'tsx', '--arg', DEMO_SERVER,
    '--audit-dir', join(workDir, 'audit'),
  ];
}

function alive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

async function waitGone(pid: number, timeoutMs: number): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (!alive(pid)) return true;
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  return !alive(pid);
}

/** 等网关打印 ready（stderr），避免竞态：EOF 可能在 transport 还没接上时就发出去。 */
async function waitReady(child: ChildProcess, timeoutMs = 20_000): Promise<void> {
  const stream = child.stderr;
  if (!stream) throw new Error('child stderr unavailable');
  await new Promise<void>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('gateway did not become ready')), timeoutMs);
    stream.on('data', (chunk: Buffer) => {
      if (chunk.toString().includes('gateway ready on stdio')) {
        clearTimeout(timer);
        resolve();
      }
    });
  });
}

describe('stdio 网关回收', () => {
  it('agent 关闭管道（stdin EOF）后退出', async () => {
    const workDir = mkdtempSync(join(tmpdir(), 'pod-reap-eof-'));
    const child = spawn(process.execPath, serveArgs(workDir), { stdio: ['pipe', 'pipe', 'pipe'] });
    try {
      await waitReady(child);
      child.stdin!.end();
      expect(await waitGone(child.pid!, 10_000)).toBe(true);
    } finally {
      if (child.pid && alive(child.pid)) child.kill('SIGKILL');
    }
  }, 40_000);

  it('agent 被强杀、管道写端被继承（收不到 EOF）时靠 PPID 迁移退出', async () => {
    const workDir = mkdtempSync(join(tmpdir(), 'pod-reap-ppid-'));
    const launcher = spawnSync(process.execPath, [ORPHAN_HELPER, ...serveArgs(workDir)], { encoding: 'utf8' });
    expect(launcher.status).toBe(0);
    const { pod, holder } = JSON.parse(launcher.stdout.trim()) as { pod: number; holder: number };
    try {
      expect(alive(pod)).toBe(true);
      // 看门狗 5s 一次，留一个完整周期 + 启动余量
      expect(await waitGone(pod, 20_000)).toBe(true);
    } finally {
      if (alive(holder)) process.kill(holder, 'SIGKILL');
      if (alive(pod)) process.kill(pod, 'SIGKILL');
    }
  }, 40_000);
});
