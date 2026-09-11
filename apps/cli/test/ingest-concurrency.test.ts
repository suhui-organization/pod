/**
 * 并发 ingest 回归测试。
 *
 * 事故背景（2026-09-09）：Codex PostToolUse 钩子并发触发，两个 pod ingest
 * 进程同时读到同一个链尾，各写了一条 seq=5、prevHash 相同的记录——链分叉，
 * 云端按连续性校验拒绝上传，且此后所有追加都因"链已损坏"失败（静默丢了 2.5 天）。
 * 这里起真的多进程同时写，断言链仍然连续。
 */
import { spawn } from 'node:child_process';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { AuditLog } from '@podsec/audit';

const HERE = dirname(fileURLToPath(import.meta.url));
const CLI_INDEX = join(HERE, '../src/index.ts');

function ingest(auditDir: string, i: number): Promise<number | null> {
  return new Promise((resolve) => {
    const child = spawn(
      process.execPath,
      [
        '--import', 'tsx', CLI_INDEX, 'ingest',
        '--agent', 'codex', '--server', 'codex-tools',
        '--tool', `Bash${i}`, '--decision', 'allow', '--outcome', 'ok',
        '--args', JSON.stringify({ command: `echo ${i}` }),
        '--audit-dir', auditDir,
      ],
      { stdio: 'ignore' },
    );
    child.on('exit', (code) => resolve(code));
  });
}

describe('并发 pod ingest', () => {
  it('8 个进程同时写同一文件，链保持连续且无重复 seq', async () => {
    const auditDir = mkdtempSync(join(tmpdir(), 'pod-concurrent-'));
    const codes = await Promise.all(Array.from({ length: 8 }, (_, i) => ingest(auditDir, i)));
    expect(codes.every((c) => c === 0)).toBe(true);

    const path = join(auditDir, 'codex', 'codex-tools.jsonl');
    const log = AuditLog.fromJSONL(readFileSync(path, 'utf8'), 'external');
    expect(log.entries).toHaveLength(8);
    expect(log.verify()).toEqual({ ok: true });
    // seq 必须是 1..8，出现重复就说明有并发分叉
    expect(log.entries.map((e) => e.seq)).toEqual([1, 2, 3, 4, 5, 6, 7, 8]);
    expect(new Set(log.entries.map((e) => e.prevHash)).size).toBe(8);
  }, 60_000);
});
