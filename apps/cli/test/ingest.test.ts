/**
 * pod ingest 测试：外部 agent 事件（Codex PostToolUse hook）追加进哈希链。
 */
import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { AuditLog } from '@podsec/audit';

const HERE = dirname(fileURLToPath(import.meta.url));
const CLI_INDEX = join(HERE, '../src/index.ts');

describe('pod ingest', () => {
  it('appends external events to the hash chain and keeps it verifiable', () => {
    const dir = mkdtempSync(join(tmpdir(), 'pod-ingest-'));
    const auditDir = join(dir, 'audit');
    const run = (tool: string) =>
      spawnSync(
        process.execPath,
        [
          '--import', 'tsx', CLI_INDEX, 'ingest',
          '--agent', 'codex', '--server', 'codex-tools', '--tool', tool,
          '--decision', 'allow', '--outcome', 'ok',
          '--args', '{"command":"echo hi"}', '--audit-dir', auditDir,
        ],
        { encoding: 'utf8' },
      );

    expect(run('Bash').status).toBe(0);
    expect(run('apply_patch').status).toBe(0);

    const file = join(auditDir, 'codex', 'codex-tools.jsonl');
    const log = AuditLog.fromJSONL(readFileSync(file, 'utf8'), 'external');
    expect(log.verify()).toEqual({ ok: true });
    expect(log.entries.map((e) => e.tool)).toEqual(['Bash', 'apply_patch']);
    expect(log.entries.map((e) => e.seq)).toEqual([1, 2]);
    expect(log.entries[0]!.agent).toBe('codex');
    expect(log.entries[0]!.policyVersion).toBe('external');
  });
});
