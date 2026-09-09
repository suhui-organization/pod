/**
 * P2 端到端：pod serve --snapshot-all → 工具写文件 → pod rollback 恢复。
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { fileURLToPath } from 'node:url';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { AuditLog } from '@podsec/audit';

const HERE = dirname(fileURLToPath(import.meta.url));
const CLI_INDEX = join(HERE, '../src/index.ts');
const DEMO_SERVER = join(HERE, '../../../packages/gateway/src/demo-server.ts');

let workDir: string;
let target: string;
let snapshotDir: string;
let auditDir: string;
let client: Client;
let transport: StdioClientTransport;

beforeAll(async () => {
  workDir = mkdtempSync(join(tmpdir(), 'pod-snapshot-e2e-'));
  target = join(workDir, 'notes.txt');
  writeFileSync(target, 'original', 'utf8');
  snapshotDir = join(workDir, 'snapshots');
  auditDir = join(workDir, 'audit');
  const policyFile = join(workDir, 'policy.json');
  writeFileSync(
    policyFile,
    JSON.stringify({ version: '0.1.0', agent: 'snap-agent', servers: { demo: { allow: ['write_file'] } } }),
    'utf8',
  );
  transport = new StdioClientTransport({
    command: process.execPath,
    args: [
      '--import', 'tsx', CLI_INDEX, 'serve',
      '--agent', 'snap-agent', '--server', 'demo', '--policy', policyFile,
      '--command', process.execPath, '--arg', '--import', '--arg', 'tsx', '--arg', DEMO_SERVER,
      '--audit-dir', auditDir,
      '--snapshot-all', '--snapshot-dir', snapshotDir,
    ],
  });
  client = new Client({ name: 'snapshot-client', version: '0.1.0' }, { capabilities: {} });
  await client.connect(transport);
});

afterAll(async () => {
  await client.close();
  await transport.close();
});

describe('snapshot + rollback (P2 e2e)', () => {
  it('restores a file modified by a tool call', async () => {
    const result = await client.callTool({ name: 'write_file', arguments: { path: target, content: 'modified' } });
    expect(result.isError).toBeFalsy();
    expect(readFileSync(target, 'utf8')).toBe('modified');

    const log = AuditLog.fromJSONL(readFileSync(join(auditDir, 'demo.jsonl'), 'utf8'), '0.1.0');
    const entry = log.entries.find((e) => e.tool === 'write_file')!;
    expect(entry.snapshot).toBeTruthy();

    const res = spawnSync(
      process.execPath,
      ['--import', 'tsx', CLI_INDEX, 'rollback', '--id', entry.snapshot!, '--snapshot-dir', snapshotDir],
      { encoding: 'utf8' },
    );
    expect(res.status).toBe(0);
    expect(res.stderr).toContain('restored 1 path');
    expect(readFileSync(target, 'utf8')).toBe('original');
  });
});
