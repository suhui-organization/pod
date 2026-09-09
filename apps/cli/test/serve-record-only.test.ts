/**
 * pod serve --record-only：策略照常求值并写审计，但一律放行（onboard 默认包装模式）。
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { fileURLToPath } from 'node:url';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { AuditLog } from '@podsec/audit';

const HERE = dirname(fileURLToPath(import.meta.url));
const CLI_INDEX = join(HERE, '../src/index.ts');
const DEMO_SERVER = join(HERE, '../../../packages/gateway/src/demo-server.ts');

let workDir: string;
let client: Client;
let transport: StdioClientTransport;

beforeAll(async () => {
  workDir = mkdtempSync(join(tmpdir(), 'pod-serve-record-'));
  const policyFile = join(workDir, 'policy.json');
  writeFileSync(
    policyFile,
    JSON.stringify({ version: '0.1.0', agent: 'rec-agent', servers: { demo: { deny: ['danger_delete'] } } }),
    'utf8',
  );
  transport = new StdioClientTransport({
    command: process.execPath,
    args: [
      '--import', 'tsx', CLI_INDEX, 'serve', '--record-only',
      '--agent', 'rec-agent', '--server', 'demo', '--policy', policyFile,
      '--command', process.execPath, '--arg', '--import', '--arg', 'tsx', '--arg', DEMO_SERVER,
      '--audit-dir', join(workDir, 'audit'),
    ],
  });
  client = new Client({ name: 'serve-record-client', version: '0.1.0' }, { capabilities: {} });
  await client.connect(transport);
});

afterAll(async () => {
  await client.close();
  await transport.close();
});

describe('pod serve --record-only', () => {
  it('forwards a denied tool but audits it with enforced=false', async () => {
    const result = await client.callTool({ name: 'danger_delete', arguments: { path: '/etc' } });
    expect(result.isError).toBeFalsy();
    const content = result.content as Array<{ text?: string }>;
    expect(content[0]?.text).toContain('would delete');

    const log = AuditLog.fromJSONL(readFileSync(join(workDir, 'audit', 'demo.jsonl'), 'utf8'), '0.1.0');
    expect(log.verify()).toEqual({ ok: true });
    expect(log.entries[0]!.enforced).toBe(false);
    expect(log.entries[0]!.decision).toBe('deny');
    expect(log.entries[0]!.outcome).toBe('ok');
  });
});
