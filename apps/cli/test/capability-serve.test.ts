/**
 * pod serve capabilityRules 端到端测试：
 * - 工具在 servers.allow 里，但能力命中 capabilityRules.deny → 仍被阻断
 * - 未命中 denied capability 的工具正常放行
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { fileURLToPath } from 'node:url';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import type { Policy } from '@podsec/policy';

type CallToolResponse = Awaited<ReturnType<Client['callTool']>>;
function textOf(result: CallToolResponse): string {
  if (!('content' in result)) return '';
  const content = result.content as Array<{ type?: string; text?: string }>;
  return content[0]?.text ?? '';
}

const HERE = dirname(fileURLToPath(import.meta.url));
const CLI_INDEX = join(HERE, '../src/index.ts');
const DEMO_SERVER = join(HERE, '../../../packages/gateway/src/demo-server.ts');

const policy: Policy = {
  version: '0.1.0',
  agent: 'cap-agent',
  servers: { demo: { allow: ['echo', 'now'] } },
  capabilityMap: { 'demo.echo': ['external-communication'] },
  capabilityRules: { deny: ['external-communication'] },
};

let workDir: string;
let client: Client;
let transport: StdioClientTransport;

beforeAll(async () => {
  workDir = mkdtempSync(join(tmpdir(), 'pod-cap-serve-'));
  const policyFile = join(workDir, 'policy.json');
  writeFileSync(policyFile, JSON.stringify(policy, null, 2), 'utf8');
  transport = new StdioClientTransport({
    command: process.execPath,
    args: [
      '--import', 'tsx', CLI_INDEX, 'serve',
      '--agent', 'cap-agent',
      '--server', 'demo',
      '--policy', policyFile,
      '--command', process.execPath, '--arg', '--import', '--arg', 'tsx', '--arg', DEMO_SERVER,
      '--audit-dir', join(workDir, 'audit'),
      '--pending-dir', join(workDir, 'pending'),
      '--graph', join(workDir, 'missing-graph.json'),
    ],
  });
  client = new Client({ name: 'cap-client', version: '0.1.0' }, { capabilities: {} });
  await client.connect(transport);
});

afterAll(async () => {
  await client.close().catch(() => {});
});

describe('capabilityRules enforcement', () => {
  it('blocks a tool whose capability is denied even though the tool is allowed', async () => {
    const result = await client.callTool({ name: 'echo', arguments: { message: 'hi' } });
    expect(result.isError).toBe(true);
    expect(textOf(result)).toContain('denied capability');
  });

  it('allows a tool that does not have the denied capability', async () => {
    const result = await client.callTool({ name: 'now', arguments: {} });
    expect(result.isError).toBeFalsy();
  });
});
