/**
 * 全链路冒烟测试：真实子进程跑 demo server + pod serve，再用 MCP client 连网关，
 * 验证 stdio 双向代理、策略阻断、审计落盘。
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { fileURLToPath } from 'node:url';
import { mkdtempSync, writeFileSync, existsSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import type { Policy } from '@podsec/policy';

/** SDK 1.30 将 callTool 返回类型放宽为 union，测试里收窄后取文本 */
type CallToolResponse = Awaited<ReturnType<Client['callTool']>>;
function textOf(result: CallToolResponse): string {
  if (!('content' in result)) return '';
  const content = result.content as Array<{ type?: string; text?: string }>;
  return content[0]?.text ?? '';
}

const HERE = dirname(fileURLToPath(import.meta.url));
const CLI_INDEX = join(HERE, '../src/index.ts');
const DEMO_SERVER = join(HERE, '../../../packages/gateway/src/demo-server.ts');
// node --import 从子进程 cwd 向上解析 tsx（pnpm 根 node_modules），无需 resolve 包路径

const policy: Policy = {
  version: '0.1.0',
  agent: 'smoke-agent',
  defaultDecision: 'deny',
  servers: {
    demo: {
      allow: ['echo', 'now'],
      deny: ['danger_delete'],
    },
  },
};

let auditDir: string;
let client: Client;
let transport: StdioClientTransport;

async function spawnPodServe(): Promise<StdioClientTransport> {
  const policyFile = join(auditDir, 'policy.json');
  writeFileSync(policyFile, JSON.stringify(policy, null, 2), 'utf8');

  const t = new StdioClientTransport({
    command: process.execPath,
    args: [
      '--import',
      'tsx',
      CLI_INDEX,
      'serve',
      '--agent',
      'smoke-agent',
      '--server',
      'demo',
      '--policy',
      policyFile,
      '--command',
      process.execPath,
      '--arg',
      '--import',
      '--arg',
      'tsx',
      '--arg',
      DEMO_SERVER,
      '--audit-dir',
      auditDir,
    ],
  });
  return t;
}

beforeAll(async () => {
  auditDir = mkdtempSync(join(tmpdir(), 'pod-smoke-'));
  transport = await spawnPodServe();
  client = new Client({ name: 'smoke-client', version: '0.1.0' }, { capabilities: {} });
  await client.connect(transport);
});

afterAll(async () => {
  await client.close();
  await transport.close();
});

describe('pod serve end-to-end (stdio, real processes)', () => {
  it('exposes the upstream tool list through the gateway', async () => {
    const { tools } = await client.listTools();
    const names = tools.map((t) => t.name).sort();
    expect(names).toEqual(['danger_delete', 'echo', 'now', 'write_file']);
  });

  it('forwards allowed calls and writes an audit trail', async () => {
    const result = await client.callTool({ name: 'echo', arguments: { message: 'smoke ok' } });
    expect(result.isError).toBeFalsy();
    expect(textOf(result)).toBe('smoke ok');

    const auditFile = join(auditDir, 'demo.jsonl');
    expect(existsSync(auditFile)).toBe(true);
    const lines = readFileSync(auditFile, 'utf8').trim().split('\n');
    expect(lines.length).toBeGreaterThanOrEqual(1);
    const first = JSON.parse(lines[0]!) as { decision: string; outcome: string; tool: string };
    expect(first.decision).toBe('allow');
    expect(first.outcome).toBe('ok');
    expect(first.tool).toBe('echo');
  });

  it('blocks denied calls at the gateway', async () => {
    const result = await client.callTool({ name: 'danger_delete', arguments: { path: '/etc/passwd' } });
    expect(result.isError).toBe(true);
    expect(textOf(result)).toContain('blocked (deny)');
  });
});
