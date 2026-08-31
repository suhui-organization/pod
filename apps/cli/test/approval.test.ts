/**
 * pod serve 审批流冒烟测试：
 * 1. approve 规则挂起调用 → 旁路 `pod approve --id` → 调用恢复并审计 approver
 * 2. 超时（fail-closed）→ 调用被阻断
 * 3. pod pending 列出挂起请求
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, readdirSync, readFileSync } from 'node:fs';
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
  agent: 'approval-agent',
  servers: { demo: { allow: ['now'], approve: ['echo'], deny: ['danger_delete'] } },
};

let workDir: string;
let pendingDir: string;
let auditDir: string;
let client: Client;
let transport: StdioClientTransport;

function spawnServe() {
  const policyFile = join(workDir, 'policy.json');
  writeFileSync(policyFile, JSON.stringify(policy, null, 2), 'utf8');
  return new StdioClientTransport({
    command: process.execPath,
    args: [
      '--import', 'tsx', CLI_INDEX, 'serve',
      '--agent', 'approval-agent',
      '--server', 'demo',
      '--policy', policyFile,
      '--command', process.execPath, '--arg', '--import', '--arg', 'tsx', '--arg', DEMO_SERVER,
      '--audit-dir', auditDir,
      '--pending-dir', pendingDir,
      '--approval-timeout', '2',
    ],
  });
}

function pendingFiles(): string[] {
  return readdirSync(pendingDir).filter((f) => f.endsWith('.json') && !f.endsWith('.decision.json'));
}

async function findPendingId(): Promise<string> {
  const deadline = Date.now() + 5000;
  while (Date.now() < deadline) {
    const files = pendingFiles();
    if (files.length > 0) return files[0]!.replace(/\.json$/, '');
    await new Promise((r) => setTimeout(r, 50));
  }
  throw new Error('no pending approval appeared');
}

beforeAll(async () => {
  workDir = mkdtempSync(join(tmpdir(), 'pod-approval-'));
  pendingDir = join(workDir, 'pending');
  auditDir = join(workDir, 'audit');
  transport = spawnServe();
  client = new Client({ name: 'approval-client', version: '0.1.0' }, { capabilities: {} });
  await client.connect(transport);
});

afterAll(async () => {
  await client.close();
  await transport.close();
});

describe('pod serve approval flow (side-channel)', () => {
  it('lists a pending approval via pod pending', async () => {
    const call = client.callTool({ name: 'echo', arguments: { message: 'needs approval' } });
    const id = await findPendingId();
    const res = spawnSync(
      process.execPath,
      ['--import', 'tsx', CLI_INDEX, 'pending', '--pending-dir', pendingDir],
      { encoding: 'utf8' },
    );
    expect(res.status).toBe(0);
    expect(res.stderr).toContain(id);
    // 清理：批准它，避免影响后续断言
    spawnSync(
      process.execPath,
      ['--import', 'tsx', CLI_INDEX, 'approve', '--id', id, '--approver', 'tester', '--pending-dir', pendingDir],
      { encoding: 'utf8' },
    );
    const result = await call;
    expect(result.isError).toBeFalsy();
    expect(textOf(result)).toBe('needs approval');
  });

  it('approves via side-channel: call resumes and audit records approver', async () => {
    const call = client.callTool({ name: 'echo', arguments: { message: 'second' } });
    const id = await findPendingId();
    const res = spawnSync(
      process.execPath,
      ['--import', 'tsx', CLI_INDEX, 'approve', '--id', id, '--approver', 'walden', '--reason', 'looks fine', '--pending-dir', pendingDir],
      { encoding: 'utf8' },
    );
    expect(res.status).toBe(0);
    expect(res.stderr).toContain('approved');

    const result = await call;
    expect(result.isError).toBeFalsy();
    expect(textOf(result)).toBe('second');

    const auditFile = join(auditDir, 'demo.jsonl');
    const lines = readFileSync(auditFile, 'utf8').trim().split('\n');
    const echoEntries = lines
      .map((l) => JSON.parse(l))
      .filter((e) => e.tool === 'echo' && e.decision === 'approve');
    const entry = echoEntries[echoEntries.length - 1]!;
    expect(entry.outcome).toBe('ok');
    expect(entry.approver).toBe('walden');
    expect(entry.reason).toBe('looks fine');
  });

  it('fails closed on approval timeout', async () => {
    const call = client.callTool({ name: 'echo', arguments: { message: 'will timeout' } });
    const id = await findPendingId();
    expect(id).toBeTruthy();
    // 不批准，等待超时（2s）
    const result = await call;
    expect(result.isError).toBe(true);
    expect(textOf(result)).toContain('timed out');
  });
});
