/**
 * pod record 冒烟测试：mock dsh-mcp-manager 配置指向 demo server，
 * 验证 record-only 模式：deny 工具被放行、审计标记 enforced=false、
 * pod audit 可读出并校验哈希链。
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { fileURLToPath } from 'node:url';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { AuditLog } from '@podsec/audit';

type CallToolResponse = Awaited<ReturnType<Client['callTool']>>;
function textOf(result: CallToolResponse): string {
  if (!('content' in result)) return '';
  const content = result.content as Array<{ type?: string; text?: string }>;
  return content[0]?.text ?? '';
}

const HERE = dirname(fileURLToPath(import.meta.url));
const CLI_INDEX = join(HERE, '../src/index.ts');
const DEMO_SERVER = join(HERE, '../../../packages/gateway/src/demo-server.ts');

let workDir: string;
let configFile: string;
let auditDir: string;
let client: Client;
let transport: StdioClientTransport;

beforeAll(async () => {
  workDir = mkdtempSync(join(tmpdir(), 'pod-record-'));
  auditDir = join(workDir, 'audit');
  // mock 一个 dsh-mcp-manager 格式的配置
  configFile = join(workDir, 'mcp-manager.json');
  writeFileSync(
    configFile,
    JSON.stringify({
      servers: [
        {
          name: 'demo',
          transport: 'stdio',
          command: process.execPath,
          args: ['--import', 'tsx', DEMO_SERVER],
          env: { POD_TEST: '1' },
        },
      ],
    }),
    'utf8',
  );

  transport = new StdioClientTransport({
    command: process.execPath,
    args: [
      '--import',
      'tsx',
      CLI_INDEX,
      'record',
      '--config',
      configFile,
      '--server',
      'demo',
      '--agent',
      'record-agent',
      '--audit-dir',
      auditDir,
    ],
  });
  client = new Client({ name: 'record-client', version: '0.1.0' }, { capabilities: {} });
  await client.connect(transport);
});

afterAll(async () => {
  await client.close();
  await transport.close();
});

describe('pod record (record-only, mock mcp-manager.json)', () => {
  it('exposes the upstream tool list', async () => {
    const { tools } = await client.listTools();
    expect(tools.map((t) => t.name).sort()).toEqual(['danger_delete', 'echo', 'now']);
  });

  it('forwards a denied tool instead of blocking, and marks audit enforced=false', async () => {
    const result = await client.callTool({ name: 'danger_delete', arguments: { path: '/etc' } });
    expect(result.isError).toBeFalsy();
    expect(textOf(result)).toContain('would delete');
  });

  it('forwards an allowed tool', async () => {
    const result = await client.callTool({ name: 'echo', arguments: { message: 'rec ok' } });
    expect(textOf(result)).toBe('rec ok');
  });

  it('writes a hash-chained audit with record-only markers', async () => {
    const auditFile = join(auditDir, 'demo.jsonl');
    expect(existsSync(auditFile)).toBe(true);
    const log = AuditLog.fromJSONL(readFileSync(auditFile, 'utf8'), '0.1.0');
    expect(log.verify()).toEqual({ ok: true });
    expect(log.entries.length).toBeGreaterThanOrEqual(2);
    // 允许调用在前（listTools 不记录），danger_delete 与 echo 的标记
    const byTool = Object.fromEntries(log.entries.map((e) => [e.tool, e]));
    expect(byTool['danger_delete']!.enforced).toBe(false);
    expect(byTool['danger_delete']!.outcome).toBe('ok');
    expect(byTool['echo']!.enforced).toBe(false);
    expect(byTool['echo']!.decision).toBe('allow');
    expect(byTool['echo']!.agent).toBe('record-agent');
  });

  it('pod audit command reads the file and verifies the chain', () => {
    // CLI 日志走 stderr（stdout 是 MCP 协议），用 spawnSync 同时拿两路
    const res = spawnSync(
      process.execPath,
      ['--import', 'tsx', CLI_INDEX, 'audit', '--server', 'demo', '--tail', '5', '--audit-dir', auditDir],
      { encoding: 'utf8' },
    );
    expect(res.status).toBe(0);
    expect(res.stderr).toContain('demo.jsonl:');
    expect(res.stderr).toContain('chain verified');
    expect(res.stderr).toContain('rec'); // record-only 标记列
    expect(res.stderr).toContain('danger_delete');
  });

  it('pod audit reports tampered chains', async () => {
    const auditFile = join(auditDir, 'demo.jsonl');
    const lines = readFileSync(auditFile, 'utf8').trim().split('\n');
    const first = JSON.parse(lines[0]!);
    first.outcome = 'error';
    lines[0] = JSON.stringify(first);
    writeFileSync(auditFile, lines.join('\n') + '\n', 'utf8');
    let failed = false;
    try {
      execFileSync(
        process.execPath,
        ['--import', 'tsx', CLI_INDEX, 'audit', '--server', 'demo', '--audit-dir', auditDir],
        { encoding: 'utf8' },
      );
    } catch {
      failed = true;
    }
    expect(failed).toBe(true);
  });
});

describe('pod record restart continues the hash chain', () => {
  it('appends to the existing chain with sequential seq across restarts', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'pod-record-restart-'));
    const auditDir2 = join(dir, 'audit');
    const configFile2 = join(dir, 'mcp-manager.json');
    writeFileSync(
      configFile2,
      JSON.stringify({ servers: [{ name: 'demo', transport: 'stdio', command: process.execPath, args: ['--import', 'tsx', DEMO_SERVER] }] }),
      'utf8',
    );
    const spawnRec = () =>
      new StdioClientTransport({
        command: process.execPath,
        args: ['--import', 'tsx', CLI_INDEX, 'record', '--config', configFile2, '--server', 'demo', '--agent', 'restart-test', '--audit-dir', auditDir2],
      });
    const runOnce = async (tool: string, args: Record<string, unknown>) => {
      const t = spawnRec();
      const c = new Client({ name: 'restart-client', version: '0.1.0' }, { capabilities: {} });
      await c.connect(t);
      await c.callTool({ name: tool, arguments: args }, undefined);
      await c.close();
      await t.close();
    };

    // 第一次进程：echo
    await runOnce('echo', { message: 'first' });
    // 第二次进程（重启）：now —— 链必须续上，不能从 seq=1 重开
    await runOnce('now', {});

    const auditFile = join(auditDir2, 'demo.jsonl');
    const log = AuditLog.fromJSONL(readFileSync(auditFile, 'utf8'), '0.1.0');
    expect(log.verify()).toEqual({ ok: true });
    expect(log.entries.map((e) => e.seq)).toEqual([1, 2]);
    expect(log.entries[1]!.prevHash).toBe(log.entries[0]!.hash);
    expect(log.entries[1]!.agent).toBe('restart-test');
  });
});
