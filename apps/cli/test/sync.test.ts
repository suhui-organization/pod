/**
 * pod sync 集成测试：进程内 mock Pod Cloud（/api/v1/sync/events），
 * 验证推送、幂等（游标）、增量续传、断链 409。
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createServer, type Server } from 'node:http';
import { mkdtempSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { AuditLog } from '@podsec/audit';
import { runSync } from '../src/sync.js';

/** mock Pod Cloud：按 (server) 维护链尾 hash，断链返回 409 */
function startMockCloud(): { url: string; close: () => void; received: Map<string, number> } {
  const tails = new Map<string, string>();
  const received = new Map<string, number>();
  const server: Server = createServer((req, res) => {
    if (req.method !== 'POST' || !req.url?.endsWith('/api/v1/sync/events')) {
      res.writeHead(404).end();
      return;
    }
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => {
      const { events } = JSON.parse(body) as { events: Array<{ server: string; prev_hash: string; hash: string; seq: number }> };
      for (const ev of events) {
        const tail = tails.get(ev.server) ?? '';
        if (ev.prev_hash !== tail) {
          res.writeHead(409, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ detail: `哈希链断裂：期望 prev_hash=${tail.slice(0, 12)}…，收到 ${ev.prev_hash.slice(0, 12)}…（seq=${ev.seq}）` }));
          return;
        }
        tails.set(ev.server, ev.hash);
        received.set(ev.server, (received.get(ev.server) ?? 0) + 1);
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ synced: events.length, agent_id: 1 }));
    });
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address() as { port: number };
      resolve({ url: `http://127.0.0.1:${addr.port}`, close: () => server.close(), received });
    });
  });
}

function writeAuditFile(dir: string, server: string, count: number): AuditLog {
  const log = new AuditLog('0.1.0');
  for (let i = 0; i < count; i++) {
    log.append({
      agent: 'test', session: 's', server,
      tool: i % 2 ? 'write_file' : 'read_file',
      argsHash: `h${i}`.padEnd(64, '0'),
      decision: 'allow', outcome: 'ok', policyVersion: '0.1.0',
    });
  }
  writeFileSync(join(dir, `${server}.jsonl`), log.toJSONL(), 'utf8');
  return log;
}

/** 追加模式（与 pod record 的真实 append-only 行为一致）：续写已有链 */
function appendAuditFile(dir: string, server: string, count: number): void {
  const file = join(dir, `${server}.jsonl`);
  const { existsSync, readFileSync } = require('node:fs') as typeof import('node:fs');
  const log = existsSync(file)
    ? AuditLog.fromJSONL(readFileSync(file, 'utf8'), '')
    : new AuditLog('0.1.0');
  const base = log.entries.length;
  for (let i = 0; i < count; i++) {
    log.append({
      agent: 'test', session: 's', server,
      tool: (base + i) % 2 ? 'write_file' : 'read_file',
      argsHash: `h${base + i}`.padEnd(64, '0'),
      decision: 'allow', outcome: 'ok', policyVersion: '0.1.0',
    });
  }
  writeFileSync(file, log.toJSONL(), 'utf8');
}

describe('pod sync (mock Pod Cloud)', () => {
  let cloud: { url: string; close: () => void; received: Map<string, number> };
  let workDir: string;
  let auditDir: string;
  let stateHome: string;

  beforeAll(async () => {
    cloud = await startMockCloud();
    workDir = mkdtempSync(join(tmpdir(), 'pod-sync-'));
    auditDir = join(workDir, 'audit');
    stateHome = join(workDir, 'state');
    mkdirSync(auditDir, { recursive: true });
    mkdirSync(join(stateHome, '.pod', 'sync-state'), { recursive: true });
    // 让 HOME 指向测试目录，sync-state 写入测试目录
    process.env.HOME = join(stateHome, 'home');
    mkdirSync(process.env.HOME, { recursive: true });
  });

  afterAll(() => cloud.close());

  const opts = () => ({
    config: undefined,
    auditDir,
    apiUrl: cloud.url,
    agentId: 1,
    syncToken: 'test-token',
  });

  it('syncs a fresh audit file and persists the cursor', async () => {
    writeAuditFile(auditDir, 'filesystem', 3);
    const r1 = await runSync(opts());
    expect(r1.total_synced).toBe(3);
    expect(cloud.received.get('filesystem')).toBe(3);

    // 幂等：无新事件
    const r2 = await runSync(opts());
    expect(r2.total_synced).toBe(0);
    expect(r2.servers).toHaveLength(0);
    expect(cloud.received.get('filesystem')).toBe(3);
  });

  it('syncs only the delta after appending new events', async () => {
    appendAuditFile(auditDir, 'filesystem', 2); // 追加 2 条（续写链）
    const r = await runSync(opts());
    expect(r.total_synced).toBe(2);
    expect(cloud.received.get('filesystem')).toBe(5);
  });

  it('handles multiple servers as independent chains', async () => {
    writeAuditFile(auditDir, 'github', 2);
    const r = await runSync(opts());
    expect(r.total_synced).toBe(2);
    expect(cloud.received.get('github')).toBe(2);
    // 再次同步无新事件
    expect((await runSync(opts())).total_synced).toBe(0);
  });

  it('reports 409 with a clear message when the chain is broken', async () => {
    // 清空本地审计但保留游标 → 重建一条 prev_hash 不同的链（模拟本地链重置）
    const log = new AuditLog('0.1.0');
    log.append({
      agent: 'test', session: 's', server: 'broken', tool: 'x',
      argsHash: 'a'.padEnd(64, '0'), decision: 'allow', outcome: 'ok', policyVersion: '0.1.0',
    });
    // 手动篡改 prev_hash 制造断链
    const entry = { ...log.entries[0]!, prevHash: 'f'.repeat(64) };
    const broken = new AuditLog('0.1.0');
    (broken as unknown as { entries: unknown[] }).entries = [entry];
    writeFileSync(join(auditDir, 'broken.jsonl'), broken.toJSONL(), 'utf8');
    await expect(runSync(opts())).rejects.toThrow(/哈希链断裂/);
  });
});
