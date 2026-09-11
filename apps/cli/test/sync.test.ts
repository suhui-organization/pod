/**
 * pod sync 集成测试：进程内 mock Pod Cloud（/api/v1/sync/events），
 * 验证推送、幂等（游标）、增量续传、断链 409。
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createServer, type Server } from 'node:http';
import { generateKeyPairSync } from 'node:crypto';
import { mkdtempSync, writeFileSync, mkdirSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { AuditLog } from '@podsec/audit';
import { runSync, pullPolicies } from '../src/sync.js';
import { signPolicy } from '../src/policy-sign.js';

interface MockPolicy {
  id: number;
  name: string;
  agent_id: number | null;
  policy_json: string;
  version: string;
  signature?: string;
}

/** mock Pod Cloud：按 (server) 维护链尾 hash，断链返回 409；提供 /sync/policies */
function startMockCloud(): {
  url: string;
  close: () => void;
  received: Map<string, number>;
  setPolicies: (p: MockPolicy[]) => void;
} {
  const tails = new Map<string, string>();
  const received = new Map<string, number>();
  // 只有这两个 token 有效；其余一律 401（模拟被轮换/被删的 agent）
  const validTokens = new Set(['test-token', 'ok-token']);
  let policies: MockPolicy[] = [];
  const server: Server = createServer((req, res) => {
    if (req.url?.endsWith('/api/v1/sync/policies') && req.method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ agent_id: 1, policies }));
      return;
    }
    const authorized = validTokens.has(String(req.headers['x-sync-token'] ?? ''));
    if (req.url?.endsWith('/api/v1/sync/ping') && req.method === 'POST') {
      if (!authorized) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ detail: 'sync token 无效' }));
        return;
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ pong: true, agent_id: 1, event_count: 0 }));
      return;
    }
    if (req.method !== 'POST' || !req.url?.endsWith('/api/v1/sync/events')) {
      res.writeHead(404).end();
      return;
    }
    if (!authorized) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ detail: 'sync token 无效' }));
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
      resolve({
        url: `http://127.0.0.1:${addr.port}`,
        close: () => server.close(),
        received,
        setPolicies: (p) => {
          policies = p;
        },
      });
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

type MockCloud = ReturnType<typeof startMockCloud>;
let cloud: MockCloud;
let workDir: string;
let auditDir: string;

beforeAll(async () => {
  cloud = await startMockCloud();
  workDir = mkdtempSync(join(tmpdir(), 'pod-sync-'));
  auditDir = join(workDir, 'audit');
  const stateHome = join(workDir, 'state');
  mkdirSync(auditDir, { recursive: true });
  mkdirSync(join(stateHome, '.pod', 'sync-state'), { recursive: true });
  // 让 HOME 指向测试目录，sync-state 写入测试目录
  process.env.HOME = join(stateHome, 'home');
  mkdirSync(process.env.HOME, { recursive: true });
});

afterAll(() => cloud.close());

describe('pod sync (mock Pod Cloud)', () => {
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

  it('一条断链只标记它自己，不拖垮其它链，也不推进它的游标', async () => {
    // 制造一条 prev_hash 对不上的链（模拟本地链被重置/分叉）
    const log = new AuditLog('0.1.0');
    log.append({
      agent: 'test', session: 's', server: 'broken', tool: 'x',
      argsHash: 'a'.padEnd(64, '0'), decision: 'allow', outcome: 'ok', policyVersion: '0.1.0',
    });
    const entry = { ...log.entries[0]!, prevHash: 'f'.repeat(64) };
    const broken = new AuditLog('0.1.0');
    (broken as unknown as { entries: unknown[] }).entries = [entry];
    writeFileSync(join(auditDir, 'broken.jsonl'), broken.toJSONL(), 'utf8');
    // 同时放一条健康链：它必须照常上去
    writeAuditFile(auditDir, 'healthy', 2);

    const r = await runSync(opts());
    expect(r.failures).toHaveLength(1);
    expect(r.failures[0]!.server).toBe('broken');
    expect(r.failures[0]!.message).toMatch(/哈希链断裂/);
    expect(r.total_synced).toBe(2);
    expect(cloud.received.get('healthy')).toBe(2);

    // 失败的那条链不能推进游标,否则事件会被永久跳过
    const state = JSON.parse(
      readFileSync(join(process.env.HOME!, '.pod', 'sync-state', '1.json'), 'utf8'),
    ) as Record<string, string>;
    expect(state.broken).toBeUndefined();
  });

  it('一个死 token 的绑定不阻断其它绑定', async () => {
    writeAuditFile(auditDir, 'multi', 1);
    // 多绑定只能走 cloud.json
    const cfgPath = join(process.env.HOME!, '.pod', 'cloud.json');
    writeFileSync(
      cfgPath,
      JSON.stringify({
        api_url: cloud.url,
        agents: [
          { local_agent: 'test', agent_id: 99, sync_token: 'dead-token' },
          { local_agent: 'test', agent_id: 1, sync_token: 'test-token' },
        ],
      }),
      'utf8',
    );

    const r = await runSync({ config: cfgPath, auditDir });
    // 死绑定被逐个记下来(推送 401 + 心跳 401),而不是让整次同步崩掉
    expect(r.failures.some((f) => f.agent_id === 99 && /401/.test(f.message))).toBe(true);
    // 正常绑定照常同步
    expect(r.bindings.find((b) => b.agent_id === 1)!.synced).toBeGreaterThan(0);
  });
});

describe('pod pull-policy', () => {
  it('pulls agent-bound and template policies into the out dir', async () => {
    cloud.setPolicies([
      { id: 7, name: 'openclaw-main-policy', agent_id: 1, policy_json: '{"version":"0.1.0","agent":"openclaw-main","servers":{"filesystem":{"allow":["read_file"]}}}', version: '0.1.0' },
      { id: 8, name: 'baseline', agent_id: null, policy_json: '{"version":"0.1.0","agent":"x","defaultDecision":"deny"}', version: '0.2.0' },
    ]);
    const outDir = join(workDir, 'policies');
    const r = await pullPolicies({ apiUrl: cloud.url, agentId: 1, syncToken: 't', outDir });
    expect(r.policies).toHaveLength(2);
    expect(r.policies[0]!.path).toContain('7-openclaw-main-policy.json');
    expect(r.policies[1]!.path).toContain('8-baseline.json');
    // 内容落盘且为合法 JSON
    const { readFileSync } = await import('node:fs');
    const written = JSON.parse(readFileSync(r.policies[0]!.path, 'utf8'));
    expect(written.servers.filesystem.allow).toContain('read_file');
  });

  it('rejects invalid policy JSON from the cloud with a clear error', async () => {
    cloud.setPolicies([
      { id: 9, name: 'bad', agent_id: null, policy_json: '{not json', version: '0.1.0' },
    ]);
    await expect(
      pullPolicies({ apiUrl: cloud.url, agentId: 1, syncToken: 't', outDir: join(workDir, 'policies2') }),
    ).rejects.toThrow(/Unexpected token|JSON/);
  });

  it('verifies a signed policy and rejects tampering', async () => {
    const { privateKey, publicKey } = generateKeyPairSync('ed25519');
    const privatePem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
    const publicPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
    const policyJson = '{"version":"0.1.0","agent":"x","defaultDecision":"deny"}';
    const signature = signPolicy(JSON.parse(policyJson), privatePem);

    cloud.setPolicies([
      { id: 10, name: 'signed', agent_id: null, policy_json: policyJson, version: '0.1.0', signature },
    ]);
    const ok = await pullPolicies({
      apiUrl: cloud.url,
      agentId: 1,
      syncToken: 't',
      policyPublicKey: publicPem,
      outDir: join(workDir, 'signed'),
    });
    expect(ok.policies[0]!.verified).toBe(true);

    cloud.setPolicies([
      {
        id: 11,
        name: 'tampered',
        agent_id: null,
        policy_json: '{"version":"0.1.0","agent":"x","defaultDecision":"allow"}',
        version: '0.1.0',
        signature,
      },
    ]);
    await expect(
      pullPolicies({
        apiUrl: cloud.url,
        agentId: 1,
        syncToken: 't',
        policyPublicKey: publicPem,
        outDir: join(workDir, 'tampered'),
      }),
    ).rejects.toThrow(/签名无效/);

    cloud.setPolicies([{ id: 12, name: 'unsigned', agent_id: null, policy_json: policyJson, version: '0.1.0' }]);
    await expect(
      pullPolicies({
        apiUrl: cloud.url,
        agentId: 1,
        syncToken: 't',
        requireSignature: true,
        outDir: join(workDir, 'unsigned'),
      }),
    ).rejects.toThrow(/缺少签名/);
  });
});
