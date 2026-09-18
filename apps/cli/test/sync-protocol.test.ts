/**
 * 端 A ↔ 端 B 的契约：协议版本 + 健康摘要。
 *
 * 这里守三件事：
 * 1. **每次都带上版本**（header），否则云端无法判断"这台机器装的是哪一版"；
 * 2. **健康摘要只含计数**——不含任何本机路径（隐私边界，与审计同步一致）；
 * 3. **老服务端不受影响**（不认识 body / 不返回协议字段时，同步照常、不误报）。
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createServer, type Server } from 'node:http';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { AuditLog } from '@podsec/audit';
import { DEFAULT_RULES } from '@podsec/policy';
import { runSync } from '../src/sync.js';
import { buildHealthSnapshot, collectReports } from '../src/health.js';
import { POD_PROTOCOL_VERSION, cliVersion } from '../src/protocol.js';

interface Captured {
  headers: Record<string, string | string[] | undefined>;
  body: Record<string, unknown> | null;
}

/** 桩云端：记下每个请求的 header 与 ping body，可切换成"老服务端"（不回协议字段） */
function startMockCloud(
  replyWithProtocol: boolean,
  supportsReports = true,
): Promise<{ url: string; close: () => void; pings: Captured[]; uploads: Record<string, unknown[]> }> {
  const pings: Captured[] = [];
  const uploads: Record<string, unknown[]> = { inventory: [], findings: [] };
  const server: Server = createServer((req, res) => {
    let raw = '';
    req.on('data', (c) => (raw += c));
    req.on('end', () => {
      if (req.url?.endsWith('/api/v1/sync/ping')) {
        pings.push({
          headers: req.headers,
          body: raw ? (JSON.parse(raw) as Record<string, unknown>) : null,
        });
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(
          JSON.stringify(
            replyWithProtocol
              ? {
                  pong: true,
                  server_protocol: POD_PROTOCOL_VERSION + 1,
                  min_client_protocol: POD_PROTOCOL_VERSION + 1,
                  client_outdated: true,
                  message: '本机 pod 版本过旧：请升级后再接入',
                }
              : { pong: true, agent_id: 1, event_count: 0 },
          ),
        );
        return;
      }
      if (req.url?.endsWith('/api/v1/sync/quarantine')) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ quarantined: false }));
        return;
      }
      if (req.url?.endsWith('/api/v1/sync/inventory') || req.url?.endsWith('/api/v1/sync/findings')) {
        if (!supportsReports) {
          // 老服务端：没有这两个端点 → 客户端必须容忍（提示而不是失败）
          res.writeHead(404, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ detail: 'Not Found' }));
          return;
        }
        const key = req.url.endsWith('/inventory') ? 'inventory' : 'findings';
        uploads[key]!.push(JSON.parse(raw) as unknown);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: true }));
        return;
      }
      // 其余端点（events / policies）一律返回空结果：本测试只关心契约
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ synced: 0, agent_id: 1, policies: [], events: [] }));
    });
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address() as { port: number };
      resolve({ url: `http://127.0.0.1:${port}`, close: () => server.close(), pings, uploads });
    });
  });
}

let home: string;
let auditDir: string;

beforeAll(() => {
  home = mkdtempSync(join(tmpdir(), 'pod-proto-home-'));
  auditDir = join(home, '.pod', 'audit', 'demo');
  mkdirSync(auditDir, { recursive: true });
  const log = new AuditLog('0.1.0');
  for (let i = 0; i < 3; i++) {
    log.append({
      agent: 'demo', session: 's', server: 'fs',
      tool: i === 2 ? 'delete_file' : 'read_file',
      argsHash: `h${i}`.padEnd(64, '0'),
      decision: i === 2 ? 'deny' : 'allow', outcome: i === 2 ? 'blocked' : 'ok',
      policyVersion: '0.1.0',
    });
  }
  writeFileSync(join(auditDir, 'fs.jsonl'), log.toJSONL(), 'utf8');
  // 一个未纳管的 MCP server（本地配置，用于验证 coverage 计数）
  mkdirSync(join(home, '.claude'), { recursive: true });
  writeFileSync(
    join(home, '.claude.json'),
    JSON.stringify({ mcpServers: { github: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-github'] } } }),
    'utf8',
  );
});

describe('健康摘要（端 A 本地采集）', () => {
  it('给出链数 / 断裂数 / 最近工具调用 / 覆盖率 / guard 计数', () => {
    const health = buildHealthSnapshot({ home, auditDir, rules: DEFAULT_RULES });
    expect(health.audit.chains).toBe(1);
    expect(health.audit.broken).toBe(0);
    expect(health.audit.last_call_at).toBeTruthy();
    expect(health.coverage.servers).toBeGreaterThanOrEqual(1);
    expect(health.coverage.unmanaged).toBeGreaterThanOrEqual(1);
    expect(health.guard).not.toBeNull();
    expect(health.guard!.scanned_at).toBeTruthy();
  });

  it('链被改过时 broken > 0（云端此前完全看不到这件事）', () => {
    const tamperedDir = join(home, '.pod', 'audit', 'tampered');
    mkdirSync(tamperedDir, { recursive: true });
    const log = new AuditLog('0.1.0');
    log.append({ agent: 'demo', session: 's', server: 'fs', tool: 'read_file', argsHash: 'a'.repeat(64), decision: 'allow', outcome: 'ok' });
    const entries = JSON.parse(log.toJSONL().trim());
    entries.decision = 'deny'; // 改一条记录
    writeFileSync(join(tamperedDir, 'fs.jsonl'), `${JSON.stringify(entries)}\n`, 'utf8');
    const health = buildHealthSnapshot({ home, auditDir: tamperedDir, rules: DEFAULT_RULES });
    expect(health.audit.broken).toBe(1);
  });

  it('只出计数：摘要里不出现本机路径（隐私边界）', () => {
    const health = buildHealthSnapshot({ home, auditDir, rules: DEFAULT_RULES });
    const text = JSON.stringify(health);
    expect(text).not.toContain(home);
    expect(text).not.toContain('.claude.json');
    expect(text).not.toContain('github'); // 未纳管 server 的名字也不出本机，只报数量
  });
});

describe('同步请求携带协议版本与健康摘要', () => {
  it('header 带协议与客户端版本，ping body 带健康摘要；服务端提示会转成 notices', async () => {
    const cloud = await startMockCloud(true);
    try {
      const result = await runSync({
        auditDir: join(home, '.pod', 'audit'),
        apiUrl: cloud.url,
        agentId: 1,
        syncToken: 'tok',
        home,
        rules: DEFAULT_RULES,
      });
      const ping = cloud.pings.at(-1)!;
      expect(ping.headers['x-pod-protocol']).toBe(String(POD_PROTOCOL_VERSION));
      expect(ping.headers['x-pod-version']).toBe(cliVersion());
      const body = ping.body as { protocol_version?: number; pod_version?: string; health?: { audit?: unknown } };
      expect(body.protocol_version).toBe(POD_PROTOCOL_VERSION);
      expect(body.pod_version).toBe(cliVersion());
      expect(body.health?.audit).toBeTruthy();
      // 隐私：ping body 里同样不能有本机路径
      expect(JSON.stringify(body)).not.toContain(home);
      // 服务端说客户端过旧 → 转成给用户看的提示（而不是静默）
      expect(result.notices.join(' ')).toContain('版本过旧');
    } finally {
      cloud.close();
    }
  });

  it('老服务端（不返回协议字段）不产生误报', async () => {
    const cloud = await startMockCloud(false);
    try {
      const result = await runSync({
        auditDir: join(home, '.pod', 'audit'),
        apiUrl: cloud.url,
        agentId: 1,
        syncToken: 'tok',
        home,
        rules: DEFAULT_RULES,
      });
      expect(result.notices).toEqual([]);
    } finally {
      cloud.close();
    }
  });
});

describe('② 资产清单 与 ③ 发现（pod 干的活的另一半）', () => {
  it('资产只出标识与布尔：harness / server / 覆盖率都在，路径与命令行不在', () => {
    const { inventory } = collectReports({ home, auditDir, rules: DEFAULT_RULES });
    expect(inventory.harnesses.some((h) => h.id === 'claude-code')).toBe(true);
    const server = inventory.servers.find((s) => s.name === 'github');
    expect(server).toBeTruthy();
    expect(server!.behind_gateway).toBe(false); // 没接管 → 策略与审计对它无效
    expect(server!.harness).toBe('claude-code');
    expect(inventory.coverage.unmanaged).toBeGreaterThanOrEqual(1);

    // 隐私边界：没有本机路径、没有命令行、没有 args
    const text = JSON.stringify(inventory);
    expect(text).not.toContain(home);
    expect(text).not.toContain('.claude.json');
    expect(text).not.toContain('npx');
  });

  it('发现按 (来源, 威胁/类别, 级别, harness) 聚合，且不含证据原文', () => {
    const { findings } = collectReports({ home, auditDir, rules: DEFAULT_RULES });
    expect(findings.findings.length).toBeGreaterThan(0);
    expect(findings.findings.every((f) => f.count >= 1)).toBe(true);
    expect(findings.findings.some((f) => f.source === 'guard')).toBe(true);
    expect(Object.keys(findings.totals)).toEqual(['high', 'medium', 'low']);
    const text = JSON.stringify(findings);
    expect(text).not.toContain(home);
    expect(text).not.toContain('.claude.json');
  });

  it('资产与发现会同 sync 一起推上去', async () => {
    const cloud = await startMockCloud(true);
    try {
      await runSync({
        auditDir: join(home, '.pod', 'audit'),
        apiUrl: cloud.url,
        agentId: 1,
        syncToken: 'tok',
        home,
        rules: DEFAULT_RULES,
      });
      expect(cloud.uploads.inventory!.length).toBeGreaterThan(0);
      expect(cloud.uploads.findings!.length).toBeGreaterThan(0);
      const inv = cloud.uploads.inventory![0] as { inventory: { servers: unknown[] } };
      expect(inv.inventory.servers.length).toBeGreaterThan(0);
    } finally {
      cloud.close();
    }
  });

  it('老服务端没有这两个端点（404）时：提示而不是失败', async () => {
    const cloud = await startMockCloud(true, false);
    try {
      const result = await runSync({
        auditDir: join(home, '.pod', 'audit'),
        apiUrl: cloud.url,
        agentId: 1,
        syncToken: 'tok',
        home,
        rules: DEFAULT_RULES,
      });
      expect(result.failures).toEqual([]);
      expect(result.notices.join(' ')).toContain('不支持');
    } finally {
      cloud.close();
    }
  });
});
