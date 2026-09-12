// `pod harden --upload`：上传交付物、不传原始审计。
import { createServer, type Server } from 'node:http';
import { spawn } from 'node:child_process';
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

const HERE = dirname(fileURLToPath(import.meta.url));
const CLI_INDEX = join(HERE, '../src/index.ts');
const TOKEN = 'h-token';

let root: string;
let home: string;
let auditDir: string;
let cloudPath: string;
let outDir: string;
let server: Server;
let apiUrl: string;
let received: Array<Record<string, unknown>>;
let failUpload: boolean;

async function run(args: string[]): Promise<{ out: string; status: number | null }> {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, ['--import', 'tsx', CLI_INDEX, ...args]);
    let out = '';
    child.stdout.on('data', (d) => (out += String(d)));
    child.stderr.on('data', (d) => (out += String(d)));
    child.on('close', (status) => resolve({ out, status }));
  });
}

beforeAll(async () => {
  server = createServer((req, res) => {
    let body = '';
    req.on('data', (c) => (body += String(c)));
    req.on('end', () => {
      if (req.headers['x-sync-token'] !== TOKEN) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: { code: 401, message: 'sync token 无效' } }));
        return;
      }
      if (failUpload) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: { code: 500, message: 'boom' } }));
        return;
      }
      received.push(JSON.parse(body) as Record<string, unknown>);
      res.writeHead(201, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ report: { id: 42 } }));
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', () => resolve()));
  apiUrl = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
});

afterAll(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), 'pod-harden-up-'));
  home = join(root, 'home');
  mkdirSync(join(home, '.claude'), { recursive: true });
  auditDir = join(root, 'audit');
  mkdirSync(auditDir, { recursive: true });
  outDir = join(root, 'out');
  cloudPath = join(root, 'cloud.json');
  writeFileSync(
    cloudPath,
    JSON.stringify({ api_url: apiUrl, agent_id: 1, sync_token: TOKEN }),
    'utf8',
  );
  // 造一条审计记录，否则 harden 不生成 policy-draft，也不导出证据包
  received = [];
  failUpload = false;
});

function hardenArgs(extra: string[] = []): string[] {
  return [
    'harden',
    '--home', home,
    '--audit-dir', auditDir,
    '--policy-dir', join(root, 'policies'),
    '--baseline', join(root, 'baseline.json'),
    '--out', outDir,
    '--config', cloudPath,
    ...extra,
  ];
}

describe('pod harden --upload', () => {
  it('上传交付物：带计数与正文，且不包含原始审计', async () => {
    const { out, status } = await run(hardenArgs(['--upload']));
    expect(status).toBe(0);
    expect(out).toContain('已上传到云端');
    expect(out).toContain('未上传：evidence.json');

    expect(received).toHaveLength(1);
    const body = received[0]!;
    expect(body.generated_at).toBeTruthy();
    expect(body.report_md).toContain('# pod 加固审计报告');
    expect(body.findings_json).toContain('pod-harden-findings/v1');
    // 计数与报告一致（展示页直接用这些数，不能靠前端解析 markdown）
    expect(typeof body.high).toBe('number');
    expect(typeof body.mcp_servers).toBe('number');
    // 证据包（原始审计链）不在上传体里
    expect(Object.keys(body)).not.toContain('evidence_json');
  });

  it('不加 --upload 时一个字节都不出网', async () => {
    const { status } = await run(hardenArgs());
    expect(status).toBe(0);
    expect(received).toHaveLength(0);
  });

  it('上传失败时报错并不静默（本地报告仍然生成好了）', async () => {
    failUpload = true;
    const { out, status } = await run(hardenArgs(['--upload']));
    expect(status).not.toBe(0);
    expect(out).toContain('上传加固报告失败');
    expect(out).toContain('加固审计报告已生成'); // 本地交付物不受影响
  });
});
