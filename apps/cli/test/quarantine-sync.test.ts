// 云端熔断在机器侧的收敛：三条安全规则各一个用例。
//
// 这个文件是"云端能不能解除人工熔断"这个问题的答案所在——答案是不能。
import { createServer, type Server } from 'node:http';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { syncQuarantine, QUARANTINE_BY_CLOUD } from '../src/sync.js';
import { quarantineAdd } from '../src/control-plane.js';

const TOKEN = 'q-token';

let root: string;
let auditDir: string;
let quarantineFile: string;
let server: Server;
let apiUrl: string;
/** 云端"当前"的期望状态；测试里改这个 */
let cloudState: { quarantined: boolean; reason: string };
/** 让服务端模拟故障 */
let failMode: 'none' | 'http500' | 'offline';

function readState(): { agents: Record<string, { reason?: string; by?: string }> } {
  if (!existsSync(quarantineFile)) return { agents: {} };
  return JSON.parse(readFileSync(quarantineFile, 'utf8')) as { agents: Record<string, { reason?: string; by?: string }> };
}

beforeAll(async () => {
  server = createServer((req, res) => {
    if (failMode === 'offline') {
      req.socket.destroy();
      return;
    }
    if (failMode === 'http500') {
      res.writeHead(500);
      res.end('boom');
      return;
    }
    if (req.headers['x-sync-token'] !== TOKEN) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: { code: 401, message: 'sync token 无效' } }));
      return;
    }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ agent_id: 1, ...cloudState }));
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', () => resolve()));
  apiUrl = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
});

afterAll(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), 'pod-q-'));
  auditDir = join(root, 'audit');
  mkdirSync(join(auditDir, 'openclaw'), { recursive: true });
  mkdirSync(join(auditDir, 'claude-code'), { recursive: true });
  quarantineFile = join(root, 'quarantine.json');
  cloudState = { quarantined: false, reason: '' };
  failMode = 'none';
});

function call(localAgent = 'openclaw') {
  return syncQuarantine({
    api_url: apiUrl,
    sync_token: TOKEN,
    local_agent: localAgent,
    auditDir,
    quarantineFile,
  });
}

describe('云端熔断 → 机器侧收敛', () => {
  it('云端下发 → 本地落盘 + 记审计', async () => {
    cloudState = { quarantined: true, reason: '疑似被注入' };
    const r = await call();
    expect(r.applied).toEqual(['openclaw']);
    expect(readState().agents.openclaw).toMatchObject({ by: QUARANTINE_BY_CLOUD, reason: '疑似被注入' });

    const control = readFileSync(join(auditDir, 'openclaw/control.jsonl'), 'utf8');
    expect(control).toContain('quarantine:add');
  });

  it('本机全部 agent（local_agent="*"）时覆盖审计目录里出现的每个 agent', async () => {
    cloudState = { quarantined: true, reason: '整机隔离' };
    const r = await call('*');
    expect(r.applied.sort()).toEqual(['claude-code', 'openclaw']);
    expect(Object.keys(readState().agents).sort()).toEqual(['claude-code', 'openclaw']);
  });

  it('幂等：重复收敛不产生重复动作', async () => {
    cloudState = { quarantined: true, reason: 'x' };
    await call();
    const second = await call();
    expect(second.applied).toEqual([]);
    expect(readState().agents.openclaw?.by).toBe(QUARANTINE_BY_CLOUD);
  });
});

describe('三条安全规则', () => {
  it('规则 1：拉取失败什么都不做——断网不能等于解除熔断', async () => {
    cloudState = { quarantined: true, reason: 'x' };
    await call();
    expect(readState().agents.openclaw).toBeDefined();

    failMode = 'http500';
    const bad = await call();
    expect(bad.error).toBeTruthy();
    expect(bad.desired).toBeUndefined(); // 没拉到 ≠ 未熔断
    expect(readState().agents.openclaw).toBeDefined(); // 本地熔断纹丝不动

    failMode = 'offline';
    const down = await call();
    expect(down.error).toBeTruthy();
    expect(readState().agents.openclaw).toBeDefined();
  });

  it('规则 2：不接管人工下的熔断（不会被后续的云端解除顺手删掉）', async () => {
    quarantineAdd({ file: quarantineFile, agent: 'openclaw', reason: '人工处置', by: 'cli-user', auditDir });
    cloudState = { quarantined: true, reason: '云端也想拦' };
    const r = await call();
    expect(r.applied).toEqual([]); // 已处于熔断 → 不重复添加
    expect(readState().agents.openclaw?.by).toBe('cli-user'); // 所有权仍是人工
  });

  it('规则 3：云端解除只清自己的条目，人工条目留下', async () => {
    quarantineAdd({ file: quarantineFile, agent: 'openclaw', reason: '人工处置', by: 'cli-user', auditDir });
    cloudState = { quarantined: true, reason: 'x' };
    await call('claude-code'); // 云端只对 claude-code 生效
    expect(readState().agents['claude-code']?.by).toBe(QUARANTINE_BY_CLOUD);

    cloudState = { quarantined: false, reason: '' };
    const r = await call('*');
    expect(r.released).toEqual(['claude-code']); // 只解除云端那条
    expect(readState().agents.openclaw?.by).toBe('cli-user'); // 人工那条还在
    expect(readState().agents['claude-code']).toBeUndefined();

    const control = readFileSync(join(auditDir, 'claude-code/control.jsonl'), 'utf8');
    expect(control).toContain('quarantine:remove');
  });
});
