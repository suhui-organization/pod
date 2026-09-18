/**
 * 控制台 HTTP 面的测试。
 *
 * 重点不是"接口能返回数据"，而是**写操作的四道闸门**：
 * 只读模式、token、Content-Type、同源。cookie 鉴权下这四条是本地服务的 CSRF 防线，
 * 少一条就等于把"任何网页都能让 pod 写本机文件"这件事放出去。
 */
import { afterEach, describe, expect, it } from 'vitest';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { serveConsole, type UiServerHandle } from './server.js';

let handle: UiServerHandle | null = null;

function makeHome(): string {
  const home = mkdtempSync(join(tmpdir(), 'pod-ui-'));
  mkdirSync(join(home, '.claude'), { recursive: true });
  writeFileSync(
    join(home, '.claude.json'),
    JSON.stringify({ mcpServers: { github: { command: 'npx', args: ['-y', 'pkg'] } } }),
    'utf8',
  );
  return home;
}

/**
 * 造一个"机器上装了 pod"的条件。
 *
 * 接管会把 harness 的启动命令改写成 `pod serve …`，所以它要求 `pod` 可执行
 * （不在 PATH 上就拒绝执行——包装命令跑不起来会让该 harness 的 MCP server
 * 全部失效）。CI 里没有全局安装的 pod，因此测试显式给一个可执行文件，
 * 走的就是产品里的 `--pod-bin` 同一条路。
 */
function fakePodBin(home: string): string {
  const path = join(home, 'pod');
  writeFileSync(path, '#!/bin/sh\nexit 0\n', 'utf8');
  chmodSync(path, 0o755);
  return path;
}

async function start(home: string, allowWrites: boolean): Promise<UiServerHandle> {
  const webRoot = join(home, 'webroot');
  mkdirSync(webRoot, { recursive: true });
  handle = await serveConsole({
    home,
    webRoot,
    port: 0,
    token: 'test-token',
    allowWrites,
    podBin: fakePodBin(home),
  });
  return handle;
}

afterEach(async () => {
  if (handle) await handle.close();
  handle = null;
});

function call(
  path: string,
  init?: { method?: string; token?: string; contentType?: string | null; origin?: string; body?: unknown },
): Promise<Response> {
  const headers: Record<string, string> = {};
  if (init?.token !== undefined) headers['x-pod-token'] = init.token;
  // 默认 application/json；显式传 null 表示"不带这个头"（用来测 415 那条闸门）
  const contentType = init?.contentType === undefined ? 'application/json' : init.contentType;
  if (contentType !== null) headers['Content-Type'] = contentType;
  if (init?.origin) headers.Origin = init.origin;
  // handle.url 形如 http://127.0.0.1:PORT/?token=…：自己拼 host，别去抠字符串
  return fetch(`http://127.0.0.1:${handle!.port}${path}`, {
    method: init?.method ?? 'GET',
    headers,
    ...(init?.body === undefined ? {} : { body: JSON.stringify(init.body) }),
  });
}

describe('读取接口', () => {
  it('/api/agents 带上 harness 扫描结果与写能力标记', async () => {
    const home = makeHome();
    await start(home, true);
    const res = await call('/api/agents', { token: 'test-token' });
    expect(res.status).toBe(200);
    const payload = (await res.json()) as {
      harnesses: Array<{ id: string; installed: boolean; managed: boolean }>;
      capabilities: { writes: boolean };
      agents: unknown[];
    };
    expect(payload.capabilities.writes).toBe(true);
    const claude = payload.harnesses.find((h) => h.id === 'claude-code')!;
    expect(claude.installed).toBe(true);
    expect(claude.managed).toBe(false);
  });

  it('/api/harnesses 只扫 harness', async () => {
    const home = makeHome();
    await start(home, false);
    const res = await call('/api/harnesses', { token: 'test-token' });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { harnesses: unknown[]; capabilities: { writes: boolean } };
    expect(body.harnesses.length).toBeGreaterThan(0);
    expect(body.capabilities.writes).toBe(false);
  });

  it('没有 token 一律 401（读也一样）', async () => {
    const home = makeHome();
    await start(home, true);
    expect((await call('/api/agents')).status).toBe(401);
  });
});

describe('写操作的四道闸门', () => {
  it('只读模式下 POST 被拒，且不产生任何文件', async () => {
    const home = makeHome();
    await start(home, false);
    const res = await call('/api/agents/enroll', {
      method: 'POST',
      token: 'test-token',
      body: { harness: 'claude-code', agent: 'claude-code' },
    });
    expect(res.status).toBe(403);
    expect(existsSync(join(home, '.pod/identity/claude-code'))).toBe(false);
    expect(existsSync(join(home, '.pod/policies/claude-code.json'))).toBe(false);
  });

  it('缺 token 的 POST 是 401', async () => {
    const home = makeHome();
    await start(home, true);
    const res = await call('/api/agents/enroll', {
      method: 'POST',
      body: { harness: 'claude-code', agent: 'claude-code' },
    });
    expect(res.status).toBe(401);
  });

  it('非 JSON 的 Content-Type 是 415（跨站表单发不出 application/json）', async () => {
    const home = makeHome();
    await start(home, true);
    const res = await call('/api/agents/enroll', {
      method: 'POST',
      token: 'test-token',
      contentType: 'text/plain',
      body: { harness: 'claude-code', agent: 'claude-code' },
    });
    expect(res.status).toBe(415);
  });

  it('跨站 Origin 是 403', async () => {
    const home = makeHome();
    await start(home, true);
    const res = await call('/api/agents/enroll', {
      method: 'POST',
      token: 'test-token',
      origin: 'http://evil.example',
      body: { harness: 'claude-code', agent: 'claude-code' },
    });
    expect(res.status).toBe(403);
  });

  it('同源 Origin 放行（浏览器正常调用）', async () => {
    const home = makeHome();
    const server = await start(home, true);
    const origin = `http://127.0.0.1:${server.port}`;
    const res = await call('/api/agents/enroll', {
      method: 'POST',
      token: 'test-token',
      origin,
      body: { harness: 'claude-code', agent: 'claude-code' },
    });
    expect(res.status).toBe(200);
  });

  it('未知的 POST 路径是 404，其它方法仍是 405', async () => {
    const home = makeHome();
    await start(home, true);
    expect(
      (await call('/api/whatever', { method: 'POST', token: 'test-token', body: {} })).status,
    ).toBe(404);
    expect((await call('/api/agents', { method: 'DELETE', token: 'test-token' })).status).toBe(405);
  });
});

describe('纳管端到端', () => {
  it('enroll 建身份/零权限策略/审计，返回新鲜 payload，并留下哈希链记录', async () => {
    const home = makeHome();
    await start(home, true);
    const res = await call('/api/agents/enroll', {
      method: 'POST',
      token: 'test-token',
      body: { harness: 'claude-code', agent: 'claude-code' },
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      result: { changed: Record<string, boolean>; identityFingerprint: string };
      payload: {
        harnesses: Array<{ id: string; managed: boolean; hasPolicy: boolean }>;
        agents: Array<{ id: string }>;
      };
    };
    expect(body.result.changed.identity).toBe(true);
    expect(body.result.identityFingerprint).toMatch(/^[0-9a-f]+$/);
    // 返回的 payload 是写完之后的新状态——前端不必再发一次 GET
    const enrolled = body.payload.harnesses.find((h) => h.id === 'claude-code')!;
    expect(enrolled.managed).toBe(true);
    expect(enrolled.hasPolicy).toBe(true);
    expect(body.payload.agents.map((a) => a.id)).toContain('claude-code');

    // 事件落在被纳管 agent 的链上（不是 _control）：否则 pod sync 带不上云
    const chain = join(home, '.pod/audit/claude-code/control.jsonl');
    expect(existsSync(chain)).toBe(true);
    expect(readFileSync(chain, 'utf8')).toContain('console:enroll:claude-code');

    const policy = JSON.parse(
      readFileSync(join(home, '.pod/policies/claude-code.json'), 'utf8'),
    ) as { defaultDecision: string; servers: Record<string, unknown> };
    expect(policy.defaultDecision).toBe('deny');
    expect(Object.keys(policy.servers)).toHaveLength(0);
  });

  it('非法 agent 名返回 400，不产生文件', async () => {
    const home = makeHome();
    await start(home, true);
    const res = await call('/api/agents/enroll', {
      method: 'POST',
      token: 'test-token',
      body: { harness: 'claude-code', agent: '../../etc/passwd' },
    });
    expect(res.status).toBe(400);
    expect(existsSync(join(home, '.pod/policies'))).toBe(false);
  });

  it('forget 移除纳管后，payload 里该 harness 回到未纳管', async () => {
    const home = makeHome();
    await start(home, true);
    await call('/api/agents/enroll', {
      method: 'POST',
      token: 'test-token',
      body: { harness: 'claude-code', agent: 'claude-code' },
    });
    const res = await call('/api/agents/forget', {
      method: 'POST',
      token: 'test-token',
      body: { agent: 'claude-code' },
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      result: { found: boolean; removed: { policy: boolean } };
      payload: { harnesses: Array<{ id: string; managed: boolean }> };
    };
    expect(body.result.found).toBe(true);
    expect(body.result.removed.policy).toBe(true);
    // 身份与审计目录刻意保留 → managed 仍可能为真；关键是"没有策略了"
    expect(body.payload.harnesses.find((h) => h.id === 'claude-code')!.hasPolicy).toBe(false);
  });
});

describe('接管端到端', () => {
  it('计划接口只读：返回改前/改后，但不改配置', async () => {
    const home = makeHome();
    await start(home, true);
    const res = await call('/api/agents/takeover-plan?harness=claude-code', { token: 'test-token' });
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      plan: { entries: Array<{ servers: Array<{ from: string; to: string }> }>; applicable: boolean };
      writes: boolean;
    };
    expect(body.writes).toBe(true);
    expect(body.plan.entries.length).toBe(1);
    expect(body.plan.entries[0]!.servers[0]!.to).toContain('serve --record-only');
    const config = JSON.parse(readFileSync(join(home, '.claude.json'), 'utf8')) as {
      mcpServers: Record<string, { command: string }>;
    };
    expect(config.mcpServers.github!.command).toBe('npx');
  });

  it('接管改写配置并留下备份；还原后回到原样', async () => {
    const home = makeHome();
    await start(home, true);
    const before = readFileSync(join(home, '.claude.json'), 'utf8');
    const res = await call('/api/agents/takeover', {
      method: 'POST',
      token: 'test-token',
      body: { harness: 'claude-code', agent: 'claude-code' },
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      result: { changed: Array<{ backup: string }> };
      payload: { harnesses: Array<{ id: string; servers: { behindGateway: number } }> };
    };
    expect(existsSync(body.result.changed[0]!.backup)).toBe(true);
    expect(body.payload.harnesses.find((h) => h.id === 'claude-code')!.servers.behindGateway).toBe(1);

    const revert = await call('/api/agents/revert', {
      method: 'POST',
      token: 'test-token',
      body: { agent: 'claude-code' },
    });
    expect(revert.status).toBe(200);
    expect(readFileSync(join(home, '.claude.json'), 'utf8')).toBe(before);
  });

  it('只读模式下接管也是 403（两道写闸门共用一套检查）', async () => {
    const home = makeHome();
    await start(home, false);
    const res = await call('/api/agents/takeover', {
      method: 'POST',
      token: 'test-token',
      body: { harness: 'claude-code', agent: 'claude-code' },
    });
    expect(res.status).toBe(403);
    const config = JSON.parse(readFileSync(join(home, '.claude.json'), 'utf8')) as {
      mcpServers: Record<string, { command: string }>;
    };
    expect(config.mcpServers.github!.command).toBe('npx');
  });
});

describe('切执法端到端', () => {
  it('没有编译好的策略时计划不可执行（前端据此禁用确认按钮）', async () => {
    const home = makeHome();
    await start(home, true);
    // 先接管，让 server 进网关（只录不拦）
    await call('/api/agents/takeover', {
      method: 'POST',
      token: 'test-token',
      body: { harness: 'claude-code', agent: 'claude-code' },
    });
    const res = await call('/api/agents/enforce-plan?harness=claude-code&mode=enforce', {
      token: 'test-token',
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { plan: { applicable: boolean; blockedReason: string } };
    expect(body.plan.applicable).toBe(false);
    expect(body.plan.blockedReason).toContain('pod policy draft');
  });

  it('有计划 → 切执法 → 回到只录不拦，配置与 payload 都跟着变', async () => {
    const home = makeHome();
    await start(home, true);
    await call('/api/agents/takeover', {
      method: 'POST',
      token: 'test-token',
      body: { harness: 'claude-code', agent: 'claude-code' },
    });
    mkdirSync(join(home, '.pod/policies'), { recursive: true });
    writeFileSync(
      join(home, '.pod/policies/draft.json'),
      JSON.stringify({
        version: '0.1.0',
        agent: 'claude-code',
        defaultDecision: 'deny',
        servers: { github: { allow: ['search'] } },
      }),
      'utf8',
    );

    const plan = await call('/api/agents/enforce-plan?harness=claude-code&mode=enforce', {
      token: 'test-token',
    });
    const planBody = (await plan.json()) as { plan: { applicable: boolean; policyLabel: string } };
    expect(planBody.plan.applicable).toBe(true);
    expect(planBody.plan.policyLabel).toContain('draft.json');

    const applied = await call('/api/agents/enforce', {
      method: 'POST',
      token: 'test-token',
      body: { harness: 'claude-code', mode: 'enforce' },
    });
    expect(applied.status).toBe(200);
    const appliedBody = (await applied.json()) as {
      result: { mode: string };
      payload: { harnesses: Array<{ id: string; servers: { enforcing: number; recordOnly: number }; enforcedPolicy: string | null }> };
    };
    expect(appliedBody.result.mode).toBe('enforce');
    const candidate = appliedBody.payload.harnesses.find((h) => h.id === 'claude-code')!;
    expect(candidate.servers.enforcing).toBe(1);
    expect(candidate.servers.recordOnly).toBe(0);
    expect(candidate.enforcedPolicy).toContain('draft.json');

    const back = await call('/api/agents/enforce', {
      method: 'POST',
      token: 'test-token',
      body: { harness: 'claude-code', mode: 'record-only' },
    });
    const backBody = (await back.json()) as {
      payload: { harnesses: Array<{ id: string; servers: { enforcing: number; recordOnly: number } }> };
    };
    const backCandidate = backBody.payload.harnesses.find((h) => h.id === 'claude-code')!;
    expect(backCandidate.servers.recordOnly).toBe(1);
    expect(backCandidate.servers.enforcing).toBe(0);
  });

  it('只读模式下切执法也是 403', async () => {
    const home = makeHome();
    await start(home, false);
    const res = await call('/api/agents/enforce', {
      method: 'POST',
      token: 'test-token',
      body: { harness: 'claude-code', mode: 'enforce' },
    });
    expect(res.status).toBe(403);
  });
});
