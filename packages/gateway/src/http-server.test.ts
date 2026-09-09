import { describe, it, expect, afterEach } from 'vitest';
import type { Server } from 'node:http';
import { createDemoServer } from './demo-server.js';
import { serveHttp, type HttpServeResult } from './http-server.js';

/** 解析 SSE 响应 body，返回所有 data 行的 JSON 对象 */
async function parseSse(res: Response): Promise<unknown[]> {
  const text = await res.text();
  const events: unknown[] = [];
  for (const chunk of text.split('\n\n')) {
    for (const line of chunk.split('\n')) {
      if (line.startsWith('data: ')) {
        events.push(JSON.parse(line.slice(6)));
      }
    }
  }
  return events;
}

function initializeBody(protocolVersion = '2024-11-05') {
  return JSON.stringify({
    jsonrpc: '2.0',
    id: 1,
    method: 'initialize',
    params: { protocolVersion, capabilities: {}, clientInfo: { name: 'accept-test', version: '1' } },
  });
}

describe('serveHttp Accept 兼容层', () => {
  let server: Server;
  let base: string;
  let close: () => Promise<void>;

  afterEach(async () => {
    await close();
    server.closeAllConnections?.();
    await new Promise((r) => server.close(r));
  });

  async function start() {
    const result: HttpServeResult = await serveHttp({
      port: 0,
      createServer: () => createDemoServer(),
      log: () => {},
    });
    server = result.server;
    base = result.url;
    close = async () => {};
    return result;
  }

  it('SSE-only Accept（OpenClaw 风格）→ 200 + text/event-stream + 会话头', async () => {
    await start();
    const res = await fetch(base, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'text/event-stream',
      },
      body: initializeBody(),
    });
    expect(res.status).toBe(200);
    expect(res.headers.get('content-type')).toContain('text/event-stream');
    expect(res.headers.get('mcp-session-id')).toBeTruthy();
    const events = await parseSse(res);
    const result = events.find((e) => (e as { id?: unknown }).id === 1) as {
      result?: { serverInfo?: { name?: string } };
    };
    expect(result?.result?.serverInfo?.name).toBeTruthy();
  });

  it('JSON-only Accept（Codex rmcp 风格）→ 200 + application/json JSON-RPC 响应', async () => {
    await start();
    const res = await fetch(base, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      body: initializeBody(),
    });
    expect(res.status).toBe(200);
    expect(res.headers.get('content-type')).toContain('application/json');
    const body = (await res.json()) as { result?: { serverInfo?: { name?: string } } };
    expect(body.result?.serverInfo?.name).toBeTruthy();
  });

  it('双 Accept → 200 默认 SSE 流', async () => {
    await start();
    const res = await fetch(base, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json, text/event-stream',
      },
      body: initializeBody(),
    });
    expect(res.status).toBe(200);
    expect(res.headers.get('content-type')).toContain('text/event-stream');
    const events = await parseSse(res);
    expect(events.length).toBeGreaterThan(0);
  });

  it('无 Accept → 406', async () => {
    await start();
    const res = await fetch(base, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: initializeBody(),
    });
    expect(res.status).toBe(406);
  });
});

describe('serveHttp auth token (P2)', () => {
  let server: Server;

  afterEach(async () => {
    server.closeAllConnections?.();
    await new Promise((r) => server.close(r));
  });

  it('rejects requests without the token and accepts with it', async () => {
    const result = await serveHttp({
      port: 0,
      createServer: () => createDemoServer(),
      authToken: 'secret',
      log: () => {},
    });
    server = result.server;

    const unauthorized = await fetch(result.url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: initializeBody(),
    });
    expect(unauthorized.status).toBe(401);

    const ok = await fetch(result.url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
        Authorization: 'Bearer secret',
      },
      body: initializeBody(),
    });
    expect(ok.status).toBe(200);
  });
});
