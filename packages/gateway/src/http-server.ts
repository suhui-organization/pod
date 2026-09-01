/**
 * pod gateway — Streamable HTTP 常驻形态（供多 agent 通过 URL 连接）。
 *
 * 标准 session 模式：每个 MCP 会话一个 transport + Server 实例
 * （SDK 限制：Server.connect 一次一个 transport；stateless transport 不可复用）。
 * 请求带 Mcp-Session-Id 时复用对应会话；新会话由 sessionIdGenerator 分配。
 */
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { randomUUID } from 'node:crypto';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import type { Transport } from '@modelcontextprotocol/sdk/shared/transport.js';

export interface ServeHttpOptions {
  port: number;
  host?: string;
  /** 每个会话创建一个新的 MCP Server（upstream 连接由工厂内部共享） */
  createServer: () => { connect(transport: Transport): Promise<void> };
  log?: (msg: string) => void;
}

export interface HttpServeResult {
  server: ReturnType<typeof createServer>;
  url: string;
  port: number;
}

export function serveHttp(opts: ServeHttpOptions): Promise<HttpServeResult> {
  const log = opts.log ?? (() => {});
  const sessions = new Map<string, { transport: StreamableHTTPServerTransport; server: { connect(transport: Transport): Promise<void> } }>();

  const httpServer = createServer(async (req, res) => {
    const url = req.url ?? '/';
    if (url !== '/mcp' && url !== '/') {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'not found' }));
      return;
    }
    res.on('finish', () => log(`http ${req.method} ${url} -> ${res.statusCode}`));
    try {
      const sessionId = (req.headers['mcp-session-id'] as string | undefined) ?? undefined;
      // Accept 兼容层：SDK 要求客户端同时接受 application/json 与 text/event-stream，
      // 但部分客户端（如 OpenClaw bundle-mcp）只发 text/event-stream，纯 JSON 客户端只发
      // application/json。补齐缺失的媒体类型以通过 SDK 校验；响应模式按客户端原始
      // Accept 决定（SSE-only → SSE 流；JSON-only → JSON 响应）。
      const rawAccept = (req.headers.accept as string | undefined) ?? '';
      const wantsJson = rawAccept.includes('application/json');
      const wantsSse = rawAccept.includes('text/event-stream');
      if (rawAccept && (!wantsJson || !wantsSse)) {
        const patched = rawAccept + (wantsJson ? ', text/event-stream' : ', application/json');
        req.headers.accept = patched;
        log(`accept patched: "${rawAccept}" -> "${patched}"`);
      }
      let session = sessionId ? sessions.get(sessionId) : undefined;
      if (!session) {
        const server = opts.createServer();
        let transport: StreamableHTTPServerTransport | undefined;
        transport = new StreamableHTTPServerTransport({
          sessionIdGenerator: () => randomUUID(),
          // 纯 JSON 客户端（如 Codex rmcp）→ JSON 响应模式；其余默认 SSE 流
          enableJsonResponse: wantsJson && !wantsSse,
          onsessioninitialized: (id) => {
            if (transport) {
              sessions.set(id, { transport, server });
              log(`session initialized: ${id.slice(0, 8)}`);
            }
          },
        });
        await server.connect(transport);
        transport.onclose = () => {
          for (const [id, s] of sessions) {
            if (s.transport === transport) sessions.delete(id);
          }
        };
        session = { transport, server };
      }
      res.on('close', () => {
        // 不主动关闭会话 transport（SSE 断开会触发 onclose 清理）
      });
      // 不预读 body：Hono listener 需要原始流
      await session.transport.handleRequest(req as IncomingMessage & { body?: unknown }, res as ServerResponse);
    } catch (err) {
      log(`http handler error: ${err instanceof Error ? err.message : String(err)}`);
      if (!res.writableEnded && !res.headersSent) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'internal error' }));
      }
    }
  });

  const host = opts.host ?? '127.0.0.1';
  return new Promise((resolve, reject) => {
    httpServer.once('error', reject);
    httpServer.listen(opts.port, host, () => {
      const addr = httpServer.address() as { port: number };
      resolve({ server: httpServer, url: `http://${host}:${addr.port}/mcp`, port: addr.port });
    });
  });
}
