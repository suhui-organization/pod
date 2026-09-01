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

export interface ServeHttpOptions {
  port: number;
  host?: string;
  /** 每个会话创建一个新的 MCP Server（upstream 连接由工厂内部共享） */
  createServer: () => Server;
  log?: (msg: string) => void;
}

export interface HttpServeResult {
  server: ReturnType<typeof createServer>;
  url: string;
  port: number;
}

export function serveHttp(opts: ServeHttpOptions): Promise<HttpServeResult> {
  const log = opts.log ?? (() => {});
  const sessions = new Map<string, { transport: StreamableHTTPServerTransport; server: Server }>();

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
      let session = sessionId ? sessions.get(sessionId) : undefined;
      if (!session) {
        const server = opts.createServer();
        let transport: StreamableHTTPServerTransport | undefined;
        transport = new StreamableHTTPServerTransport({
          sessionIdGenerator: () => randomUUID(),
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
