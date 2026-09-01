/**
 * pod gateway — Streamable HTTP 常驻形态（供多 agent 通过 URL 连接）。
 *
 * stdio 形态由 agent 每次 spawn，无法常驻；HTTP 形态是常驻网关的正确架构。
 * 端点：POST/GET /mcp（MCP Streamable HTTP 协议）。
 * 默认只绑 127.0.0.1（本地优先，D3）。
 *
 * 无会话（stateless）模式：SDK 要求每个请求使用新的 transport + Server 实例，
 * 因此 serveHttp 接收 createServer 工厂（每请求调用一次）；upstream 连接
 * 由工厂内部共享（真实 MCP server 进程只 spawn 一次）。
 */
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';

export interface ServeHttpOptions {
  port: number;
  host?: string;
  /** 每请求创建一个新的 MCP Server（stateless 模式要求） */
  createServer: () => Server;
  /** 日志（走 stderr 惯例） */
  log?: (msg: string) => void;
}

export interface HttpServeResult {
  server: ReturnType<typeof createServer>;
  url: string;
  port: number;
}

export function serveHttp(opts: ServeHttpOptions): Promise<HttpServeResult> {
  const log = opts.log ?? (() => {});

  const httpServer = createServer(async (req, res) => {
    const url = req.url ?? '/';
    if (url !== '/mcp' && url !== '/') {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'not found' }));
      return;
    }
    res.on('finish', () => log(`http ${req.method} ${url} -> ${res.statusCode}`));
    let transport: StreamableHTTPServerTransport | undefined;
    try {
      // stateless：每请求新 transport + Server（SDK 限制：stateless transport
      // 不可复用；Server.connect 一次只能一个 transport）
      const server = opts.createServer();
      transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: undefined,
        onsessioninitialized: () => log('MCP session initialized'),
      });
      await server.connect(transport);
      res.on('close', () => {
        transport?.close().catch(() => {});
        server.close().catch(() => {});
      });
      // 不预读 body：Hono listener 需要原始流（预读会消费流导致空 body/500）
      await transport.handleRequest(req as IncomingMessage & { body?: unknown }, res as ServerResponse);
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
