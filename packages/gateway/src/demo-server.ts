/**
 * demo MCP server：供 spike 与测试使用，不依赖外部网络。
 * 工具：echo / now / danger_delete（模拟破坏性操作，用于演示 deny 规则）。
 * 可直接运行：node --import tsx src/demo-server.ts
 */
import { z } from 'zod';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { pathToFileURL } from 'node:url';
import { resolve } from 'node:path';

export function createDemoServer(): McpServer {
  const server = new McpServer({ name: 'pod-demo-server', version: '0.1.0' });

  server.tool(
    'echo',
    'Echo back the given message',
    { message: z.string() },
    async ({ message }) => ({ content: [{ type: 'text', text: message }] }),
  );

  server.tool('now', 'Return the current UTC ISO timestamp', {}, async () => ({
    content: [{ type: 'text', text: new Date().toISOString() }],
  }));

  server.tool(
    'danger_delete',
    'Simulate a destructive operation (would delete a path)',
    { path: z.string() },
    async ({ path }) => ({ content: [{ type: 'text', text: `would delete ${path}` }] }),
  );

  return server;
}

const isMain =
  process.argv[1] !== undefined && import.meta.url === pathToFileURL(resolve(process.argv[1])).href;

if (isMain) {
  createDemoServer()
    .connect(new StdioServerTransport())
    .catch((err: unknown) => {
      console.error(err);
      process.exit(1);
    });
}
