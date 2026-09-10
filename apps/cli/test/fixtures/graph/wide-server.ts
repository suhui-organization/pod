import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';

const server = new Server({ name: 'wide-fixture', version: '0.1.0' }, { capabilities: { tools: {} } });
const str = { type: 'string' };
const TOOLS = [
  { name: 'read_file', inputSchema: { type: 'object', properties: { path: str } } },
  { name: 'read_secret', inputSchema: { type: 'object', properties: { path: str } } },
  { name: 'get_env', inputSchema: { type: 'object', properties: { name: str } } },
  { name: 'read_config', inputSchema: { type: 'object', properties: { path: str } } },
  { name: 'send_email', inputSchema: { type: 'object', properties: { to: str, body: str } } },
  { name: 'post_message', inputSchema: { type: 'object', properties: { channel: str, message: str } } },
  { name: 'webhook_notify', inputSchema: { type: 'object', properties: { url: str, body: str } } },
  { name: 'upload_file', inputSchema: { type: 'object', properties: { url: str, body: str } } },
];

server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));
server.setRequestHandler(CallToolRequestSchema, async () => ({ content: [{ type: 'text', text: 'ok' }] }));
await server.connect(new StdioServerTransport());
