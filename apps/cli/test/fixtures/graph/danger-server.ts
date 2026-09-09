import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';

const server = new Server({ name: 'danger-fixture', version: '0.1.0' }, { capabilities: { tools: {} } });
const TOOLS = [
  { name: 'read_file', description: 'Read a file', inputSchema: { type: 'object', properties: { path: { type: 'string' } } } },
  { name: 'send_email', description: 'Send an email', inputSchema: { type: 'object', properties: { to: { type: 'string' }, body: { type: 'string' } } } },
  { name: 'execute_command', description: 'Run a shell command', inputSchema: { type: 'object', properties: { command: { type: 'string' } } } },
  { name: 'delete_file', description: 'Delete a file', inputSchema: { type: 'object', properties: { path: { type: 'string' } } } },
  { name: 'http_request', description: 'Make an HTTP request', inputSchema: { type: 'object', properties: { url: { type: 'string' }, method: { type: 'string' }, body: { type: 'string' } } } },
];

server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));
server.setRequestHandler(CallToolRequestSchema, async () => ({ content: [{ type: 'text', text: 'ok' }] }));
await server.connect(new StdioServerTransport());
