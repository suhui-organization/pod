/**
 * 攻击靶机：一个"真的会造成副作用"的 MCP server，专门用来验证网关是不是真挡住。
 *
 * 与 demo-server 的区别（关键）：demo 只是"返回一句话"，它无法证明拦没拦住；
 * 这个 server 会**真的读文件、真的写文件、真的落一个执行痕迹**，
 * 并且每次被调用都先往 effects log 追加一行。
 *
 * 于是"攻击有没有得手"有了客观判据：
 *   - effects log 里没有这条调用 → 调用根本没到 server，副作用不可能发生；
 *   - 目标文件 / marker 不存在 → 副作用确实没有发生。
 *
 * 用 MCP 低层 Server API（而不是 McpServer.tool）是刻意的：低层 API 不依赖 zod，
 * 于是这个 fixture 不需要给 apps/cli 新增任何依赖。
 *
 * 环境变量：
 *   POD_ATTACK_EFFECTS  副作用日志路径（每次调用先写这里）
 *   POD_ATTACK_MARKER   run_shell 的执行痕迹路径
 */
import { appendFileSync, readFileSync, writeFileSync } from 'node:fs';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { pathToFileURL } from 'node:url';
import { resolve } from 'node:path';

const EFFECTS = process.env.POD_ATTACK_EFFECTS ?? '/tmp/pod-attack-effects.log';

/** 先记痕迹再动作：日志里没有 = 这次调用没有到达 server */
function note(tool: string, detail: unknown): void {
  appendFileSync(EFFECTS, `${tool} ${JSON.stringify(detail)}\n`, 'utf8');
}

function text(value: string): { content: Array<{ type: 'text'; text: string }> } {
  return { content: [{ type: 'text', text: value }] };
}

const TOOLS = [
  {
    name: 'read_file',
    description: 'Read a file from disk',
    inputSchema: { type: 'object', properties: { path: { type: 'string' } }, required: ['path'] },
  },
  {
    name: 'write_file',
    description: 'Write content to a file',
    inputSchema: {
      type: 'object',
      properties: { path: { type: 'string' }, content: { type: 'string' } },
      required: ['path', 'content'],
    },
  },
  {
    name: 'run_shell',
    description: 'Run a shell command',
    inputSchema: { type: 'object', properties: { command: { type: 'string' } }, required: ['command'] },
  },
  {
    name: 'send_data',
    description: 'Send data to a URL',
    inputSchema: {
      type: 'object',
      properties: { url: { type: 'string' }, body: { type: 'string' } },
      required: ['url', 'body'],
    },
  },
  {
    name: 'fetch_url',
    description: 'Fetch a URL',
    inputSchema: { type: 'object', properties: { url: { type: 'string' } }, required: ['url'] },
  },
  { name: 'get_credentials', description: 'Return cloud credentials', inputSchema: { type: 'object', properties: {} } },
  {
    name: 'echo',
    description: 'Echo back the given message',
    inputSchema: { type: 'object', properties: { message: { type: 'string' } }, required: ['message'] },
  },
];

export function createAttackServer(): Server {
  const server = new Server({ name: 'pod-attack-target', version: '0.1.0' }, { capabilities: { tools: {} } });

  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const name = request.params.name;
    const args = (request.params.arguments ?? {}) as Record<string, unknown>;
    switch (name) {
      case 'read_file': {
        const path = String(args.path);
        note('read_file', path);
        return text(readFileSync(path, 'utf8'));
      }
      case 'write_file': {
        const path = String(args.path);
        note('write_file', path);
        writeFileSync(path, String(args.content ?? ''), 'utf8');
        return text(`wrote ${path}`);
      }
      case 'run_shell': {
        const command = String(args.command);
        note('run_shell', command);
        // 不执行真实 shell：留一个不可否认的执行痕迹就够判定"有没有穿透"
        const marker = process.env.POD_ATTACK_MARKER;
        if (marker) writeFileSync(marker, `executed: ${command}`, 'utf8');
        return text(`ran ${command}`);
      }
      case 'send_data': {
        const url = String(args.url);
        note('send_data', { url, bytes: String(args.body ?? '').length });
        // 不发真实请求，但"数据已交给外部端点"这件事在 effects log 里留痕
        return text(`sent to ${url}`);
      }
      case 'fetch_url': {
        const url = String(args.url);
        note('fetch_url', url);
        return text(`fetched ${url}`);
      }
      case 'get_credentials': {
        note('get_credentials', {});
        // 输出侧拦截的靶子：一个格式合法的 AWS access key
        return text('aws_access_key_id = AKIAIOSFODNN7EXAMPLE');
      }
      case 'echo': {
        note('echo', { len: String(args.message ?? '').length });
        return text(String(args.message ?? ''));
      }
      default:
        return { content: [{ type: 'text', text: `unknown tool ${name}` }], isError: true };
    }
  });

  return server;
}

const isMain =
  process.argv[1] !== undefined && import.meta.url === pathToFileURL(resolve(process.argv[1])).href;

if (isMain) {
  createAttackServer()
    .connect(new StdioServerTransport())
    .catch((err: unknown) => {
      console.error(err);
      process.exit(1);
    });
}
