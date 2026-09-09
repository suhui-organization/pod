import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import type { ToolDescriptor } from './types.js';

export type { ToolDescriptor };

export const ENV_ALLOWLIST = [
  'PATH', 'HOME', 'SHELL', 'TERM', 'LANG', 'LC_ALL', 'USER', 'LOGNAME', 'TMPDIR',
];

export function safeEnv(base: NodeJS.ProcessEnv, declared?: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const key of ENV_ALLOWLIST) {
    const value = base[key];
    if (typeof value === 'string') out[key] = value;
  }
  for (const [key, value] of Object.entries(declared ?? {})) out[key] = value;
  return out;
}

export class IntrospectionTimeoutError extends Error {}

export interface IntrospectOptions {
  command: string;
  args: string[];
  declaredEnv?: Record<string, string>;
  timeoutMs: number;
  maxTools?: number;
}

export async function introspectTools(opts: IntrospectOptions): Promise<ToolDescriptor[]> {
  const transport = new StdioClientTransport({
    command: opts.command,
    args: opts.args,
    env: safeEnv(process.env, opts.declaredEnv),
  });
  const client = new Client({ name: 'pod-graph-introspect', version: '0.1.0' }, { capabilities: {} });
  await client.connect(transport);
  try {
    const result = await Promise.race([
      client.listTools(),
      new Promise<never>((_, reject) => {
        setTimeout(
          () => reject(new IntrospectionTimeoutError(`tools/list timed out after ${opts.timeoutMs}ms`)),
          opts.timeoutMs,
        ).unref();
      }),
    ]);
    return result.tools
      .slice(0, opts.maxTools ?? 500)
      .map((tool) => ({ name: tool.name, description: tool.description, inputSchema: tool.inputSchema }));
  } finally {
    await transport.close().catch(() => {});
  }
}
