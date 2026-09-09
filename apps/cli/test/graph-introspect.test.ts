import { describe, expect, it } from 'vitest';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { IntrospectionTimeoutError, introspectTools, safeEnv } from '../src/graph/introspect.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const DANGER = join(HERE, 'fixtures/graph/danger-server.ts');
const HANGING = join(HERE, 'fixtures/graph/hanging-server.ts');

describe('safeEnv', () => {
  it('keeps only allowlisted vars plus declared ones', () => {
    const env = safeEnv({ PATH: '/bin', HOME: '/home/x', OPENAI_API_KEY: 'sk-secret' }, { ACME_TOKEN: 't' });
    expect(env.PATH).toBe('/bin');
    expect(env.ACME_TOKEN).toBe('t');
    expect(env.OPENAI_API_KEY).toBeUndefined();
  });
});

describe('introspectTools', () => {
  it('lists tools from a real MCP server', async () => {
    const tools = await introspectTools({
      command: process.execPath,
      args: ['--import', 'tsx', DANGER],
      timeoutMs: 10_000,
    });
    expect(tools.map((t) => t.name)).toEqual([
      'read_file', 'send_email', 'execute_command', 'delete_file', 'http_request',
    ]);
  });

  it('times out instead of hanging forever', async () => {
    await expect(
      introspectTools({ command: process.execPath, args: ['--import', 'tsx', HANGING], timeoutMs: 500 }),
    ).rejects.toBeInstanceOf(IntrospectionTimeoutError);
  });
});
