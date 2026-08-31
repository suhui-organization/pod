import { describe, it, expect, beforeEach } from 'vitest';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { AuditLog } from '@podsec/audit';
import type { Policy } from '@podsec/policy';
import { createDemoServer } from './demo-server.js';
import { createProxyServer } from './proxy.js';

/** SDK 1.30 将 callTool 返回类型放宽为 union，测试里收窄后取文本 */
type CallToolResponse = Awaited<ReturnType<Client['callTool']>>;
function textOf(result: CallToolResponse): string {
  if (!('content' in result)) return '';
  const content = result.content as Array<{ type?: string; text?: string }>;
  return content[0]?.text ?? '';
}

const policy: Policy = {
  version: '0.1.0',
  agent: 'test-agent',
  defaultDecision: 'deny',
  servers: {
    demo: {
      allow: ['echo', 'now'],
      deny: ['danger_delete'],
    },
  },
};

async function connectPair() {
  const [a, b] = InMemoryTransport.createLinkedPair();
  return { a, b };
}

describe('createProxyServer (in-memory)', () => {
  let audit: AuditLog;
  let agentClient: Client;

  beforeEach(async () => {
    audit = new AuditLog(policy.version);

    // 真实 server（demo）↔ upstream client
    const demo = createDemoServer();
    const { a: demoSide, b: upClientSide } = await connectPair();
    await demo.connect(demoSide);
    const upstream = new Client({ name: 'test-upstream', version: '0.1.0' }, { capabilities: {} });
    await upstream.connect(upClientSide);

    // proxy server ↔ agent client
    const proxy = createProxyServer({
      agent: 'test-agent',
      serverName: 'demo',
      policy,
      audit,
      connectUpstream: async () => upstream,
    });
    const { a: agentSide, b: proxySide } = await connectPair();
    await proxy.connect(proxySide);
    agentClient = new Client({ name: 'test-agent-client', version: '0.1.0' }, { capabilities: {} });
    await agentClient.connect(agentSide);
  });

  it('passes through the tool list from the real server', async () => {
    const { tools } = await agentClient.listTools();
    const names = tools.map((t) => t.name).sort();
    expect(names).toEqual(['danger_delete', 'echo', 'now']);
  });

  it('forwards an allowed call and audits it', async () => {
    const result = await agentClient.callTool({ name: 'echo', arguments: { message: 'hello pod' } });
    expect(result.isError).toBeFalsy();
    expect(textOf(result)).toBe('hello pod');

    expect(audit.entries).toHaveLength(1);
    const e = audit.entries[0]!;
    expect(e.decision).toBe('allow');
    expect(e.outcome).toBe('ok');
    expect(e.tool).toBe('echo');
    expect(e.argsHash).toMatch(/^[0-9a-f]{64}$/);
    expect(audit.verify()).toEqual({ ok: true });
  });

  it('blocks a denied call with a structured error and audits it', async () => {
    const result = await agentClient.callTool({ name: 'danger_delete', arguments: { path: '/etc' } });
    expect(result.isError).toBe(true);
    expect(textOf(result)).toContain('blocked (deny)');

    expect(audit.entries).toHaveLength(1);
    expect(audit.entries[0]!.decision).toBe('deny');
    expect(audit.entries[0]!.outcome).toBe('blocked');
  });

  it('fails closed for tools not listed in the policy', async () => {
    const result = await agentClient.callTool({ name: 'unlisted', arguments: {} });
    expect(result.isError).toBe(true);
    expect(audit.entries[0]!.decision).toBe('deny');
  });

  it('fails closed for approve-required tools until the approval flow exists (v0)', async () => {
    const p: Policy = {
      version: '0.1.0',
      agent: 'test-agent',
      servers: { demo: { approve: ['echo'] } },
    };
    // 重新构造一个仅 approve 策略的 proxy
    const demo = createDemoServer();
    const { a: demoSide, b: upClientSide } = await connectPair();
    await demo.connect(demoSide);
    const upstream = new Client({ name: 'test-upstream', version: '0.1.0' }, { capabilities: {} });
    await upstream.connect(upClientSide);
    const proxy = createProxyServer({
      agent: 'test-agent',
      serverName: 'demo',
      policy: p,
      audit,
      connectUpstream: async () => upstream,
    });
    const { a: agentSide, b: proxySide } = await connectPair();
    await proxy.connect(proxySide);
    const client = new Client({ name: 'test-agent-client', version: '0.1.0' }, { capabilities: {} });
    await client.connect(agentSide);

    const result = await client.callTool({ name: 'echo', arguments: { message: 'x' } });
    expect(result.isError).toBe(true);
    expect(audit.entries[0]!.decision).toBe('approve');
    expect(audit.entries[0]!.outcome).toBe('blocked');
  });

  it('propagates upstream tool errors and audits them as error outcome', async () => {
    // demo server 的 echo 对非字符串参数会抛错（zod 校验失败）——用非法参数触发
    const result = await agentClient.callTool({ name: 'echo', arguments: { message: 42 } });
    expect(result.isError).toBe(true);
    expect(audit.entries).toHaveLength(1);
    expect(audit.entries[0]!.outcome).toBe('error');
  });
});
