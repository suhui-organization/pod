/**
 * pod gateway — MCP 双向代理（Phase 0 spike）。
 *
 * 架构（architecture.md 1.1）：
 *   Agent ──MCP──▶ pod gateway ──MCP client──▶ 真实 MCP server
 *   - 对 agent：表现为一个 MCP server（工具列表透传自真实 server）；
 *   - 对真实 server：表现为一个 MCP client；
 *   - 每个 tools/call 必经：策略求值 → 记录审计（v0 仅 allow/deny，
 *     approve 按 fail-closed 阻断，审批流 Phase 1 实现）。
 */
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  CompatibilityCallToolResultSchema,
  ListToolsRequestSchema,
  type CallToolResult,
  type Tool,
} from '@modelcontextprotocol/sdk/types.js';
import { AuditLog, hashValue } from '@podsec/audit';
import { evaluate, type Policy } from '@podsec/policy';

export interface ProxyOptions {
  /** Asset Registry 中的 agent 身份 */
  agent: string;
  /** 对外暴露的 server 名（策略按此名求值） */
  serverName: string;
  policy: Policy;
  audit: AuditLog;
  /** 建立到真实 MCP server 的客户端连接（已连接） */
  connectUpstream: () => Promise<Client>;
}

/**
 * 创建代理 server（未连接 transport，由调用方 connect）。
 * 测试可用 InMemoryTransport；CLI 用 StdioServerTransport。
 */
export function createProxyServer(opts: ProxyOptions): Server {
  const { agent, serverName, policy, audit } = opts;
  let upstream: Client | undefined;

  const ensureUpstream = async (): Promise<Client> => {
    upstream ??= await opts.connectUpstream();
    return upstream;
  };

  const server = new Server(
    { name: `pod-gateway:${serverName}`, version: '0.1.0' },
    { capabilities: { tools: {} } },
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => {
    const client = await ensureUpstream();
    const result = await client.listTools();
    return { tools: result.tools as Tool[] };
  });

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;
    const ctx = { agent, server: serverName, tool: name };
    const verdict = evaluate(policy, ctx);

    const blocked = (decision: 'deny' | 'approve', reason: string): CallToolResult => {
      audit.append({
        ...ctx,
        session: 'cli-v0',
        argsHash: hashValue(args),
        decision,
        outcome: 'blocked',
        reason,
        policyVersion: policy.version,
      });
      return {
        content: [{ type: 'text', text: `pod: blocked (${decision}): ${reason}` }],
        isError: true,
      };
    };

    if (verdict.decision === 'deny') return blocked('deny', verdict.reason);
    if (verdict.decision === 'approve') {
      // v0 fail-closed：审批流未实现，先阻断（Phase 1 接入 Approval Gate）
      return blocked('approve', `approval flow not implemented yet (v0 fail-closed): ${verdict.reason}`);
    }

    const client = await ensureUpstream();
    let result: CallToolResult;
    try {
      // 显式要求兼容格式（{ content, isError }），与 server 侧 handler 的返回类型一致；
      // callTool 声明为 union（content | toolResult 分支），此处按请求的 schema 收窄
      result = (await client.callTool(
        { name, arguments: args ?? {} },
        CompatibilityCallToolResultSchema,
      )) as CallToolResult;
    } catch (err) {
      audit.append({
        ...ctx,
        session: 'cli-v0',
        argsHash: hashValue(args),
        decision: 'allow',
        outcome: 'error',
        reason: err instanceof Error ? err.message : String(err),
        policyVersion: policy.version,
      });
      throw err;
    }
    audit.append({
      ...ctx,
      session: 'cli-v0',
      argsHash: hashValue(args),
      decision: 'allow',
      outcome: result.isError ? 'error' : 'ok',
      outputHash: hashValue(result.content),
      policyVersion: policy.version,
    });
    return result;
  });

  return server;
}

export interface StdioProxyOptions extends Omit<ProxyOptions, 'connectUpstream'> {
  command: string;
  args: string[];
  env?: Record<string, string>;
}

/** spawn 真实 MCP server 子进程并返回已连上游的代理 server（调用方 connect 自己的 transport） */
export async function createStdioProxy(opts: StdioProxyOptions): Promise<Server> {
  const transport = new StdioClientTransport({ command: opts.command, args: opts.args, env: opts.env });
  const client = new Client({ name: 'pod-gateway-upstream', version: '0.1.0' }, { capabilities: {} });
  await client.connect(transport);
  const server = createProxyServer({
    ...opts,
    connectUpstream: async () => client,
  });
  return server;
}
