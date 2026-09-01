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

/** 从工具响应中提取全部文本内容（用于输出侧密钥扫描） */
function extractResponseText(result: CallToolResult): string {
  const content = result.content as Array<{ type?: string; text?: string }>;
  return content
    .filter((c) => c.type === 'text' && typeof c.text === 'string')
    .map((c) => c.text ?? '')
    .join('\n');
}

/**
 * P0（T2）：工具响应命中 secrets.deny_output_matching 正则 → 返回命中的模式。
 * 非法正则跳过（策略来自用户，可能写错；lint 会在 P1 覆盖）。
 */
export function matchSecretOutput(policy: Policy, result: CallToolResult): string | null {
  const rules = policy.secrets?.deny_output_matching;
  if (!rules || rules.length === 0) return null;
  const text = extractResponseText(result);
  if (!text) return null;
  for (const pattern of rules) {
    try {
      const re = new RegExp(pattern);
      if (re.test(text)) return pattern;
    } catch {
      // 非法正则：跳过
    }
  }
  return null;
}

export interface ApprovalRequest {
  /** 全局唯一 id（如 filesystem-1） */
  id: string;
  agent: string;
  server: string;
  tool: string;
  args: unknown;
}

export interface ApprovalDecision {
  approved: boolean;
  approver?: string;
  reason?: string;
}

/**
 * 审批 provider：对需批准的调用返回决策。
 * 实现方负责超时（超时按拒绝处理，fail-closed）与用户交互通道
 * （stdio 被 MCP 占用，CLI 用 ~/.pod/pending/ 文件旁路）。
 */
export type ApprovalProvider = (req: ApprovalRequest) => Promise<ApprovalDecision>;

export interface ProxyOptions {
  /** Asset Registry 中的 agent 身份 */
  agent: string;
  /** 对外暴露的 server 名（策略按此名求值） */
  serverName: string;
  policy: Policy;
  audit: AuditLog;
  /**
   * record-only（pod record）：策略照常求值并写入审计（含 enforced:false），
   * 但绝不阻断——所有调用直接透传。用于 Phase 0 语料采集。
   */
  recordOnly?: boolean;
  /** approve 决策的审批通道；缺省时 approve 按 fail-closed 阻断 */
  approval?: ApprovalProvider;
  /** 建立到真实 MCP server 的客户端连接（已连接） */
  connectUpstream: () => Promise<Client>;
}

/**
 * 创建代理 server（未连接 transport，由调用方 connect）。
 * 测试可用 InMemoryTransport；CLI 用 StdioServerTransport。
 */
export function createProxyServer(opts: ProxyOptions): Server {
  const { agent, serverName, policy, audit, recordOnly, approval } = opts;
  let upstream: Client | undefined;
  let approvalSeq = 0;

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
    const ctx = { agent, server: serverName, tool: name, args };
    const verdict = evaluate(policy, ctx);

    const blocked = (
      decision: 'deny' | 'approve',
      reason: string,
      extra?: { approver?: string },
    ): CallToolResult => {
      audit.append({
        ...ctx,
        session: 'cli-v0',
        argsHash: hashValue(args),
        decision,
        outcome: 'blocked',
        reason,
        approver: extra?.approver,
        policyVersion: policy.version,
      });
      return {
        content: [{ type: 'text', text: `pod: blocked (${decision}): ${reason}` }],
        isError: true,
      };
    };

    const forward = async (decision: 'allow' | 'approve', extra?: { approver?: string; reason?: string }): Promise<CallToolResult> => {
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
          decision,
          outcome: 'error',
          reason: err instanceof Error ? err.message : String(err),
          approver: extra?.approver,
          policyVersion: policy.version,
        });
        throw err;
      }
      const leak = matchSecretOutput(policy, result);
      if (leak !== null) {
        audit.append({
          ...ctx,
          session: 'cli-v0',
          argsHash: hashValue(args),
          decision,
          outcome: 'blocked',
          reason: `secret_leak: output matched pattern ${leak} (secrets.deny_output_matching)`,
          approver: extra?.approver,
          outputHash: hashValue(result.content),
          policyVersion: policy.version,
        });
        return {
          content: [{ type: 'text', text: `pod: blocked — tool output matched secret pattern (${leak})` }],
          isError: true,
        };
      }
      audit.append({
        ...ctx,
        session: 'cli-v0',
        argsHash: hashValue(args),
        decision,
        outcome: result.isError ? 'error' : 'ok',
        reason: extra?.reason,
        approver: extra?.approver,
        outputHash: hashValue(result.content),
        policyVersion: policy.version,
      });
      return result;
    };

    if (recordOnly) {
      // 只录不拦：求值结果作为 decision 标注写入审计，但一律放行
      const client = await ensureUpstream();
      let result: CallToolResult;
      try {
        result = (await client.callTool(
          { name, arguments: args ?? {} },
          CompatibilityCallToolResultSchema,
        )) as CallToolResult;
      } catch (err) {
        audit.append({
          ...ctx,
          session: 'cli-v0',
          argsHash: hashValue(args),
          decision: verdict.decision,
          outcome: 'error',
          reason: `${verdict.reason} (record-only) | ${err instanceof Error ? err.message : String(err)}`,
          enforced: false,
          policyVersion: policy.version,
        });
        throw err;
      }
      audit.append({
        ...ctx,
        session: 'cli-v0',
        argsHash: hashValue(args),
        decision: verdict.decision,
        outcome: result.isError ? 'error' : 'ok',
        reason: `${verdict.reason} (record-only)`,
        outputHash: hashValue(result.content),
        enforced: false,
        policyVersion: policy.version,
      });
      return result;
    }

    if (verdict.decision === 'deny') return blocked('deny', verdict.reason);

    if (verdict.decision === 'approve') {
      if (!approval) {
        return blocked('approve', `approval flow not configured (fail-closed): ${verdict.reason}`);
      }
      const req: ApprovalRequest = { id: `${serverName}-${++approvalSeq}`, agent, server: serverName, tool: name, args };
      let decision: ApprovalDecision;
      try {
        decision = await approval(req);
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        return blocked('approve', `approval provider error: ${msg}`);
      }
      if (!decision.approved) {
        return blocked('approve', decision.reason ?? 'denied by approver', { approver: decision.approver });
      }
      return forward('approve', { approver: decision.approver, reason: decision.reason });
    }

    return forward('allow');
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
