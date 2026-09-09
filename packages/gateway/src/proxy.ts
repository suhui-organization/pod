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
import { serveHttp, type HttpServeResult } from './http-server.js';
import {
  CallToolRequestSchema,
  CompatibilityCallToolResultSchema,
  ListToolsRequestSchema,
  type CallToolResult,
  type Tool,
} from '@modelcontextprotocol/sdk/types.js';
import { AuditLog, hashValue } from '@podsec/audit';
import { checkServerSource, evaluate, findHighEntropySecrets, type EntropyFinding, type Policy } from '@podsec/policy';

/** 从工具响应中提取全部文本内容（用于输出侧密钥扫描） */
function extractResponseText(result: CallToolResult): string {
  const content = result.content as Array<{ type?: string; text?: string }>;
  return content
    .filter((c) => c.type === 'text' && typeof c.text === 'string')
    .map((c) => c.text ?? '')
    .join('\n');
}

/** 轻量注入信号模式（P1，T1）：工具响应含"忽略之前指令"类文本时标记审计（不阻断）。 */
const INJECTION_PATTERNS: RegExp[] = [
  /ignore (all )?(previous|prior|above|earlier) (instructions|prompts|messages|text)/i,
  /disregard (all )?(previous|prior|above) (instructions|prompts)/i,
  /you are now (an? )?(autonomous|unrestricted|jailbroken)/i,
];

/** 检测注入信号；命中返回 true（审计标记用，不阻断） */
export function matchInjectionSignal(result: CallToolResult): boolean {
  const text = extractResponseText(result);
  if (!text) return false;
  return INJECTION_PATTERNS.some((re) => re.test(text));
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

/**
 * P2（T2）：输出侧高熵检测，兜底正则覆盖不到的未知格式密钥。
 * 返回第一个候选（已掩码）；block=false 时由调用方降级为仅审计。
 */
export function matchEntropyOutput(policy: Policy, result: CallToolResult): EntropyFinding | null {
  const rules = policy.secrets?.entropy;
  if (!rules?.enabled) return null;
  const text = extractResponseText(result);
  if (!text) return null;
  return findHighEntropySecrets(text, rules)[0] ?? null;
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
  /**
   * 会话内记忆：同一 (server, tool) 批准过一次后，本进程后续调用免重复审批。
   * 默认关（安全优先）；开启后仍逐条写审计，reason 标记 session-remembered。
   */
  rememberApprovals?: boolean;
  /**
   * 转发前钩子（P2 快照）：approve/allow 决策在真正调用上游前触发，
   * 返回 snapshotId 则写入审计（可用 pod rollback --id 恢复）。
   * 钩子抛错 = fail-closed 阻断（用户已显式开启快照，不能悄悄失去回滚点）。
   */
  onBeforeForward?: (ctx: {
    agent: string;
    server: string;
    tool: string;
    args: unknown;
    decision: 'allow' | 'approve';
  }) => Promise<{ snapshotId?: string } | void>;
  /** 建立到真实 MCP server 的客户端连接（已连接） */
  connectUpstream: () => Promise<Client>;
}

/** 进程级审批序号：HTTP 模式每会话新建 proxy server，不能放在实例内（否则 id 跨会话碰撞） */
let approvalSeq = 0;

/**
 * 创建代理 server（未连接 transport，由调用方 connect）。
 * 测试可用 InMemoryTransport；CLI 用 StdioServerTransport。
 */
export function createProxyServer(opts: ProxyOptions): Server {
  const { agent, serverName, policy, audit, recordOnly, approval, rememberApprovals } = opts;
  let upstream: Client | undefined;
  const remembered = new Map<string, string | undefined>();

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
      let snapshotId: string | undefined;
      if (opts.onBeforeForward) {
        try {
          const r = await opts.onBeforeForward({ agent, server: serverName, tool: name, args, decision });
          snapshotId = r?.snapshotId;
        } catch (err) {
          const msg = err instanceof Error ? err.message : String(err);
          audit.append({
            ...ctx,
            session: 'cli-v0',
            argsHash: hashValue(args),
            decision,
            outcome: 'blocked',
            reason: `snapshot_failed: ${msg}`,
            approver: extra?.approver,
            policyVersion: policy.version,
          });
          return {
            content: [{ type: 'text', text: `pod: blocked — snapshot failed: ${msg}` }],
            isError: true,
          };
        }
      }
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
          snapshot: snapshotId,
          policyVersion: policy.version,
        });
        throw err;
      }
      const injection = matchInjectionSignal(result);
      if (injection) {
        audit.append({
          ...ctx,
          session: 'cli-v0',
          argsHash: hashValue(args),
          decision,
          outcome: 'ok',
          reason: 'injection_suspect: output contains prompt-override language (T1)',
          approver: extra?.approver,
          snapshot: snapshotId,
          outputHash: hashValue(result.content),
          policyVersion: policy.version,
        });
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
          snapshot: snapshotId,
          outputHash: hashValue(result.content),
          policyVersion: policy.version,
        });
        return {
          content: [{ type: 'text', text: `pod: blocked — tool output matched secret pattern (${leak})` }],
          isError: true,
        };
      }
      const entropyHit = matchEntropyOutput(policy, result);
      if (entropyHit && policy.secrets?.entropy?.block !== false) {
        audit.append({
          ...ctx,
          session: 'cli-v0',
          argsHash: hashValue(args),
          decision,
          outcome: 'blocked',
          reason:
            `secret_entropy: output looks like a secret ` +
            `(entropy=${entropyHit.entropy}, len=${entropyHit.length}, sample=${entropyHit.sample})`,
          approver: extra?.approver,
          snapshot: snapshotId,
          outputHash: hashValue(result.content),
          policyVersion: policy.version,
        });
        return {
          content: [{ type: 'text', text: `pod: blocked — tool output looks like a secret (entropy ${entropyHit.entropy})` }],
          isError: true,
        };
      }
      if (entropyHit) {
        audit.append({
          ...ctx,
          session: 'cli-v0',
          argsHash: hashValue(args),
          decision,
          outcome: 'ok',
          reason:
            `secret_entropy_suspect: output looks like a secret ` +
            `(entropy=${entropyHit.entropy}, len=${entropyHit.length}, sample=${entropyHit.sample})`,
          approver: extra?.approver,
          snapshot: snapshotId,
          outputHash: hashValue(result.content),
          policyVersion: policy.version,
        });
      }
      audit.append({
        ...ctx,
        session: 'cli-v0',
        argsHash: hashValue(args),
        decision,
        outcome: result.isError ? 'error' : 'ok',
        reason: extra?.reason,
        approver: extra?.approver,
        snapshot: snapshotId,
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
      const key = `${serverName}:${name}`;
      if (rememberApprovals && remembered.has(key)) {
        return forward('approve', {
          approver: remembered.get(key),
          reason: 'session-remembered approval',
        });
      }
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
      if (rememberApprovals) remembered.set(key, decision.approver);
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
  // T4：来源白名单校验——策略声明了 source 且不匹配时拒绝启动（fail-closed）
  const sourceCheck = checkServerSource(opts.policy.servers?.[opts.serverName]?.source, opts.command, opts.args);
  if (sourceCheck !== null) {
    throw new Error(`server "${opts.serverName}" 未通过来源白名单校验（T4）：${sourceCheck}`);
  }
  const transport = new StdioClientTransport({ command: opts.command, args: opts.args, env: opts.env });
  const client = new Client({ name: 'pod-gateway-upstream', version: '0.1.0' }, { capabilities: {} });
  await client.connect(transport);
  const server = createProxyServer({
    ...opts,
    connectUpstream: async () => client,
  });
  return server;
}

export interface HttpProxyOptions extends Omit<ProxyOptions, 'connectUpstream'> {
  command: string;
  args: string[];
  env?: Record<string, string>;
  port: number;
  host?: string;
  /** P2：HTTP 身份令牌（设置后客户端必须带 Authorization: Bearer <token>） */
  authToken?: string;
  log?: (msg: string) => void;
}

/** spawn 真实 MCP server 并暴露为常驻 HTTP 网关（http://host:port/mcp） */
export async function createHttpProxy(opts: HttpProxyOptions): Promise<HttpServeResult> {
  // T4：来源白名单校验（与 createStdioProxy 一致）
  const sourceCheck = checkServerSource(opts.policy.servers?.[opts.serverName]?.source, opts.command, opts.args);
  if (sourceCheck !== null) {
    throw new Error(`server "${opts.serverName}" 未通过来源白名单校验（T4）：${sourceCheck}`);
  }
  let upstream: Client | undefined;
  const getUpstream = async (): Promise<Client> => {
    if (!upstream) {
      const transport = new StdioClientTransport({ command: opts.command, args: opts.args, env: opts.env });
      upstream = new Client({ name: 'pod-gateway-upstream', version: '0.1.0' }, { capabilities: {} });
      await upstream.connect(transport);
    }
    return upstream;
  };
  // stateless 模式：每请求新建 proxy server，共享 upstream 连接
  return serveHttp({
    port: opts.port,
    host: opts.host,
    authToken: opts.authToken,
    log: opts.log,
    createServer: () =>
      createProxyServer({
        ...opts,
        connectUpstream: getUpstream,
      }),
  });
}
