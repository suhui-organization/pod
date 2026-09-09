/**
 * pod policy draft — 从录制语料生成最小权限策略草稿（OPC 缺口 G2：策略不会写）。
 *
 * 闭环：pod record（只录不拦）→ pod policy draft（生成草稿）→ 人工复核 → pod serve（执法）
 *
 * 设计原则：
 * - 只读审计，绝不修改任何现有策略；
 * - 按 (server, tool) 聚合真实调用，工具名语义分三档：
 *     destructive（删除/销毁）→ deny
 *     write/exec（写入/执行/外发）→ approve
 *     其余 → allow
 * - 任何一次敏感路径命中或密钥泄漏 → 该工具强制 deny（观测优先于猜测）；
 * - 人类复核是最后一道闸门：输出 Markdown 报告 + JSON 草稿，不自动启用。
 */
import type { AuditEntry } from '@podsec/audit';
import { lintPolicy, type Policy, type ServerPolicy } from '@podsec/policy';

export type Proposed = 'allow' | 'approve' | 'deny';

export interface ToolStat {
  server: string;
  tool: string;
  calls: number;
  ok: number;
  errors: number;
  blocked: number;
  /** 观测到敏感路径/密钥命中的次数 */
  sensitive: number;
  proposed: Proposed;
  /** 判定依据（给人看的） */
  reason: string;
}

export interface DraftInput {
  server: string;
  entries: AuditEntry[];
}

export interface DraftOptions {
  agent: string;
  version?: string;
  /** 未登记 server 的默认决策，默认 deny（fail-closed） */
  defaultDecision?: Proposed;
}

export interface DraftResult {
  policy: Policy;
  stats: ToolStat[];
  notes: string[];
}

/** 破坏性动词（命中即 deny） */
const DESTRUCTIVE_TOKENS = new Set([
  'delete', 'remove', 'rm', 'rmdir', 'drop', 'destroy', 'purge', 'truncate', 'wipe', 'uninstall', 'kill',
]);

/** 写入/执行/外发动词（命中即 approve，保守优先） */
const WRITE_TOKENS = new Set([
  'write', 'edit', 'create', 'update', 'patch', 'move', 'rename', 'copy', 'mkdir', 'touch',
  'append', 'insert', 'upload', 'push', 'commit', 'deploy', 'exec', 'execute', 'run', 'shell',
  'command', 'install', 'chmod', 'chown', 'set', 'send', 'post', 'publish',
]);

/** 把工具名切成小写 token：snake_case / kebab-case / camelCase / dot.case 都支持 */
export function tokenizeToolName(name: string): string[] {
  return name
    .replace(/([a-z0-9])([A-Z])/g, '$1_$2')
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter(Boolean);
}

/** 工具名语义分档（纯函数，可单测；误判方向永远偏保守） */
export function classifyTool(name: string): { proposed: Proposed; reason: string } {
  const tokens = tokenizeToolName(name);
  const destructive = tokens.find((t) => DESTRUCTIVE_TOKENS.has(t));
  if (destructive) return { proposed: 'deny', reason: `工具名含破坏性动词 "${destructive}"` };
  const write = tokens.find((t) => WRITE_TOKENS.has(t));
  if (write) return { proposed: 'approve', reason: `工具名含写/执行动词 "${write}"` };
  return { proposed: 'allow', reason: '未命中高危动词（只读类）' };
}

function isSensitive(entry: AuditEntry): boolean {
  const reason = entry.reason ?? '';
  return reason.includes('secrets-input') || reason.includes('secret_leak');
}

/**
 * 纯函数：从审计条目生成策略草稿。
 * 不读文件、不写文件，便于 100% 单测。
 */
export function draftPolicyFromEntries(input: DraftInput[], opts: DraftOptions): DraftResult {
  const notes: string[] = [];
  const byServer = new Map<string, Map<string, ToolStat>>();
  let total = 0;

  for (const { server, entries } of input) {
    let tools = byServer.get(server);
    if (!tools) {
      tools = new Map();
      byServer.set(server, tools);
    }
    for (const e of entries) {
      total += 1;
      let stat = tools.get(e.tool);
      if (!stat) {
        const verdict = classifyTool(e.tool);
        stat = {
          server,
          tool: e.tool,
          calls: 0,
          ok: 0,
          errors: 0,
          blocked: 0,
          sensitive: 0,
          proposed: verdict.proposed,
          reason: verdict.reason,
        };
        tools.set(e.tool, stat);
      }
      stat.calls += 1;
      if (e.outcome === 'ok') stat.ok += 1;
      else if (e.outcome === 'error') stat.errors += 1;
      else if (e.outcome === 'blocked') stat.blocked += 1;
      if (isSensitive(e)) {
        stat.sensitive += 1;
        // 观测到的敏感命中永远覆盖工具名猜测：强制 deny
        stat.proposed = 'deny';
        stat.reason = '观测到敏感路径/密钥命中（强制 deny）';
      }
    }
  }

  if (total === 0) notes.push('审计目录为空或没有匹配记录，无法生成草稿');

  const servers: Record<string, ServerPolicy> = {};
  const stats: ToolStat[] = [];
  for (const [server, tools] of [...byServer.entries()].sort(([a], [b]) => a.localeCompare(b))) {
    const list = [...tools.values()].sort((a, b) => b.calls - a.calls || a.tool.localeCompare(b.tool));
    stats.push(...list);
    const sp: ServerPolicy = {};
    const allow = list.filter((s) => s.proposed === 'allow').map((s) => s.tool);
    const approve = list.filter((s) => s.proposed === 'approve').map((s) => s.tool);
    const deny = list.filter((s) => s.proposed === 'deny').map((s) => s.tool);
    if (allow.length > 0) sp.allow = allow;
    if (approve.length > 0) sp.approve = approve;
    if (deny.length > 0) sp.deny = deny;
    servers[server] = sp;
  }

  const sensitiveTools = stats.filter((s) => s.sensitive > 0);
  if (sensitiveTools.length > 0) {
    notes.push(
      `以下工具观测到敏感命中，已强制 deny：${sensitiveTools.map((s) => `${s.server}.${s.tool}`).join('、')}`,
    );
  }

  const policy: Policy = {
    version: opts.version ?? '0.1.0',
    agent: opts.agent,
    defaultDecision: opts.defaultDecision ?? 'deny',
    servers,
    secrets: {
      deny_input_paths: ['.ssh', '.aws', '.env', 'credentials', 'id_rsa', 'id_ed25519', 'known_hosts'],
      deny_output_matching: [
        'ghp_[A-Za-z0-9]{36}',
        'github_pat_[A-Za-z0-9_]{22,}',
        'sk-[A-Za-z0-9]{20,}',
        'sk-ant-[A-Za-z0-9-]{20,}',
        'AKIA[0-9A-Z]{16}',
        'xox[baprs]-[A-Za-z0-9-]{10,}',
        'AIza[0-9A-Za-z_-]{35}',
      ],
      entropy: { enabled: true, min_length: 24, threshold: 4.5, block: true },
    },
  };

  notes.push(`草稿基于 ${total} 条录制记录；启用前请人工复核并运行 pod lint`);
  return { policy, stats, notes };
}

/** 人类可读的草稿报告 */
export function renderDraftReport(result: DraftResult): string {
  const lines: string[] = ['# pod policy draft — 从录制语料生成的最小权限草稿', ''];
  lines.push(`生成时间：${new Date().toISOString()}`);
  lines.push(`agent：${result.policy.agent}　未登记 server 默认：${result.policy.defaultDecision}`);
  lines.push('');
  if (result.stats.length === 0) {
    lines.push('（没有可用的录制记录）');
  } else {
    lines.push('| server | tool | 调用 | ok | err | blocked | 敏感 | 建议 | 依据 |');
    lines.push('|--------|------|-----:|----:|----:|--------:|-----:|------|------|');
    for (const s of result.stats) {
      lines.push(
        `| ${s.server} | ${s.tool} | ${s.calls} | ${s.ok} | ${s.errors} | ${s.blocked} | ${s.sensitive} | ${s.proposed} | ${s.reason} |`,
      );
    }
  }
  lines.push('');
  lines.push('## 复核要点');
  lines.push('');
  lines.push('- `allow` 只代表"录制期间只读/未命中高危动词"，不代表绝对安全；');
  lines.push('- `approve` 是写/执行类，保留人工闸门；`deny` 是破坏性动作或观测到敏感命中；');
  lines.push('- 未在语料中出现的工具不会进策略，启用后按 `defaultDecision` 处理（fail-closed）。');
  lines.push('');
  for (const n of result.notes) lines.push(`> ${n}`);
  lines.push('');
  lines.push('**下一步**：复核本报告 → `pod lint --policy <draft>` → `pod serve --policy <draft>`');
  return lines.join('\n');
}

export interface DraftSummary {
  policy: Policy;
  report: string;
  issues: ReturnType<typeof lintPolicy>;
}

/** 汇总入口：生成策略 + 报告 + lint 结果（不落盘，落盘由 CLI 负责） */
export function draftPolicy(input: DraftInput[], opts: DraftOptions): DraftSummary {
  const result = draftPolicyFromEntries(input, opts);
  return {
    policy: result.policy,
    report: renderDraftReport(result),
    issues: lintPolicy(result.policy),
  };
}
