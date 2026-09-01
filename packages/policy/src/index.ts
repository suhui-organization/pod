/**
 * 策略求值器 v0（threat-model.md 的决策核心）。
 *
 * 设计原则（D2）：
 * - 三态决策：deny > approve > allow（拒绝优先，规则冲突时取更严格者）；
 * - fail-closed：未显式授权的工具/未登记的 server 一律拒绝；
 * - 规则为工具名精确匹配或 "*" 通配，v0 不引入 DSL；
 * - 纯函数、无副作用，便于 100% 单测。
 */

export type Decision = 'allow' | 'deny' | 'approve';

export interface ToolRule {
  allow?: string[];
  approve?: string[];
  deny?: string[];
}

export type ServerPolicy = ToolRule;

/**
 * 敏感信息规则（P0，威胁 T2）：
 * - deny_input_paths：参数中的字符串命中这些模式（如 "~/.ssh"、".env"）→ 调用直接拒绝；
 * - deny_output_matching：工具响应的文本命中这些正则 → 网关阻断该响应（在 gateway 层执行）。
 */
export interface SecretRules {
  deny_input_paths?: string[];
  deny_output_matching?: string[];
}

export interface Policy {
  version: string;
  /** 策略绑定的 agent 身份（Asset Registry 中一个 agent 一条策略） */
  agent: string;
  servers?: Record<string, ServerPolicy>;
  /** 未登记 server 的默认决策（默认 deny，fail-closed） */
  defaultDecision?: Decision;
  secrets?: SecretRules;
}

export interface EvalContext {
  agent: string;
  server: string;
  tool: string;
  /** 工具参数（敏感路径检查用；递归收集字符串值） */
  args?: unknown;
}

export interface EvalResult {
  decision: Decision;
  reason: string;
  /** 命中的规则位置，便于审计与调试 */
  matched: 'agent' | 'server' | 'deny' | 'secrets-input' | 'approve' | 'allow' | 'default';
}

/** 递归收集参数中的字符串值（数组/对象嵌套） */
export function collectStrings(value: unknown, out: string[] = []): string[] {
  if (typeof value === 'string') {
    out.push(value);
  } else if (Array.isArray(value)) {
    for (const v of value) collectStrings(v, out);
  } else if (value !== null && typeof value === 'object') {
    for (const v of Object.values(value)) collectStrings(v, out);
  }
  return out;
}

function hitSensitivePath(policy: Policy, args: unknown): string | null {
  const patterns = policy.secrets?.deny_input_paths;
  if (!patterns || patterns.length === 0) return null;
  const strings = collectStrings(args);
  for (const pattern of patterns) {
    for (const str of strings) {
      if (str.includes(pattern)) return pattern;
    }
  }
  return null;
}

function matches(patterns: string[] | undefined, tool: string): boolean {
  if (!patterns) return false;
  return patterns.includes('*') || patterns.includes(tool);
}

export function evaluate(policy: Policy, ctx: EvalContext): EvalResult {
  if (policy.agent !== ctx.agent) {
    return {
      decision: 'deny',
      reason: `policy is bound to agent "${policy.agent}", got "${ctx.agent}"`,
      matched: 'agent',
    };
  }

  const serverPolicy = policy.servers?.[ctx.server];
  if (!serverPolicy) {
    const decision = policy.defaultDecision ?? 'deny';
    return {
      decision,
      reason: `server "${ctx.server}" is not registered (default ${decision})`,
      matched: 'server',
    };
  }

  if (matches(serverPolicy.deny, ctx.tool)) {
    return { decision: 'deny', reason: `tool "${ctx.tool}" is denied on "${ctx.server}"`, matched: 'deny' };
  }

  const sensitive = hitSensitivePath(policy, ctx.args);
  if (sensitive !== null) {
    return {
      decision: 'deny',
      reason: `argument hits sensitive path pattern "${sensitive}" (secrets.deny_input_paths)`,
      matched: 'secrets-input',
    };
  }
  if (matches(serverPolicy.approve, ctx.tool)) {
    return { decision: 'approve', reason: `tool "${ctx.tool}" requires approval on "${ctx.server}"`, matched: 'approve' };
  }
  if (matches(serverPolicy.allow, ctx.tool)) {
    return { decision: 'allow', reason: `tool "${ctx.tool}" is allowed on "${ctx.server}"`, matched: 'allow' };
  }
  return {
    decision: 'deny',
    reason: `tool "${ctx.tool}" is not authorized on "${ctx.server}" (fail-closed)`,
    matched: 'default',
  };
}

// ---------- 策略 lint（P1：误配置防线，T9） ----------

export interface LintIssue {
  severity: 'error' | 'warn' | 'info';
  /** 定位路径，如 servers.filesystem.allow */
  where: string;
  message: string;
}

/** 检查策略中的危险/可疑模式（纯函数，供 pod lint 与 CI 使用） */
export function lintPolicy(policy: Policy): LintIssue[] {
  const issues: LintIssue[] = [];

  if (policy.defaultDecision === 'allow' || policy.defaultDecision === 'approve') {
    issues.push({
      severity: 'warn',
      where: 'defaultDecision',
      message: `defaultDecision="${policy.defaultDecision}" 是 fail-open，未登记 server 将被放行（建议 deny）`,
    });
  }

  const servers = policy.servers ?? {};
  if (Object.keys(servers).length === 0) {
    issues.push({ severity: 'info', where: 'servers', message: '未配置任何 server 规则（空策略）' });
  }

  for (const [server, sp] of Object.entries(servers)) {
    if (sp.deny && sp.deny.length === 0) {
      issues.push({ severity: 'warn', where: `servers.${server}.deny`, message: 'deny 为空数组（无实际拒绝规则）' });
    }
    if (sp.allow && sp.allow.includes('*')) {
      issues.push({
        severity: 'warn',
        where: `servers.${server}.allow`,
        message: `allow 含 "*"（该 server 全部工具放行；建议最小授权）`,
      });
    }
  }

  const secrets = policy.secrets;
  if (!secrets || (!secrets.deny_input_paths?.length && !secrets.deny_output_matching?.length)) {
    issues.push({
      severity: 'info',
      where: 'secrets',
      message: '未配置 secrets 规则（建议加 deny_input_paths 与 deny_output_matching，见 T2）',
    });
  } else {
    for (const pattern of secrets?.deny_output_matching ?? []) {
      try {
        new RegExp(pattern);
      } catch {
        issues.push({
          severity: 'error',
          where: 'secrets.deny_output_matching',
          message: `非法正则: ${pattern}`,
        });
      }
    }
  }

  return issues;
}
