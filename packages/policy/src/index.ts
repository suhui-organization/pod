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

export interface Policy {
  version: string;
  /** 策略绑定的 agent 身份（Asset Registry 中一个 agent 一条策略） */
  agent: string;
  servers?: Record<string, ServerPolicy>;
  /** 未登记 server 的默认决策（默认 deny，fail-closed） */
  defaultDecision?: Decision;
}

export interface EvalContext {
  agent: string;
  server: string;
  tool: string;
}

export interface EvalResult {
  decision: Decision;
  reason: string;
  /** 命中的规则位置，便于审计与调试 */
  matched: 'agent' | 'server' | 'deny' | 'approve' | 'allow' | 'default';
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
