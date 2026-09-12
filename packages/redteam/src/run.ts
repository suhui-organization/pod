/**
 * 场景执行与报告：**确定性**判定，与真实网关共用 `decideCall`。
 *
 * 大模型在这里没有任何位置——它只负责"想出攻击"，不负责"判断挡住了没有"。
 * 判定用的是网关那套纯函数，所以同样的策略 + 同样的场景 = 同样的结论，
 * 可以挂进 CI 当回归测试用。
 */
import { decideCall } from '@podsec/gateway';
import type { Decision, Policy, RuleSet, Severity } from '@podsec/policy';
import type { RedteamReport, Scenario, ScenarioResult } from './types.js';

/** 判决的严格程度：allow < approve < deny */
const RANK: Record<Decision, number> = { allow: 0, approve: 1, deny: 2 };

export interface RunOptions {
  policy: Policy;
  rules: RuleSet;
  scenarios: Scenario[];
  now?: Date;
  /** 生成阶段的说明（未生成的场景、被丢弃的外部场景） */
  notes?: string[];
}

export function runScenarios(opts: RunOptions): ScenarioResult[] {
  return opts.scenarios.map((scenario) => {
    const decision = decideCall({
      policy: opts.policy,
      rules: opts.rules,
      // 策略是绑定 agent 的（policy.agent !== ctx.agent 直接 deny），所以用策略自己的 agent
      agent: opts.policy.agent,
      server: scenario.server,
      tool: scenario.tool,
      args: scenario.args,
    });
    const outcome: ScenarioResult['outcome'] =
      RANK[decision.decision] >= RANK[scenario.expect] ? 'blocked' : 'bypassed';
    return {
      scenario,
      outcome,
      actual: decision.decision,
      matched: decision.matched,
      reason: decision.reason,
      // 本该 deny 却放行 = high；本该 approve 却 allow = medium
      severity: outcome === 'bypassed' ? (scenario.expect === 'deny' ? 'high' : 'medium') : 'low',
    };
  });
}

export function buildReport(opts: RunOptions): RedteamReport {
  const results = runScenarios(opts);
  const findings = results
    .filter((r) => r.outcome === 'bypassed')
    .sort((a, b) => RANK[b.actual] - RANK[a.actual] || a.scenario.id.localeCompare(b.scenario.id));
  return {
    generatedAt: (opts.now ?? new Date()).toISOString(),
    agent: opts.policy.agent,
    policyVersion: opts.policy.version,
    total: results.length,
    blocked: results.filter((r) => r.outcome === 'blocked').length,
    bypassed: findings.length,
    results,
    findings,
    notes: opts.notes ?? [],
  };
}

const ICON: Record<Severity, string> = { high: '🔴', medium: '🟠', low: '🟡' };

export function renderRedteamReport(report: RedteamReport): string {
  const lines: string[] = ['# pod redteam — 策略红队报告', ''];
  lines.push(`生成时间：${report.generatedAt}`);
  lines.push(`agent：${report.agent}　策略版本：${report.policyVersion}`);
  lines.push('');
  lines.push('| 场景总数 | 挡住 | 绕过 |');
  lines.push('|---------:|-----:|-----:|');
  lines.push(`| ${report.total} | ${report.blocked} | ${report.bypassed} |`);
  lines.push('');

  lines.push('## 1. 绕过项（需要处理）');
  lines.push('');
  if (report.findings.length === 0) {
    lines.push('✅ 所有场景都被正确处置——没有发现策略被绕过的路径。');
  } else {
    lines.push('| 级别 | 攻击意图 | 期望 | 实际 | 命中规则 | 场景 |');
    lines.push('|------|----------|------|------|----------|------|');
    for (const f of report.findings) {
      lines.push(
        `| ${ICON[f.severity]} ${f.severity} | ${f.scenario.intent} | ${f.scenario.expect} | ${f.actual} | \`${f.matched}\` | \`${f.scenario.id}\` |`,
      );
    }
    lines.push('');
    lines.push('修复建议：优先看"期望 deny 实际 allow"的高危项——它们说明策略里缺了一条明确规则，');
    lines.push('而不是"阈值调松了"。这类修补可以直接变成规则包里的一个新模式。');
  }
  lines.push('');

  lines.push('## 2. 全部场景');
  lines.push('');
  lines.push('| 场景 | 威胁 | 期望 | 实际 | 结果 |');
  lines.push('|------|------|------|------|------|');
  for (const r of report.results) {
    lines.push(
      `| \`${r.scenario.id}\` | ${r.scenario.threat} | ${r.scenario.expect} | ${r.actual} | ${
        r.outcome === 'blocked' ? '✅ 挡住' : '❌ 绕过'
      } |`,
    );
  }
  lines.push('');

  lines.push('## 3. 本报告的边界');
  lines.push('');
  lines.push('- **只说"这 N 个场景被正确处置"，不说"策略是安全的"。** 红队报告的证明力上限就是场景表的覆盖度；');
  lines.push('- 判定走的是与网关同一条纯函数流水线（`decideCall`），所以结论可复现、可进 CI 当回归测试；');
  lines.push('- **运行时状态不在范围内**：熔断（quarantine）、审批人、令牌有效期这些与策略无关；');
  lines.push('- 场景只在策略层"被判"，**没有真的调用任何 MCP server**——所以它不会碰客户的数据（这是刻意的）；');
  lines.push('- 已知边界：`secrets.deny_input_paths` 做的是路径段匹配，**不理解编码**（base64 过的敏感路径不在本报告覆盖内）。');
  lines.push('');
  if (report.notes.length > 0) {
    lines.push('### 本次未覆盖或已丢弃');
    lines.push('');
    for (const n of report.notes) lines.push(`- ${n}`);
    lines.push('');
  }
  return lines.join('\n');
}
