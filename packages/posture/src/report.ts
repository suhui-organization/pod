import type { PostureResult } from './types.js';

const ICON: Record<string, string> = { high: '🔴', medium: '🟠', low: '🟡' };

export function renderPostureReport(result: PostureResult): string {
  const lines: string[] = ['# pod posture — 控制平面姿态', ''];
  lines.push(`生成时间：${result.generatedAt}`);
  lines.push('');
  if (result.baselineMissing) {
    lines.push('> ⚠️ 还没有基线：本次只做静态判定，漂移类检查（配置/记忆/钩子变更）未生效。');
    lines.push('> 先跑 `pod posture freeze` 记录当前姿态。');
    lines.push('');
  }
  const counts = { high: 0, medium: 0, low: 0 };
  for (const f of result.findings) counts[f.severity]++;
  lines.push(`汇总：🔴 ${counts.high} · 🟠 ${counts.medium} · 🟡 ${counts.low}`);
  lines.push('');

  if (result.findings.length === 0) {
    lines.push('✅ 未发现问题。');
  } else {
    for (const f of result.findings) {
      lines.push(`- ${ICON[f.severity] ?? '•'} **[${f.severity.toUpperCase()}]** \`${f.category}\` ${f.message}`);
      lines.push(`  - 位置：${f.subject}`);
      if (f.evidence?.length) lines.push(`  - 证据：${f.evidence.join(' | ')}`);
    }
  }
  lines.push('');
  lines.push('## 采集到的事实');
  lines.push('');
  lines.push(`- 生命周期钩子：${result.facts.hooks.length} 条`);
  lines.push(`- 冻结项配置：${result.facts.configs.filter((c) => c.exists).length} 个存在`);
  lines.push(`- 记忆文件：${result.facts.memory.filter((m) => m.exists).length} 个存在`);
  lines.push(`- MCP server：${result.facts.packages.length} 个`);
  lines.push(`- Agent 身份：${result.facts.identities.filter((i) => i.hasIdentity).length}/${result.facts.identities.length} 已建立`);
  lines.push(`- 委托链：${result.facts.delegations.length} 条`);
  lines.push(
    `- 审计链：${result.facts.audits.length} 条` +
      `${result.facts.audits.some((a) => !a.valid) ? `（${result.facts.audits.filter((a) => !a.valid).length} 条断裂）` : ''}`,
  );
  lines.push('');
  lines.push('---');
  lines.push('判定规则来自用户规则文件（默认 ~/.pod/rules.json），改规则即改判定。');
  lines.push('');
  return lines.join('\n');
}
