import type { PostureResult } from './types.js';
import { t } from '@podsec/i18n';

const ICON: Record<string, string> = { high: '🔴', medium: '🟠', low: '🟡' };

export function renderPostureReport(result: PostureResult): string {
  const lines: string[] = [t('# pod posture — 控制平面姿态'), ''];
  lines.push(t('生成时间：{ts}', { ts: result.generatedAt }));
  lines.push('');
  if (result.baselineMissing) {
    lines.push(t('> ⚠️ 还没有基线：本次只做静态判定，漂移类检查（配置/记忆/钩子变更）未生效。'));
    lines.push(t('> 先跑 `pod posture freeze` 记录当前姿态。'));
    lines.push('');
  }
  const counts = { high: 0, medium: 0, low: 0 };
  for (const f of result.findings) counts[f.severity]++;
  lines.push(t('汇总：🔴 {high} · 🟠 {medium} · 🟡 {low}', { high: counts.high, medium: counts.medium, low: counts.low }));
  lines.push('');

  if (result.findings.length === 0) {
    lines.push(t('✅ 未发现问题。'));
  } else {
    for (const f of result.findings) {
      lines.push(`- ${ICON[f.severity] ?? '•'} **[${f.severity.toUpperCase()}]** \`${f.category}\` ${f.message}`);
      lines.push(t('  - 位置：{subject}', { subject: f.subject }));
      if (f.evidence?.length) lines.push(t('  - 证据：{evidence}', { evidence: f.evidence.join(' | ') }));
    }
  }
  lines.push('');
  lines.push(t('## 采集到的事实'));
  lines.push('');
  lines.push(t('- 生命周期钩子：{n} 条', { n: result.facts.hooks.length }));
  lines.push(t('- 冻结项配置：{n} 个存在', { n: result.facts.configs.filter((c) => c.exists).length }));
  lines.push(t('- 记忆文件：{n} 个存在', { n: result.facts.memory.filter((m) => m.exists).length }));
  lines.push(t('- MCP server：{n} 个', { n: result.facts.packages.length }));
  lines.push(
    t('- Agent 身份：{built}/{total} 已建立', {
      built: result.facts.identities.filter((i) => i.hasIdentity).length,
      total: result.facts.identities.length,
    }),
  );
  lines.push(t('- 委托链：{n} 条', { n: result.facts.delegations.length }));
  const brokenChains = result.facts.audits.filter((a) => !a.valid).length;
  lines.push(
    brokenChains > 0
      ? t('- 审计链：{n} 条（{broken} 条断裂）', { n: result.facts.audits.length, broken: brokenChains })
      : t('- 审计链：{n} 条', { n: result.facts.audits.length }),
  );
  lines.push('');
  lines.push('---');
  lines.push(t('判定规则来自用户规则文件（默认 ~/.pod/rules.json），改规则即改判定。'));
  lines.push('');
  return lines.join('\n');
}
