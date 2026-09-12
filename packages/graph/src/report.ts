import type { CapabilityGraph, ToxicPath } from './types.js';
import type { ScoredToxicGroup } from './score.js';
import type { GraphDiffResult } from './graph-diff.js';
import { t } from '@podsec/i18n';

export interface ToxicReportInput {
  graph: CapabilityGraph;
  paths: ToxicPath[];
  total: number;
  maxPaths: number;
  minConfidence: number;
  groups?: ScoredToxicGroup[];
  feedback?: Record<string, 'confirmed' | 'false-positive'>;
}

export function renderGraphSummary(graph: CapabilityGraph): string {
  const agents = graph.nodes.filter((n) => n.type === 'agent').length;
  const servers = graph.nodes.filter((n) => n.type === 'server').length;
  const tools = graph.nodes.filter((n) => n.type === 'tool').length;
  const lines = [
    t('# pod graph（{source}）', { source: graph.source }),
    '',
    t('生成时间：{ts}', { ts: graph.generated_at }),
    t('agent：{agents} · server：{servers} · tool：{tools}', { agents, servers, tools }),
    t('配置指纹：{fp}', { fp: graph.meta.config_fingerprint }),
  ];
  if (graph.meta.warnings.length > 0) {
    lines.push('', t('## 警告'));
    for (const warning of graph.meta.warnings) {
      lines.push(
        `- [${warning.code}] ${warning.message}${warning.where ? t('（{where}）', { where: warning.where }) : ''}`,
      );
    }
  }
  return lines.join('\n');
}

export function renderToxicReport(input: ToxicReportInput): string {
  const { graph, paths, total, maxPaths, minConfidence, groups, feedback } = input;
  const lines = [t('# pod graph toxic — 毒性路径'), ''];
  lines.push(t('生成时间：{ts}', { ts: graph.generated_at }));
  lines.push(t('阈值：min-confidence={min} · max-paths={max}', { min: minConfidence, max: maxPaths }));
  lines.push('');
  if (graph.meta.warnings.length > 0) {
    lines.push(t('## 警告'));
    for (const warning of graph.meta.warnings) {
      lines.push(
        `- [${warning.code}] ${warning.message}${warning.where ? t('（{where}）', { where: warning.where }) : ''}`,
      );
    }
    lines.push('');
  }
  if (groups && groups.length > 0) {
    lines.push(t('## 风险排序（按 score）'));
    lines.push('');
    lines.push(t('| score | 风险 | 规则 | source → sink | 路径数 | 跨 agent | 主要理由 |'));
    lines.push('|------:|------|------|---------------|-------:|---------:|----------|');
    for (const group of groups) {
      lines.push(
        `| **${group.score}** | ${group.risk} | ${group.rule} | ${group.sourceCapability} → ${group.sinkCapability} | ${group.count} | ${group.crossAgent} | ` +
          `${group.score_reasons.slice(0, 3).join('；')} |`,
      );
    }
    lines.push('');
  }
  const withChainDiff = groups?.filter((group) => group.chain_diff) ?? [];
  if (withChainDiff.length > 0) {
    lines.push(t('## 断链建议'));
    lines.push('');
    for (const group of withChainDiff) {
      const diff = group.chain_diff!;
      const verdict = feedback?.[group.id] ? ` 【${feedback[group.id]}】` : '';
      lines.push(
        t('### {id}（score {score}，{rule}）{verdict}', {
          id: group.id,
          score: group.score,
          rule: group.rule,
          verdict,
        }),
      );
      if (diff.strategy === 'capability-level' && diff.capability_recommendation) {
        lines.push(t('**能力级建议**：{reason}', { reason: diff.capability_recommendation.reason }));
        lines.push(t('示例改动（前 {n} 个）：', { n: diff.changes.length }));
      } else {
        lines.push(
          t('收紧 {side} 的 {n} 个工具，覆盖 {paths} 条路径：', {
            side: diff.strategy === 'tighten-sinks' ? 'sink' : 'source',
            n: diff.changes.length,
            paths: diff.breaks_paths,
          }),
        );
      }
      for (const change of diff.changes) {
        lines.push(`- \`${change.target}\`：${change.from} → ${change.to}`);
      }
      lines.push('');
    }
  }
  if (paths.length === 0) {
    lines.push(t('未发现毒性路径。'));
    return lines.join('\n');
  }
  const high = paths.filter((p) => p.severity === 'high');
  const medium = paths.filter((p) => p.severity === 'medium');
  lines.push(t('## 高危（{n}）', { n: high.length }));
  lines.push('');
  for (const path of high) lines.push(...renderPath(path));
  if (medium.length > 0) {
    lines.push(t('## 中危（{n}）', { n: medium.length }));
    lines.push('');
    for (const path of medium) lines.push(...renderPath(path));
  }
  if (total > paths.length) {
    lines.push(t('> 还有 {n} 条路径未显示；用 --max-paths 调整。', { n: total - paths.length }));
  }
  return lines.join('\n');
}

export function renderDiffReport(diff: GraphDiffResult): string {
  const lines = [
    t('# pod graph diff — 潜在 vs 观测'),
    '',
    t('潜在工具：{potential} · 观测工具：{observed}', {
      potential: diff.summary.potentialTools,
      observed: diff.summary.observedTools,
    }),
    '',
    t('## 权限过载（潜在 − 实际）：{n}', { n: diff.summary.overPrivileged }),
    '',
  ];
  if (diff.overPrivileged.length === 0) {
    lines.push(t('（无）'));
  } else {
    lines.push(t('| server | tool | agents | 能力 |'));
    lines.push('|--------|------|--------|------|');
    for (const entry of diff.overPrivileged.slice(0, 100)) {
      lines.push(
        `| ${entry.servers.join(' / ')} | ${entry.tool} | ${entry.agents.join(', ')} | ${entry.capabilities.join(', ') || '—'} |`,
      );
    }
    if (diff.overPrivileged.length > 100) {
      lines.push(t('| … | 还有 {n} 条 | … | … |', { n: diff.overPrivileged.length - 100 }));
    }
  }
  lines.push('', t('## 影子能力（实际 − 潜在）：{n}', { n: diff.summary.shadow }), '');
  if (diff.shadow.length === 0) {
    lines.push(t('（无）'));
  } else {
    lines.push(t('| server | tool | agents | 能力 | 调用 |'));
    lines.push('|--------|------|--------|------|-----:|');
    for (const entry of diff.shadow.slice(0, 100)) {
      lines.push(
        `| ${entry.servers.join(' / ')} | ${entry.tool} | ${entry.agents.join(', ')} | ${entry.capabilities.join(', ') || '—'} | ${entry.calls ?? 0} |`,
      );
    }
    if (diff.shadow.length > 100) {
      lines.push(t('| … | 还有 {n} 条 | … | … | … |', { n: diff.shadow.length - 100 }));
    }
  }
  return lines.join('\n');
}

function renderPath(path: ToxicPath): string[] {
  const lines = [
    t('### {id}  {rule}（{kind}，置信度 {confidence}）', {
      id: path.id,
      rule: path.rule,
      kind: path.kind,
      confidence: path.confidence,
    }),
    `  ${path.source.agent}.${path.source.server}.${path.source.tool} [${path.source.capability} ${path.source.confidence}]`,
    `    └─▶ ${path.sink.agent}.${path.sink.server}.${path.sink.tool} [${path.sink.capability} ${path.sink.confidence}]`,
    t('  说明：{explain}', { explain: path.explain }),
  ];
  if (path.suggested_diff) {
    lines.push(
      t('  建议：将 {target} 从 {from} 改为 {to}', {
        target: path.suggested_diff.target,
        from: path.suggested_diff.from,
        to: path.suggested_diff.to,
      }),
    );
    lines.push(t('  理由：{rationale}', { rationale: path.suggested_diff.rationale }));
  }
  lines.push('');
  return lines;
}
