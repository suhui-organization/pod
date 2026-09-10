import type { CapabilityGraph, ToxicPath } from './types.js';
import type { ScoredToxicGroup } from './score.js';
import type { GraphDiffResult } from './graph-diff.js';

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
    `# pod graph（${graph.source}）`,
    '',
    `生成时间：${graph.generated_at}`,
    `agent：${agents} · server：${servers} · tool：${tools}`,
    `配置指纹：${graph.meta.config_fingerprint}`,
  ];
  if (graph.meta.warnings.length > 0) {
    lines.push('', '## 警告');
    for (const warning of graph.meta.warnings) {
      lines.push(`- [${warning.code}] ${warning.message}${warning.where ? `（${warning.where}）` : ''}`);
    }
  }
  return lines.join('\n');
}

export function renderToxicReport(input: ToxicReportInput): string {
  const { graph, paths, total, maxPaths, minConfidence, groups, feedback } = input;
  const lines = ['# pod graph toxic — 毒性路径', ''];
  lines.push(`生成时间：${graph.generated_at}`);
  lines.push(`阈值：min-confidence=${minConfidence} · max-paths=${maxPaths}`);
  lines.push('');
  if (graph.meta.warnings.length > 0) {
    lines.push('## 警告');
    for (const warning of graph.meta.warnings) {
      lines.push(`- [${warning.code}] ${warning.message}${warning.where ? `（${warning.where}）` : ''}`);
    }
    lines.push('');
  }
  if (groups && groups.length > 0) {
    lines.push('## 风险排序（按 score）');
    lines.push('');
    lines.push('| score | 风险 | 规则 | source → sink | 路径数 | 跨 agent | 主要理由 |');
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
    lines.push('## 断链建议');
    lines.push('');
    for (const group of withChainDiff) {
      const diff = group.chain_diff!;
      const verdict = feedback?.[group.id] ? ` 【${feedback[group.id]}】` : '';
      lines.push(`### ${group.id}（score ${group.score}，${group.rule}）${verdict}`);
      if (diff.strategy === 'capability-level' && diff.capability_recommendation) {
        lines.push(`**能力级建议**：${diff.capability_recommendation.reason}`);
        lines.push(`示例改动（前 ${diff.changes.length} 个）：`);
      } else {
        lines.push(
          `收紧 ${diff.strategy === 'tighten-sinks' ? 'sink' : 'source'} 的 ${diff.changes.length} 个工具，覆盖 ${diff.breaks_paths} 条路径：`,
        );
      }
      for (const change of diff.changes) {
        lines.push(`- \`${change.target}\`：${change.from} → ${change.to}`);
      }
      lines.push('');
    }
  }
  if (paths.length === 0) {
    lines.push('未发现毒性路径。');
    return lines.join('\n');
  }
  const high = paths.filter((p) => p.severity === 'high');
  const medium = paths.filter((p) => p.severity === 'medium');
  lines.push(`## 高危（${high.length}）`);
  lines.push('');
  for (const path of high) lines.push(...renderPath(path));
  if (medium.length > 0) {
    lines.push(`## 中危（${medium.length}）`);
    lines.push('');
    for (const path of medium) lines.push(...renderPath(path));
  }
  if (total > paths.length) {
    lines.push(`> 还有 ${total - paths.length} 条路径未显示；用 --max-paths 调整。`);
  }
  return lines.join('\n');
}

export function renderDiffReport(diff: GraphDiffResult): string {
  const lines = [
    '# pod graph diff — 潜在 vs 观测',
    '',
    `潜在工具：${diff.summary.potentialTools} · 观测工具：${diff.summary.observedTools}`,
    '',
    `## 权限过载（潜在 − 实际）：${diff.summary.overPrivileged}`,
    '',
  ];
  if (diff.overPrivileged.length === 0) {
    lines.push('（无）');
  } else {
    lines.push('| server | tool | agents | 能力 |');
    lines.push('|--------|------|--------|------|');
    for (const entry of diff.overPrivileged.slice(0, 100)) {
      lines.push(
        `| ${entry.servers.join(' / ')} | ${entry.tool} | ${entry.agents.join(', ')} | ${entry.capabilities.join(', ') || '—'} |`,
      );
    }
    if (diff.overPrivileged.length > 100) lines.push(`| … | 还有 ${diff.overPrivileged.length - 100} 条 | … | … |`);
  }
  lines.push('', `## 影子能力（实际 − 潜在）：${diff.summary.shadow}`, '');
  if (diff.shadow.length === 0) {
    lines.push('（无）');
  } else {
    lines.push('| server | tool | agents | 能力 | 调用 |');
    lines.push('|--------|------|--------|------|-----:|');
    for (const entry of diff.shadow.slice(0, 100)) {
      lines.push(
        `| ${entry.servers.join(' / ')} | ${entry.tool} | ${entry.agents.join(', ')} | ${entry.capabilities.join(', ') || '—'} | ${entry.calls ?? 0} |`,
      );
    }
    if (diff.shadow.length > 100) lines.push(`| … | 还有 ${diff.shadow.length - 100} 条 | … | … | … |`);
  }
  return lines.join('\n');
}

function renderPath(path: ToxicPath): string[] {
  const lines = [
    `### ${path.id}  ${path.rule}（${path.kind}，置信度 ${path.confidence}）`,
    `  ${path.source.agent}.${path.source.server}.${path.source.tool} [${path.source.capability} ${path.source.confidence}]`,
    `    └─▶ ${path.sink.agent}.${path.sink.server}.${path.sink.tool} [${path.sink.capability} ${path.sink.confidence}]`,
    `  说明：${path.explain}`,
  ];
  if (path.suggested_diff) {
    lines.push(
      `  建议：将 ${path.suggested_diff.target} 从 ${path.suggested_diff.from} 改为 ${path.suggested_diff.to}`,
    );
    lines.push(`  理由：${path.suggested_diff.rationale}`);
  }
  lines.push('');
  return lines;
}
