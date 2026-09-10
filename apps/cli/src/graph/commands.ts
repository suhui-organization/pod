import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import {
  capabilityMapFromGraph,
  findToxicPaths,
  renderGraphSummary,
  renderToxicReport,
  scoreToxicGroups,
  suggestChainDiff,
  suggestDiff,
  type ToxicPath,
} from '@podsec/graph';
import type { Policy } from '@podsec/policy';
import { buildStaticGraph } from './static.js';
import { graphDir, readChains, readGraphFile, readPaths, writeFileAtomic, writeGraph, writePaths } from './io.js';

export interface GraphBuildOptions {
  home: string;
  config?: string;
  noExec: boolean;
  timeoutMs: number;
  out: string;
  policyPath?: string;
  json: boolean;
}

export async function cmdGraphBuild(opts: GraphBuildOptions): Promise<number> {
  let policy: Policy | null = null;
  if (opts.policyPath) {
    try {
      policy = JSON.parse(readFileSync(opts.policyPath, 'utf8')) as Policy;
    } catch (err) {
      process.stderr.write(`policy unreadable: ${err instanceof Error ? err.message : String(err)}\n`);
      return 2;
    }
  }
  const { graph } = await buildStaticGraph({
    home: opts.home,
    config: opts.config,
    noExec: opts.noExec,
    timeoutMs: opts.timeoutMs,
    cacheDir: join(graphDir(opts.home), 'schema-cache'),
    policy,
  });
  writeGraph(opts.out, graph);
  if (opts.json) {
    process.stdout.write(JSON.stringify({ out: opts.out, graph }, null, 2) + '\n');
  } else {
    process.stdout.write(renderGraphSummary(graph) + '\n');
    process.stdout.write(`\n已写入：${opts.out}\n`);
  }
  return 0;
}

export interface GraphToxicOptions {
  graphPath: string;
  outDir: string;
  crossAgent: boolean;
  minConfidence: number;
  maxPaths: number;
  baselinePath?: string;
  json: boolean;
}

export function cmdGraphToxic(opts: GraphToxicOptions): number {
  if (!existsSync(opts.graphPath)) {
    process.stderr.write(`graph not found: ${opts.graphPath}\n`);
    return 2;
  }
  let graph;
  try {
    graph = readGraphFile(opts.graphPath);
  } catch (err) {
    process.stderr.write(`graph unreadable: ${err instanceof Error ? err.message : String(err)}\n`);
    return 2;
  }
  const ageMs = Date.now() - new Date(graph.generated_at).getTime();
  if (Number.isFinite(ageMs) && ageMs > 7 * 24 * 60 * 60 * 1000) {
    graph.meta.warnings.push({
      code: 'stale_graph',
      message: `graph 生成于 ${graph.generated_at}，超过 7 天，结论仅供参考`,
    });
  }
  const { paths, total, groups } = findToxicPaths(graph, {
    crossAgent: opts.crossAgent,
    minConfidence: opts.minConfidence,
    maxPaths: opts.maxPaths,
  });
  let policy: Policy | null = null;
  if (opts.baselinePath) {
    try {
      policy = JSON.parse(readFileSync(opts.baselinePath, 'utf8')) as Policy;
    } catch (err) {
      process.stderr.write(`baseline unreadable: ${err instanceof Error ? err.message : String(err)}\n`);
      return 2;
    }
  }
  const scoredGroups = scoreToxicGroups(groups).map((group) => ({
    ...group,
    chain_diff: policy ? suggestChainDiff(group, policy) : null,
  }));
  const withDiff: ToxicPath[] = paths.map((path) => ({
    ...path,
    suggested_diff: policy ? suggestDiff(path, policy) : null,
  }));
  writePaths(join(opts.outDir, 'paths.json'), withDiff);
  writeFileAtomic(join(opts.outDir, 'chains.json'), JSON.stringify(scoredGroups, null, 2) + '\n');
  writeFileAtomic(
    join(opts.outDir, 'report.md'),
    renderToxicReport({
      graph,
      paths: withDiff,
      total,
      maxPaths: opts.maxPaths,
      minConfidence: opts.minConfidence,
      groups: scoredGroups,
    }) + '\n',
  );
  if (policy) {
    const diff = withDiff
      .map((p) => p.suggested_diff)
      .filter((d): d is NonNullable<typeof d> => d !== null);
    const unique = [...new Map(diff.map((d) => [`${d.target}|${d.from}|${d.to}`, d])).values()];
    writeFileAtomic(join(opts.outDir, 'policy-diff.json'), JSON.stringify(unique, null, 2) + '\n');
  }
  const capabilityPatches = [
    ...new Map(
      scoredGroups
        .filter((group) => group.chain_diff?.capability_recommendation)
        .map((group) => {
          const recommendation = group.chain_diff!.capability_recommendation!;
          return [recommendation.capability, recommendation.policy_patch] as const;
        }),
    ).values(),
  ];
  if (capabilityPatches.length > 0) {
    writeFileAtomic(join(opts.outDir, 'capability-diff.json'), JSON.stringify(capabilityPatches, null, 2) + '\n');
  }
  if (opts.json) {
    process.stdout.write(
      JSON.stringify({ total, groups: scoredGroups, paths: withDiff, warnings: graph.meta.warnings }, null, 2) + '\n',
    );
  } else {
    process.stdout.write(
      renderToxicReport({
        graph,
        paths: withDiff,
        total,
        maxPaths: opts.maxPaths,
        minConfidence: opts.minConfidence,
        groups: scoredGroups,
      }) + '\n',
    );
  }
  return withDiff.some((p) => p.severity === 'high') ? 1 : 0;
}

export interface GraphApplyOptions {
  graphPath: string;
  policyPath: string;
  out: string;
  json: boolean;
}

/** 把能力图里的 tool→capability 映射写入策略的 capabilityMap */
export function cmdGraphApply(opts: GraphApplyOptions): number {
  if (!existsSync(opts.graphPath)) {
    process.stderr.write(`graph not found: ${opts.graphPath}\n`);
    return 2;
  }
  let graph;
  try {
    graph = readGraphFile(opts.graphPath);
  } catch (err) {
    process.stderr.write(`graph unreadable: ${err instanceof Error ? err.message : String(err)}\n`);
    return 2;
  }
  let policy: Policy;
  try {
    policy = JSON.parse(readFileSync(opts.policyPath, 'utf8')) as Policy;
  } catch (err) {
    process.stderr.write(`policy unreadable: ${err instanceof Error ? err.message : String(err)}\n`);
    return 2;
  }
  const map = capabilityMapFromGraph(graph);
  const merged: Policy = { ...policy, capabilityMap: { ...(policy.capabilityMap ?? {}), ...map } };
  writeFileAtomic(opts.out, JSON.stringify(merged, null, 2) + '\n');
  if (opts.json) {
    process.stdout.write(JSON.stringify({ out: opts.out, tools: Object.keys(map).length }, null, 2) + '\n');
  } else {
    process.stdout.write(`已写入 ${opts.out}：capabilityMap 覆盖 ${Object.keys(map).length} 个工具\n`);
  }
  return 0;
}

export interface GraphExplainOptions {
  pathsPath: string;
  id: string;
  json: boolean;
}

export function cmdGraphExplain(opts: GraphExplainOptions): number {
  if (!existsSync(opts.pathsPath)) {
    process.stderr.write(`paths not found: ${opts.pathsPath}\n`);
    return 2;
  }
  if (opts.id.startsWith('chain-')) {
    const chainsPath = join(dirname(opts.pathsPath), 'chains.json');
    if (!existsSync(chainsPath)) {
      process.stderr.write(`chains not found: ${chainsPath}\n`);
      return 2;
    }
    const chain = readChains(chainsPath).find((c) => c.id === opts.id);
    if (!chain) {
      process.stderr.write(`chain not found: ${opts.id}\n`);
      return 2;
    }
    if (opts.json) {
      process.stdout.write(JSON.stringify(chain, null, 2) + '\n');
    } else {
      const lines = [
        `${chain.id}  ${chain.rule}（score ${chain.score} / ${chain.risk}，路径 ${chain.count}，跨 agent ${chain.crossAgent}）`,
        `source: ${chain.sourceCapability}（${chain.sourceTools.join(', ')}）`,
        `sink:   ${chain.sinkCapability}（${chain.sinkTools.join(', ')}）`,
      ];
      if (chain.chain_diff) {
        if (chain.chain_diff.strategy === 'capability-level' && chain.chain_diff.capability_recommendation) {
          lines.push(`断链（能力级）：${chain.chain_diff.capability_recommendation.reason}`);
          lines.push('示例改动：');
        } else {
          lines.push(
            `断链：收紧 ${chain.chain_diff.strategy === 'tighten-sinks' ? 'sink' : 'source'} 的 ${chain.chain_diff.changes.length} 个工具`,
          );
        }
        for (const change of chain.chain_diff.changes) {
          lines.push(`  - ${change.target}: ${change.from} → ${change.to}`);
        }
      }
      process.stdout.write(lines.join('\n') + '\n');
    }
    return 0;
  }
  const paths = readPaths(opts.pathsPath);
  const path = paths.find((p) => p.id === opts.id);
  if (!path) {
    process.stderr.write(`path not found: ${opts.id}\n`);
    return 2;
  }
  if (opts.json) {
    process.stdout.write(JSON.stringify(path, null, 2) + '\n');
  } else {
    process.stdout.write(
      [
        `${path.id}  ${path.rule}（${path.kind}，置信度 ${path.confidence}）`,
        `source: ${path.source.agent}.${path.source.server}.${path.source.tool} [${path.source.capability}]`,
        `sink:   ${path.sink.agent}.${path.sink.server}.${path.sink.tool} [${path.sink.capability}]`,
        `说明:   ${path.explain}`,
        ...path.evidence.map((e) => `证据:   ${e}`),
        ...(path.suggested_diff
          ? [`建议:   ${path.suggested_diff.target} ${path.suggested_diff.from} → ${path.suggested_diff.to}`]
          : []),
      ].join('\n') + '\n',
    );
  }
  return 0;
}
