import { DEFAULT_SECRET_RULES, type Policy, type ServerPolicy } from '@podsec/policy';
import { buildToolRefs } from './toxic.js';
import type { GraphDiffEntry } from './graph-diff.js';
import type { CapabilityGraph, ToolRef } from './types.js';
import { t } from '@podsec/i18n';

export interface BaselineOptions {
  agent: string;
  capabilityRules?: { deny?: string[]; approve?: string[]; allow?: string[] };
}

export interface BaselineResult {
  policy: Policy;
  overPrivileged: GraphDiffEntry[];
  shadow: GraphDiffEntry[];
  counts: { allow: number; approve: number; deny: number; omitted: number };
}

function toDiffEntry(ref: ToolRef, calls?: number): GraphDiffEntry {
  return {
    server: ref.server,
    servers: [ref.server],
    tool: ref.tool,
    agents: [ref.agent],
    capabilities: ref.capabilities.map((assertion) => assertion.capability),
    calls,
  };
}

/** 观测到的能力 → 决策：破坏性 deny，敏感/写/外发审批，只读放行；未分类按保守审批 */
export function decideFromCapabilities(capabilities: string[]): 'allow' | 'approve' | 'deny' {
  if (capabilities.includes('destructive-write')) return 'deny';
  if (capabilities.includes('read-secret')) return 'approve';
  if (
    capabilities.some((capability) =>
      ['exec', 'external-communication', 'credential-access'].includes(capability),
    )
  ) {
    return 'approve';
  }
  if (capabilities.length === 0) return 'approve';
  return 'allow';
}

/**
 * B4：从潜在图 + 观测图为单个 agent 生成最小权限基线。
 * - 观测到的工具按其能力分档；
 * - 潜在有、观测无（权限过载）的工具不进策略 → 默认 deny；
 * - 观测有、潜在无（影子能力）的工具按保守审批并标注。
 */
export function baselineForAgent(
  potential: CapabilityGraph,
  observed: CapabilityGraph,
  opts: BaselineOptions,
): BaselineResult {
  const potentialRefs = buildToolRefs(potential).filter((ref) => ref.agent === opts.agent);
  const observedRefs = buildToolRefs(observed).filter((ref) => ref.agent === opts.agent);
  const observedKeys = new Set(observedRefs.map((ref) => `${ref.server}|${ref.tool}`));
  const potentialKeys = new Set(potentialRefs.map((ref) => `${ref.server}|${ref.tool}`));

  const servers: Record<string, ServerPolicy> = {};
  const capabilityMap: Record<string, string[]> = {};
  const counts = { allow: 0, approve: 0, deny: 0, omitted: 0 };

  for (const ref of observedRefs) {
    const capabilities = ref.capabilities.map((assertion) => assertion.capability);
    const decision = decideFromCapabilities(capabilities);
    const serverPolicy = servers[ref.server] ?? (servers[ref.server] = {});
    const list = serverPolicy[decision] ?? (serverPolicy[decision] = []);
    if (!list.includes(ref.tool)) list.push(ref.tool);
    capabilityMap[`${ref.server}.${ref.tool}`] = capabilities;
    counts[decision] += 1;
  }

  const callCount = (ref: ToolRef): number | undefined =>
    observed.nodes.find((node) => node.id === ref.nodeId)?.calls;
  const overPrivileged = potentialRefs
    .filter((ref) => !observedKeys.has(`${ref.server}|${ref.tool}`))
    .map((ref) => toDiffEntry(ref));
  const shadow = observedRefs
    .filter((ref) => !potentialKeys.has(`${ref.server}|${ref.tool}`))
    .map((ref) => toDiffEntry(ref, callCount(ref)));
  counts.omitted = overPrivileged.length;

  const policy: Policy = {
    version: '0.1.0',
    agent: opts.agent,
    defaultDecision: 'deny',
    servers,
    capabilityMap,
    secrets: DEFAULT_SECRET_RULES,
    ...(opts.capabilityRules ? { capabilityRules: opts.capabilityRules } : {}),
  };
  return { policy, overPrivileged, shadow, counts };
}

export function renderBaselineReport(agent: string, result: BaselineResult): string {
  const { counts, policy, overPrivileged, shadow } = result;
  const lines = [
    `# pod graph baseline — ${agent}`,
    '',
    t('allow {allow} · approve {approve} · deny {deny} · 省略（权限过载）{omitted}', {
      allow: counts.allow,
      approve: counts.approve,
      deny: counts.deny,
      omitted: counts.omitted,
    }),
    '',
  ];
  if (shadow.length > 0) {
    lines.push(t('## 影子能力（需人工确认）：{n}', { n: shadow.length }));
    for (const entry of shadow) {
      lines.push(
        t('- {server}.{tool}（{caps}，调用 {n}）', {
          server: entry.server,
          tool: entry.tool,
          caps: entry.capabilities.join(', ') || t('未分类'),
          n: entry.calls ?? 0,
        }),
      );
    }
    lines.push('');
  }
  if (overPrivileged.length > 0) {
    lines.push(t('## 已从基线移除（潜在 − 实际）：{n}', { n: overPrivileged.length }));
    for (const entry of overPrivileged.slice(0, 30)) {
      lines.push(
        t('- {server}.{tool}（{caps}）', {
          server: entry.server,
          tool: entry.tool,
          caps: entry.capabilities.join(', ') || t('未分类'),
        }),
      );
    }
    if (overPrivileged.length > 30) lines.push(t('- … 还有 {n} 条', { n: overPrivileged.length - 30 }));
    lines.push('');
  }
  lines.push('## 策略', '', '```json', JSON.stringify(policy, null, 2), '```');
  return lines.join('\n');
}
