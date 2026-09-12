import type { Policy } from '@podsec/policy';
import type { PathEndpoint, PolicyDiffHint, ToxicGroup, ToxicPath } from './types.js';
import { t } from '@podsec/i18n';

export function decisionFor(
  policy: Policy,
  server: string,
  tool: string,
): 'allow' | 'approve' | 'deny' | '(unlisted)' {
  const rules = policy.servers?.[server];
  if (!rules) return '(unlisted)';
  if (rules.deny?.includes(tool)) return 'deny';
  if (rules.approve?.includes(tool)) return 'approve';
  if (rules.allow?.includes(tool)) return 'allow';
  return '(unlisted)';
}

export function suggestDiff(path: ToxicPath, policy: Policy): PolicyDiffHint | null {
  const sink = decisionFor(policy, path.sink.server, path.sink.tool);
  if (sink === 'deny') return null;
  if (sink === 'allow' || sink === '(unlisted)') {
    return {
      target: `${path.sink.server}.${path.sink.tool}`,
      from: sink,
      to: 'approve',
      rationale: t('sink 是链路末端；改为审批可保留可用性，同时阻断自动外发。'),
    };
  }
  const source = decisionFor(policy, path.source.server, path.source.tool);
  if (source === 'allow' || source === '(unlisted)') {
    return {
      target: `${path.source.server}.${path.source.tool}`,
      from: source,
      to: 'approve',
      rationale: t('sink 已需审批，收紧 source 可进一步降低自动触发的风险。'),
    };
  }
  if (source === 'approve') {
    return {
      target: `${path.source.server}.${path.source.tool}`,
      from: 'approve',
      to: 'deny',
      rationale: t('两端均已需审批；若要彻底断链，需 deny source（会改变工作流，需人工确认）。'),
    };
  }
  return null;
}

export interface ChainDiffHint {
  chain_id: string;
  strategy: 'tighten-sinks' | 'tighten-sources' | 'capability-level';
  changes: PolicyDiffHint[];
  capability_recommendation?: {
    capability: string;
    action: 'approve' | 'deny';
    reason: string;
    needs_capability_policy: boolean;
    policy_patch: { capabilityRules: { approve?: string[]; deny?: string[] } };
  };
  breaks_paths: number;
  total_paths: number;
}

function uniqueToolEndpoints(endpoints: PathEndpoint[]): PathEndpoint[] {
  const seen = new Set<string>();
  return endpoints.filter((endpoint) => {
    const key = `${endpoint.server}.${endpoint.tool}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

/**
 * 链级 diff：选择改动更少的一侧（sink 或 source）来断掉整条链。
 * 覆盖的路径数是该链类型的全部路径（收紧一侧即可断掉所有经过该侧工具的路径）。
 */
export function suggestChainDiff(group: ToxicGroup, policy: Policy): ChainDiffHint | null {
  const sinks = uniqueToolEndpoints(group.sinkEndpoints);
  const sources = uniqueToolEndpoints(group.sourceEndpoints);
  if (sinks.length === 0 || sources.length === 0) return null;

  const strategy: ChainDiffHint['strategy'] =
    sinks.length <= sources.length ? 'tighten-sinks' : 'tighten-sources';
  const targets = strategy === 'tighten-sinks' ? sinks : sources;
  const changes: PolicyDiffHint[] = [];
  for (const target of targets) {
    const from = decisionFor(policy, target.server, target.tool);
    if (from === 'deny') continue;
    changes.push({
      target: `${target.server}.${target.tool}`,
      from,
      to: from === 'approve' ? 'deny' : 'approve',
      rationale:
        strategy === 'tighten-sinks'
        ? t('断链：收紧 sink {server}.{tool}（{capability}）', {
            server: target.server,
            tool: target.tool,
            capability: target.capability,
          })
          : t('断链：收紧 source {server}.{tool}（{capability}）', {
              server: target.server,
              tool: target.tool,
              capability: target.capability,
            }),
    });
  }
  if (changes.length === 0) return null;
  if (targets.length > 3) {
    const capability = strategy === 'tighten-sinks' ? group.sinkCapability : group.sourceCapability;
    const side = strategy === 'tighten-sinks' ? 'sink' : 'source';
    return {
      chain_id: group.id,
      strategy: 'capability-level',
      changes: changes.slice(0, 3),
      capability_recommendation: {
        capability,
        action: 'approve',
        reason: t(
          '工具级最小割需要改 {n} 个 {side}；建议加入 capabilityRules.approve: ["{capability}"]，并运行 pod graph apply 生成 capabilityMap',
          { n: targets.length, side, capability },
        ),
        needs_capability_policy: false,
        policy_patch: { capabilityRules: { approve: [capability] } },
      },
      breaks_paths: group.count,
      total_paths: group.count,
    };
  }
  return {
    chain_id: group.id,
    strategy,
    changes,
    breaks_paths: group.count,
    total_paths: group.count,
  };
}
