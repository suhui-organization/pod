import type { Policy } from '@podsec/policy';
import type { PolicyDiffHint, ToxicPath } from './types.js';

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
      rationale: 'sink 是链路末端；改为审批可保留可用性，同时阻断自动外发。',
    };
  }
  const source = decisionFor(policy, path.source.server, path.source.tool);
  if (source === 'allow' || source === '(unlisted)') {
    return {
      target: `${path.source.server}.${path.source.tool}`,
      from: source,
      to: 'approve',
      rationale: 'sink 已需审批，收紧 source 可进一步降低自动触发的风险。',
    };
  }
  if (source === 'approve') {
    return {
      target: `${path.source.server}.${path.source.tool}`,
      from: 'approve',
      to: 'deny',
      rationale: '两端均已需审批；若要彻底断链，需 deny source（会改变工作流，需人工确认）。',
    };
  }
  return null;
}
