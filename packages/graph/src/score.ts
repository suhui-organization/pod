import type { Capability, ToxicGroup } from './types.js';

export interface ScoredToxicGroup extends ToxicGroup {
  score: number;
  risk: 'critical' | 'high' | 'medium' | 'low';
  score_reasons: string[];
}

const RULE_SCORE: Record<string, number> = {
  exfiltration: 40,
  'injection-exec': 40,
  'credential-abuse': 40,
  'injection-exfil': 30,
  destruction: 20,
};

const SEVERITY_SCORE: Record<ToxicGroup['severity'], number> = {
  high: 20,
  medium: 10,
  low: 0,
};

const SOURCE_SCORE: Record<Capability, number> = {
  'read-secret': 25,
  'credential-access': 20,
  'read-private-data': 15,
  'read-untrusted-input': 10,
  'destructive-write': 10,
  exec: 0,
  'external-communication': 0,
};

const SINK_SCORE: Record<Capability, number> = {
  exec: 25,
  'external-communication': 20,
  'destructive-write': 15,
  'read-secret': 0,
  'read-private-data': 0,
  'read-untrusted-input': 0,
  'credential-access': 0,
};

export function scoreToxicGroup(group: ToxicGroup): ScoredToxicGroup {
  const reasons: string[] = [];
  let score = 0;

  const ruleScore = RULE_SCORE[group.rule] ?? 10;
  score += ruleScore;
  reasons.push(`rule ${group.rule} +${ruleScore}`);

  const severityScore = SEVERITY_SCORE[group.severity];
  score += severityScore;
  if (severityScore > 0) reasons.push(`${group.severity} severity +${severityScore}`);

  if (group.crossAgent > 0) {
    const ratio = group.crossAgent / Math.max(1, group.count);
    const crossScore = ratio >= 0.5 ? 20 : 15;
    score += crossScore;
    reasons.push(`cross-agent ${group.crossAgent}/${group.count} +${crossScore}`);
  }

  const sourceScore = SOURCE_SCORE[group.sourceCapability] ?? 0;
  if (sourceScore > 0) {
    score += sourceScore;
    reasons.push(`source ${group.sourceCapability} +${sourceScore}`);
  }

  const sinkScore = SINK_SCORE[group.sinkCapability] ?? 0;
  if (sinkScore > 0) {
    score += sinkScore;
    reasons.push(`sink ${group.sinkCapability} +${sinkScore}`);
  }

  const confidenceScore = Math.round(group.sample.confidence * 15);
  if (confidenceScore > 0) {
    score += confidenceScore;
    reasons.push(`confidence ${group.sample.confidence} +${confidenceScore}`);
  }

  const prevalenceScore = Math.min(10, Math.round(Math.log10(group.count + 1) * 3));
  if (prevalenceScore > 0) {
    score += prevalenceScore;
    reasons.push(`${group.count} paths +${prevalenceScore}`);
  }

  const risk: ScoredToxicGroup['risk'] = score >= 130 ? 'critical' : score >= 100 ? 'high' : score >= 70 ? 'medium' : 'low';
  return { ...group, score, risk, score_reasons: reasons };
}

export function scoreToxicGroups(groups: ToxicGroup[]): ScoredToxicGroup[] {
  return groups
    .map(scoreToxicGroup)
    .sort((a, b) => b.score - a.score || b.crossAgent - a.crossAgent || a.rule.localeCompare(b.rule));
}
