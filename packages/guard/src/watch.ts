/**
 * 实时监控的增量逻辑：把"这一轮"和"上一轮"做差。
 *
 * 为什么要有这一层：每 5 分钟把同一份告警重打一遍，用户三分钟后就学会忽略它。
 * 只有**新增 / 变化 / 消失**才值得打断人——这与 pod posture 的漂移口径一致。
 *
 * 快照只存 finding id 与内容指纹，不存配置原文：状态文件（~/.pod/guard/state.json）
 * 不能变成第二个泄露面。
 */
import { createHash } from 'node:crypto';
import type { Finding } from './types.js';
import { SEVERITY_ORDER } from './types.js';

export interface GuardSnapshot {
  v: 1;
  capturedAt: string;
  /** finding id → 内容指纹（消息或级别变了也算变化） */
  fingerprints: Record<string, string>;
}

export interface GuardDiff {
  /** 本轮新出现的 finding */
  added: Finding[];
  /** 同一个 id 但内容变了（例如严重级别升级、证据增加） */
  changed: Finding[];
  /** 上一轮有、本轮没有——可能已被修好，也可能是扫描面缩小了 */
  resolved: string[];
  /** 完全没变的条数 */
  unchanged: number;
  /** 是否与上一轮完全一致 */
  quiet: boolean;
}

export function findingFingerprint(finding: Finding): string {
  return createHash('sha256')
    .update([finding.severity, finding.message, ...finding.evidence].join('\u0000'))
    .digest('hex')
    .slice(0, 16);
}

export function snapshotOf(findings: Finding[], now: Date = new Date()): GuardSnapshot {
  const fingerprints: Record<string, string> = {};
  for (const finding of findings) fingerprints[finding.id] = findingFingerprint(finding);
  return { v: 1, capturedAt: now.toISOString(), fingerprints };
}

export function parseGuardSnapshot(text: string): GuardSnapshot {
  const raw = JSON.parse(text) as Partial<GuardSnapshot>;
  if (raw.v !== 1 || typeof raw.fingerprints !== 'object' || raw.fingerprints === null) {
    throw new Error('状态文件格式不支持（期望 v=1）');
  }
  return { v: 1, capturedAt: raw.capturedAt ?? '', fingerprints: raw.fingerprints };
}

export function diffFindings(previous: GuardSnapshot | null, current: Finding[]): GuardDiff {
  if (!previous) {
    return { added: [...current], changed: [], resolved: [], unchanged: 0, quiet: current.length === 0 };
  }
  const added: Finding[] = [];
  const changed: Finding[] = [];
  let unchanged = 0;
  const seen = new Set<string>();
  for (const finding of current) {
    seen.add(finding.id);
    const before = previous.fingerprints[finding.id];
    if (before === undefined) added.push(finding);
    else if (before !== findingFingerprint(finding)) changed.push(finding);
    else unchanged++;
  }
  const resolved = Object.keys(previous.fingerprints).filter((id) => !seen.has(id));
  const sort = (list: Finding[]): Finding[] =>
    list.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] || a.id.localeCompare(b.id));
  return {
    added: sort(added),
    changed: sort(changed),
    resolved: resolved.sort(),
    unchanged,
    quiet: added.length === 0 && changed.length === 0 && resolved.length === 0,
  };
}
