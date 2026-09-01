/**
 * 证据链产品化（P0）：Agent 黑匣子三件套。
 *
 * - timeline：按时间线回放审计（调用 → 参数哈希 → 决策 → 审批人 → 当时策略版本）
 * - verify-audit：一键自证（完整哈希链校验 + 自检报告）
 * - export-evidence：导出单文件证据包（审计 + 策略快照 + 自校验说明 + 顶层哈希）
 */
import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { AuditLog, loadAuditFile, sha256Hex, stableStringify } from '@podsec/audit';

// ---------- 通用 ----------

export interface TimelineEntry {
  ts: string;
  agent: string;
  server: string;
  tool: string;
  decision: string;
  outcome: string;
  argsHash: string;
  approver?: string;
  reason?: string;
  policyVersion: string;
  seq: number;
  file: string;
}

/** 读取审计目录全部文件（校验链，损坏文件抛错并注明） */
export function loadAllAuditFiles(auditDir: string): Array<{ server: string; log: AuditLog }> {
  if (!existsSync(auditDir)) return [];
  const out: Array<{ server: string; log: AuditLog }> = [];
  for (const file of readdirSync(auditDir).filter((f) => f.endsWith('.jsonl')).sort()) {
    const server = file.replace(/\.jsonl$/, '');
    // fromJSONL 不校验（坏文件由调用方 verify 标记，不抛）
    out.push({ server, log: AuditLog.fromJSONL(readFileSync(join(auditDir, file), 'utf8'), '') });
  }
  return out;
}

export function parseSince(since: string | undefined): string | null {
  if (!since) return null;
  const m = since.match(/^(\d+)(m|h|d)$/);
  if (m) {
    const n = Number.parseInt(m[1]!, 10);
    const unit = m[2]!;
    const ms = unit === 'm' ? n * 60_000 : unit === 'h' ? n * 3_600_000 : n * 86_400_000;
    return new Date(Date.now() - ms).toISOString();
  }
  // 尝试 ISO 时间
  const iso = new Date(since);
  if (!Number.isNaN(iso.getTime())) return iso.toISOString();
  return null;
}

// ---------- timeline ----------

export interface TimelineOptions {
  auditDir: string;
  server?: string;
  agent?: string;
  tool?: string;
  since?: string;
  limit?: number;
}

export function buildTimeline(opts: TimelineOptions): { entries: TimelineEntry[]; broken: string[] } {
  const files = loadAllAuditFiles(opts.auditDir);
  const sinceTs = parseSince(opts.since);
  const entries: TimelineEntry[] = [];
  const broken: string[] = [];
  for (const { server, log } of files) {
    if (opts.server && server !== opts.server) continue;
    let verified: { ok: boolean } = { ok: true };
    try {
      verified = log.verify();
    } catch {
      verified = { ok: false };
    }
    if (!verified.ok) {
      broken.push(server);
      continue;
    }
    for (const e of log.entries) {
      if (opts.agent && e.agent !== opts.agent) continue;
      if (opts.tool && e.tool !== opts.tool) continue;
      if (sinceTs && e.ts < sinceTs) continue;
      entries.push({
        ts: e.ts,
        agent: e.agent,
        server: e.server,
        tool: e.tool,
        decision: e.decision,
        outcome: e.outcome,
        argsHash: e.argsHash,
        approver: e.approver,
        reason: e.reason,
        policyVersion: e.policyVersion,
        seq: e.seq,
        file: `${server}.jsonl`,
      });
    }
  }
  entries.sort((a, b) => (a.ts < b.ts ? -1 : a.ts > b.ts ? 1 : a.seq - b.seq));
  if (opts.limit && entries.length > opts.limit) entries.splice(0, entries.length - opts.limit);
  return { entries, broken };
}

export function renderTimeline(entries: TimelineEntry[], broken: string[]): string {
  const lines: string[] = [];
  if (broken.length > 0) {
    lines.push(`⚠️ 以下审计文件哈希链损坏（篡改或中断），已跳过：${broken.join(', ')}`);
    lines.push('');
  }
  if (entries.length === 0) {
    lines.push('（无匹配事件）');
    return lines.join('\n');
  }
  for (const e of entries) {
    const when = e.ts.slice(0, 19).replace('T', ' ');
    const d = e.decision.padEnd(7);
    const tags: string[] = [];
    if (e.approver) tags.push(`approver=${e.approver}`);
    if (e.reason) tags.push(`reason=${e.reason.slice(0, 40)}`);
    if (e.outcome === 'blocked') tags.push('blocked');
    lines.push(
      `${when}  [${d}] ${e.tool.padEnd(18)} ${e.server.padEnd(12)} agent=${e.agent.padEnd(14)} ` +
        `args=${e.argsHash.slice(0, 8)}… pol=${e.policyVersion}${tags.length ? '  ' + tags.join(' ') : ''}`,
    );
  }
  return lines.join('\n');
}

// ---------- verify-audit ----------

export interface VerifyResult {
  server: string;
  ok: boolean;
  entries: number;
  headHash?: string;
  tailHash?: string;
  firstBrokenSeq?: number;
}

export function verifyAll(auditDir: string): VerifyResult[] {
  if (!existsSync(auditDir)) return [];
  const out: VerifyResult[] = [];
  for (const file of readdirSync(auditDir).filter((f) => f.endsWith('.jsonl')).sort()) {
    const server = file.replace(/\.jsonl$/, '');
    const path = join(auditDir, file);
    const log = AuditLog.fromJSONL(readFileSync(path, 'utf8'), '');
    const check = log.verify();
    out.push({
      server,
      ok: check.ok,
      entries: log.entries.length,
      headHash: log.entries[0]?.hash,
      tailHash: log.entries[log.entries.length - 1]?.hash,
      firstBrokenSeq: check.firstBrokenSeq,
    });
  }
  return out;
}

export function renderVerifyReport(results: VerifyResult[], auditDir: string): string {
  const lines: string[] = ['# pod 审计完整性自检报告', ''];
  lines.push(`生成时间：${new Date().toISOString()}`);
  lines.push(`审计目录：${auditDir}`);
  lines.push('');
  const allOk = results.every((r) => r.ok);
  for (const r of results) {
    lines.push(`## ${r.server}.jsonl`);
    lines.push('');
    lines.push(`- 状态：${r.ok ? '✅ 哈希链完整' : `❌ 哈希链断裂（seq ${r.firstBrokenSeq}）`}`);
    lines.push(`- 条目数：${r.entries}`);
    if (r.headHash) lines.push(`- 链首 hash：${r.headHash}`);
    if (r.tailHash) lines.push(`- 链尾 hash：${r.tailHash}`);
    lines.push('');
  }
  if (results.length === 0) lines.push('（审计目录为空）');
  lines.push('---');
  lines.push(`**结论：${allOk ? '全部审计记录可验证、不可篡改。' : '存在损坏记录，请排查。'}**`);
  return lines.join('\n');
}

// ---------- export-evidence ----------

export interface EvidenceBundle {
  format: 'pod-evidence-v1';
  exported_at: string;
  audits: Record<string, string>;
  policies: Record<string, string>;
  verify: Record<string, VerifyResult>;
  top_level_hash: string;
}

export function exportEvidence(opts: {
  auditDir: string;
  policyDir: string;
  outPath: string;
}): EvidenceBundle {
  const auditDir = opts.auditDir;
  const audits: Record<string, string> = {};
  const verify: Record<string, VerifyResult> = {};
  if (existsSync(auditDir)) {
    for (const file of readdirSync(auditDir).filter((f) => f.endsWith('.jsonl')).sort()) {
      const text = readFileSync(join(auditDir, file), 'utf8');
      audits[file] = text;
      const log = AuditLog.fromJSONL(text, '');
      const check = log.verify();
      const rec: Partial<VerifyResult> = {
        server: file.replace(/\.jsonl$/, ''),
        ok: check.ok,
        entries: log.entries.length,
      };
      // 剔除 undefined 字段：JSON 落盘会省略它们，哈希必须与落盘口径一致
      if (log.entries[0]) rec.headHash = log.entries[0]!.hash;
      if (log.entries.length > 0) rec.tailHash = log.entries[log.entries.length - 1]!.hash;
      if (check.firstBrokenSeq !== undefined) rec.firstBrokenSeq = check.firstBrokenSeq;
      verify[file] = rec as VerifyResult;
    }
  }
  const policies: Record<string, string> = {};
  if (existsSync(opts.policyDir)) {
    for (const file of readdirSync(opts.policyDir).filter((f) => f.endsWith('.json')).sort()) {
      policies[file] = readFileSync(join(opts.policyDir, file), 'utf8');
    }
  }
  const bundle: EvidenceBundle = {
    format: 'pod-evidence-v1',
    exported_at: new Date().toISOString(),
    audits,
    policies,
    verify,
    top_level_hash: '',
  };
  // 顶层哈希：对除自身外的全部内容做确定性哈希（含 exported_at，供审计链与导出时间绑定）
  bundle.top_level_hash = sha256Hex(stableStringify({ ...bundle, top_level_hash: '' }));
  mkdirSync(dirname(opts.outPath), { recursive: true });
  writeFileSync(opts.outPath, JSON.stringify(bundle, null, 2) + '\n', 'utf8');
  return bundle;
}

export function verifyEvidenceBundle(path: string): { ok: boolean; reason?: string } {
  try {
    const bundle = JSON.parse(readFileSync(path, 'utf8')) as EvidenceBundle;
    if (bundle.format !== 'pod-evidence-v1') return { ok: false, reason: 'format 不是 pod-evidence-v1' };
    const expected = sha256Hex(stableStringify({ ...bundle, top_level_hash: '' }));
    if (expected !== bundle.top_level_hash) return { ok: false, reason: '顶层哈希不匹配（包被修改过）' };
    return { ok: true };
  } catch (e) {
    return { ok: false, reason: e instanceof Error ? e.message : String(e) };
  }
}
