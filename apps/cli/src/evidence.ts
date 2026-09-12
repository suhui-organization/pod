/**
 * 证据链产品化（P0）：Agent 黑匣子三件套。
 *
 * - timeline：按时间线回放审计（调用 → 参数哈希 → 决策 → 审批人 → 当时策略版本）
 * - verify-audit：一键自证（完整哈希链校验 + 自检报告）
 * - export-evidence：导出单文件证据包（审计 + 策略快照 + 自校验说明 + 顶层哈希）
 */
import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { AuditLog, loadAuditFile, sha256Hex, stableStringify } from '@podsec/audit';
import { t } from '@podsec/i18n';

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

/**
 * 列出审计目录下所有 JSONL 文件，支持两种布局：
 * - 顶层：`<audit-dir>/<server>.jsonl`（单网关）
 * - 子目录：`<audit-dir>/<agent>/<server>.jsonl`（多网关，见 docs/automation.md）
 * key 为不含 .jsonl 的标识：顶层 `filesystem`，子目录 `openclaw/filesystem`。
 */
export function listAuditFiles(auditDir: string): Array<{ key: string; path: string }> {
  if (!existsSync(auditDir)) return [];
  const out: Array<{ key: string; path: string }> = [];
  for (const entry of readdirSync(auditDir).sort()) {
    if (entry.endsWith('.jsonl')) {
      out.push({ key: entry.replace(/\.jsonl$/, ''), path: join(auditDir, entry) });
      continue;
    }
    if (entry.startsWith('.') || entry.endsWith('.legacy')) continue;
    const sub = join(auditDir, entry);
    try {
      if (!statSync(sub).isDirectory()) continue;
    } catch {
      continue;
    }
    for (const file of readdirSync(sub).filter((f) => f.endsWith('.jsonl')).sort()) {
      out.push({ key: `${entry}/${file.replace(/\.jsonl$/, '')}`, path: join(sub, file) });
    }
  }
  return out;
}

/** 读取审计目录全部文件（含多 agent 子目录；不校验，坏文件由调用方 verify 标记） */
export function loadAllAuditFiles(auditDir: string): Array<{ server: string; log: AuditLog }> {
  return listAuditFiles(auditDir).map(({ key, path }) => ({
    server: key,
    log: AuditLog.fromJSONL(readFileSync(path, 'utf8'), ''),
  }));
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
    lines.push(t('⚠️ 以下审计文件哈希链损坏（篡改或中断），已跳过：{list}', { list: broken.join(', ') }));
    lines.push('');
  }
  if (entries.length === 0) {
    lines.push(t('（无匹配事件）'));
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
  const out: VerifyResult[] = [];
  for (const { key: server, path } of listAuditFiles(auditDir)) {
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
  for (const { key, path } of listAuditFiles(auditDir)) {
      const file = `${key}.jsonl`;
      const text = readFileSync(path, 'utf8');
      audits[file] = text;
      const log = AuditLog.fromJSONL(text, '');
      const check = log.verify();
      const rec: Partial<VerifyResult> = {
        server: key,
        ok: check.ok,
        entries: log.entries.length,
      };
      // 剔除 undefined 字段：JSON 落盘会省略它们，哈希必须与落盘口径一致
      if (log.entries[0]) rec.headHash = log.entries[0]!.hash;
      if (log.entries.length > 0) rec.tailHash = log.entries[log.entries.length - 1]!.hash;
      if (check.firstBrokenSeq !== undefined) rec.firstBrokenSeq = check.firstBrokenSeq;
      verify[file] = rec as VerifyResult;
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

// ---------- 一页式合规报告（P1，给客户/审计看） ----------

export interface EvidenceSummary {
  entries: number;
  servers: string[];
  agents: string[];
  tools: string[];
  firstTs?: string;
  lastTs?: string;
  blocked: number;
  decisions: Record<string, number>;
}

/** 汇总证据包中的审计范围（纯函数，不联网） */
export function summarizeEvidence(bundle: EvidenceBundle): EvidenceSummary {
  const agents = new Set<string>();
  const tools = new Set<string>();
  const decisions: Record<string, number> = {};
  let entries = 0;
  let blocked = 0;
  let firstTs: string | undefined;
  let lastTs: string | undefined;
  for (const text of Object.values(bundle.audits)) {
    const log = AuditLog.fromJSONL(text, '');
    for (const e of log.entries) {
      entries += 1;
      agents.add(e.agent);
      tools.add(e.tool);
      if (e.outcome === 'blocked') blocked += 1;
      decisions[e.decision] = (decisions[e.decision] ?? 0) + 1;
      if (!firstTs || e.ts < firstTs) firstTs = e.ts;
      if (!lastTs || e.ts > lastTs) lastTs = e.ts;
    }
  }
  return {
    entries,
    servers: Object.keys(bundle.audits).map((f) => f.replace(/\.jsonl$/, '')).sort(),
    agents: [...agents].sort(),
    tools: [...tools].sort(),
    firstTs,
    lastTs,
    blocked,
    decisions,
  };
}

function fmtTs(ts: string | undefined): string {
  return ts ? ts.slice(0, 19).replace('T', ' ') : '—';
}

/**
 * 一页式证据报告：把 `pod-evidence-v1` 包渲染成能直接交给客户/审计的 Markdown。
 * 重点是"控制叙事 + 独立验证方式"，而不是堆原始日志。
 */
export function renderEvidenceReport(bundle: EvidenceBundle): string {
  const s = summarizeEvidence(bundle);
  const lines: string[] = ['# AI Agent 操作审计证据包', ''];
  lines.push(`> 由 pod 本地生成，数据未上传任何第三方。导出时间：${bundle.exported_at}`);
  lines.push('');
  lines.push('## 1. 覆盖范围');
  lines.push('');
  lines.push(`- 证据窗口：${fmtTs(s.firstTs)} → ${fmtTs(s.lastTs)}`);
  lines.push(`- 审计记录：${s.entries} 条（其中被阻断 ${s.blocked} 条）`);
  lines.push(`- Agent：${s.agents.length > 0 ? s.agents.join('、') : '—'}`);
  lines.push(`- MCP server：${s.servers.length > 0 ? s.servers.join('、') : '—'}`);
  lines.push(`- 涉及工具：${s.tools.length} 个`);
  lines.push(
    `- 决策分布：allow ${s.decisions.allow ?? 0} / approve ${s.decisions.approve ?? 0} / deny ${s.decisions.deny ?? 0}`,
  );
  lines.push('');

  lines.push('## 2. 完整性自证');
  lines.push('');
  lines.push(`- 顶层哈希：\`${bundle.top_level_hash}\``);
  lines.push('');
  lines.push('| 审计文件 | 哈希链 | 条目 | 链首 hash | 链尾 hash |');
  lines.push('|----------|--------|-----:|-----------|-----------|');
  for (const [file, r] of Object.entries(bundle.verify)) {
    lines.push(
      `| ${file} | ${r.ok ? '✅ 完整' : `❌ 断裂@${r.firstBrokenSeq}`} | ${r.entries} | ` +
        `${r.headHash ? r.headHash.slice(0, 12) + '…' : '—'} | ${r.tailHash ? r.tailHash.slice(0, 12) + '…' : '—'} |`,
    );
  }
  lines.push('');

  lines.push('## 3. 控制措施');
  lines.push('');
  lines.push('| 控制项 | pod 机制 | 本证据包中的对应记录 |');
  lines.push('|--------|----------|----------------------|');
  lines.push('| 工具调用授权 | 策略引擎，`deny > approve > allow`，未授权默认拒绝 | 每条记录的 decision / reason |');
  lines.push('| 高风险操作审批 | 审批闸门，超时按拒绝处理（fail-closed） | approver / reason 字段 |');
  lines.push('| 审计不可篡改 | SHA-256 哈希链，逐条前后链接 | 上方完整性自证 + 链首/链尾 hash |');
  lines.push('| 敏感数据防外泄 | 敏感路径输入拦截 + 输出密钥正则拦截 | 被阻断记录（blocked） |');
  lines.push('| 供应链来源校验 | server 启动来源白名单（command/package/version） | 策略快照中的 source 字段 |');
  lines.push('');

  lines.push('## 4. 独立验证方式');
  lines.push('');
  lines.push('```bash');
  lines.push('# 验证证据包未被修改');
  lines.push('pod verify-evidence <bundle.json>');
  lines.push('# 重新校验原始审计哈希链');
  lines.push('pod verify-audit --audit-dir <audit-dir>');
  lines.push('```');
  lines.push('');
  lines.push('---');
  lines.push('pod 只记录工具调用的哈希与元数据，不存储参数/输出原文。');
  lines.push('');
  return lines.join('\n');
}
