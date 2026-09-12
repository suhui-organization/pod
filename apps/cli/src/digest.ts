/**
 * pod digest — 本地安全周报（P1，OPC 缺口 G4：价值不可见）。
 *
 * 纯本地、不联网：把哈希链审计聚合成一页人话报告，让"平静的一天"也有价值感。
 * 输出：调用量 / 拦截 / 审批 / 敏感命中 / 未受管 server / 哈希链健康。
 */
import type { AuditEntry } from '@podsec/audit';
import { t } from '@podsec/i18n';

export interface DigestInput {
  server: string;
  entries: AuditEntry[];
}

export interface DigestCoverage {
  managed: string[];
  unmanaged: string[];
}

export interface DigestOptions {
  /** 统计窗口起点（ISO） */
  from: string;
  /** 统计窗口终点（ISO） */
  to: string;
  chain?: Array<{ server: string; ok: boolean; entries: number }>;
  coverage?: DigestCoverage;
}

export interface DigestTotals {
  calls: number;
  allow: number;
  approve: number;
  deny: number;
  ok: number;
  error: number;
  blocked: number;
  /** enforced=false 的 record-only 记录数 */
  recorded: number;
}

export interface DigestToolRow {
  server: string;
  tool: string;
  calls: number;
  blocked: number;
  sensitive: number;
}

export interface DigestAlert {
  ts: string;
  server: string;
  tool: string;
  kind: 'deny' | 'secret_leak' | 'injection_suspect' | 'approval_timeout';
  reason: string;
}

export interface DigestApprovals {
  total: number;
  approved: number;
  denied: number;
  timeout: number;
  approvers: string[];
}

export interface Digest {
  from: string;
  to: string;
  totals: DigestTotals;
  servers: Array<{ server: string; calls: number; blocked: number }>;
  tools: DigestToolRow[];
  alerts: DigestAlert[];
  approvals: DigestApprovals;
  chain: Array<{ server: string; ok: boolean; entries: number }>;
  coverage?: DigestCoverage;
  highlights: string[];
}

function alertKind(e: AuditEntry): DigestAlert['kind'] | null {
  const reason = e.reason ?? '';
  if (reason.includes('secret_leak')) return 'secret_leak';
  if (reason.includes('injection_suspect')) return 'injection_suspect';
  if (e.decision === 'approve' && reason.includes('timed out')) return 'approval_timeout';
  if (e.decision === 'deny') return 'deny';
  return null;
}

/** 纯函数：把审计条目聚合成本地周报（不读文件、不联网） */
export function buildDigest(input: DigestInput[], opts: DigestOptions): Digest {
  const totals: DigestTotals = { calls: 0, allow: 0, approve: 0, deny: 0, ok: 0, error: 0, blocked: 0, recorded: 0 };
  const serverMap = new Map<string, { server: string; calls: number; blocked: number }>();
  const toolMap = new Map<string, DigestToolRow>();
  const alerts: DigestAlert[] = [];
  const approvals: DigestApprovals = { total: 0, approved: 0, denied: 0, timeout: 0, approvers: [] };
  const approverSet = new Set<string>();

  for (const { server, entries } of input) {
    for (const e of entries) {
      if (e.ts < opts.from || e.ts > opts.to) continue;
      totals.calls += 1;
      totals[e.decision] += 1;
      totals[e.outcome] += 1;
      if (e.enforced === false) totals.recorded += 1;

      const srv = serverMap.get(server) ?? { server, calls: 0, blocked: 0 };
      srv.calls += 1;
      if (e.outcome === 'blocked') srv.blocked += 1;
      serverMap.set(server, srv);

      const key = `${server}:${e.tool}`;
      const row = toolMap.get(key) ?? { server, tool: e.tool, calls: 0, blocked: 0, sensitive: 0 };
      row.calls += 1;
      if (e.outcome === 'blocked') row.blocked += 1;
      if ((e.reason ?? '').includes('secrets-input') || (e.reason ?? '').includes('secret_leak')) row.sensitive += 1;
      toolMap.set(key, row);

      const kind = alertKind(e);
      if (kind) {
        alerts.push({ ts: e.ts, server, tool: e.tool, kind, reason: e.reason ?? '' });
      }

      if (e.decision === 'approve') {
        approvals.total += 1;
        if (e.approver) approverSet.add(e.approver);
        if ((e.reason ?? '').includes('timed out')) approvals.timeout += 1;
        else if (e.outcome === 'blocked') approvals.denied += 1;
        else approvals.approved += 1;
      }
    }
  }
  approvals.approvers = [...approverSet].sort();

  const tools = [...toolMap.values()].sort((a, b) => b.calls - a.calls || a.tool.localeCompare(b.tool));
  const servers = [...serverMap.values()].sort((a, b) => b.calls - a.calls || a.server.localeCompare(b.server));
  const chain = opts.chain ?? [];

  const highlights: string[] = [];
  const secretLeaks = alerts.filter((a) => a.kind === 'secret_leak').length;
  const injections = alerts.filter((a) => a.kind === 'injection_suspect').length;
  const denies = alerts.filter((a) => a.kind === 'deny').length;
  if (totals.calls === 0) {
    highlights.push(t('本期没有工具调用记录'));
  } else if (denies === 0 && secretLeaks === 0 && injections === 0) {
    highlights.push(t('本期平静：{n} 次调用，无拦截、无泄漏、无注入信号', { n: totals.calls }));
  } else {
    if (denies > 0) highlights.push(t('拦截了 {n} 次被策略拒绝的调用', { n: denies }));
    if (secretLeaks > 0) highlights.push(t('拦下 {n} 次疑似密钥外泄', { n: secretLeaks }));
    if (injections > 0) highlights.push(t('标记 {n} 次疑似提示注入', { n: injections }));
  }
  if (approvals.total > 0) {
    highlights.push(
      t('{n} 次人工审批（批准 {approved}、拒绝 {denied}、超时 {timeout}）', {
        n: approvals.total,
        approved: approvals.approved,
        denied: approvals.denied,
        timeout: approvals.timeout,
      }),
    );
  }
  const broken = chain.filter((c) => !c.ok);
  if (broken.length > 0) {
    highlights.push(
      t('⚠️ {n} 个审计文件哈希链异常：{list}', {
        n: broken.length,
        list: broken.map((b) => b.server).join('、'),
      }),
    );
  }
  if (opts.coverage && opts.coverage.unmanaged.length > 0) {
    highlights.push(
      t('⚠️ 发现 {n} 个未受管 MCP server（可绕过网关）：{list}', {
        n: opts.coverage.unmanaged.length,
        list: opts.coverage.unmanaged.join('、'),
      }),
    );
  }

  return {
    from: opts.from,
    to: opts.to,
    totals,
    servers,
    tools,
    alerts,
    approvals,
    chain,
    coverage: opts.coverage,
    highlights,
  };
}

function pct(n: number, total: number): string {
  if (total === 0) return '0%';
  return `${Math.round((n / total) * 100)}%`;
}

export function renderDigest(d: Digest): string {
  const lines: string[] = [t('# pod 本地安全周报'), ''];
  lines.push(
    t('统计窗口：{from} → {to}', {
      from: d.from.slice(0, 19).replace('T', ' '),
      to: d.to.slice(0, 19).replace('T', ' '),
    }),
  );
  lines.push('');
  lines.push(t('## 本期结论'));
  lines.push('');
  if (d.highlights.length === 0) lines.push(t('- 暂无数据'));
  else for (const h of d.highlights) lines.push(`- ${h}`);
  lines.push('');

  lines.push(t('## 调用总览'));
  lines.push('');
  lines.push(t('| 指标 | 数量 |'));
  lines.push('|------|-----:|');
  lines.push(t('| 总调用 | {n} |', { n: d.totals.calls }));
  lines.push(`| allow | ${d.totals.allow} (${pct(d.totals.allow, d.totals.calls)}) |`);
  lines.push(`| approve | ${d.totals.approve} (${pct(d.totals.approve, d.totals.calls)}) |`);
  lines.push(`| deny | ${d.totals.deny} (${pct(d.totals.deny, d.totals.calls)}) |`);
  lines.push(`| ok / error / blocked | ${d.totals.ok} / ${d.totals.error} / ${d.totals.blocked} |`);
  lines.push(t('| record-only（未执法） | {n} |', { n: d.totals.recorded }));
  lines.push('');

  if (d.tools.length > 0) {
    lines.push(t('## 工具调用 Top'));
    lines.push('');
    lines.push(t('| server | tool | 调用 | 拦截 | 敏感 |'));
    lines.push('|--------|------|-----:|-----:|-----:|');
    for (const t of d.tools.slice(0, 10)) {
      lines.push(`| ${t.server} | ${t.tool} | ${t.calls} | ${t.blocked} | ${t.sensitive} |`);
    }
    lines.push('');
  }

  lines.push(t('## 审批与拦截'));
  lines.push('');
  lines.push(
    t('- 人工审批：{n} 次（批准 {approved} / 拒绝 {denied} / 超时 {timeout}）', {
      n: d.approvals.total,
      approved: d.approvals.approved,
      denied: d.approvals.denied,
      timeout: d.approvals.timeout,
    }),
  );
  lines.push(
    t('- 审批人：{list}', { list: d.approvals.approvers.length > 0 ? d.approvals.approvers.join('、') : '—' }),
  );
  lines.push(t('- 拦截/告警事件：{n} 条', { n: d.alerts.length }));
  for (const a of d.alerts.slice(0, 10)) {
    lines.push(`  - ${a.ts.slice(0, 19).replace('T', ' ')} [${a.kind}] ${a.server}.${a.tool} — ${a.reason.slice(0, 80)}`);
  }
  lines.push('');

  if (d.chain.length > 0) {
    lines.push(t('## 审计完整性'));
    lines.push('');
    for (const c of d.chain) {
      lines.push(
        t('- {server}.jsonl：{status}（{n} 条）', {
          server: c.server,
          status: c.ok ? t('✅ 哈希链完整') : t('❌ 哈希链异常'),
          n: c.entries,
        }),
      );
    }
    lines.push('');
  }

  if (d.coverage) {
    lines.push(t('## 受管覆盖率'));
    lines.push('');
    lines.push(
      t('- 已受管 server：{list}', {
        list: d.coverage.managed.length > 0 ? d.coverage.managed.join('、') : '—',
      }),
    );
    lines.push(
      t('- 未受管 server：{list}', {
        list: d.coverage.unmanaged.length > 0 ? d.coverage.unmanaged.join('、') : t('无'),
      }),
    );
    lines.push('');
  }

  lines.push('---');
  lines.push(t('pod digest 只读本地审计，不联网、不上传任何数据。'));
  lines.push('');
  return lines.join('\n');
}
