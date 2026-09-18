/**
 * 漏洞清单 + 建议清单的渲染。
 *
 * 报表的两条纪律（与 PRODUCT.md 一致）：
 * 1. **证据优先**：每条漏洞都带证据（文件、命令行、变量名），不出现无出处的判断；
 * 2. **说清楚不夸大**：每条建议都标注 pod 对这类威胁的覆盖程度；
 *    做不到的写在"覆盖边界"里，不用一句"已加固"盖过去。
 */
import { t } from '@podsec/i18n';
import type { Severity } from '@podsec/policy';
import {
  THREAT_BY_ID,
  THREAT_CATALOG as THREAT_CATALOG_ALL,
  type GuardCategory,
  type ThreatEntry,
} from './catalog.js';
import type { Finding, GuardReport, RemediationItem } from './types.js';
import { SEVERITY_ORDER } from './types.js';

export const SEVERITY_ICON: Record<Severity, string> = { high: '🔴', medium: '🟠', low: '🟡' };

/**
 * 类别的可读名。
 *
 * 刻意写成 switch 里的字面量而不是查表常量：i18n 覆盖率脚本按**字面量**找
 * `t(...)` 调用，走变量它看不见，于是这些词条会被报成"僵尸键"。
 */
export function categoryLabel(category: GuardCategory): string {
  switch (category) {
    case 'credential':
      return t('凭据暴露');
    case 'execution':
      return t('代码执行');
    case 'boundary':
      return t('边界与闸门');
    case 'network':
      return t('网络暴露');
    case 'supply-chain':
      return t('供应链');
    case 'permission':
      return t('权限与审批');
    case 'memory':
      return t('记忆完整性');
    case 'identity':
      return t('身份与归因');
    case 'visibility':
      return t('可见性与证据');
    default:
      // 兜底：新增类别忘了补文案时显示原值，不制造空白
      return category;
  }
}

/** 同一类问题在报表里最多展开这么多条，其余指向 JSON（清单要能一屏读完） */
const MAX_PER_THREAT = 5;

function groupBy<T, K>(items: T[], keyOf: (item: T) => K): Array<[K, T[]]> {
  const map = new Map<K, T[]>();
  for (const item of items) {
    const key = keyOf(item);
    const list = map.get(key);
    if (list) list.push(item);
    else map.set(key, [item]);
  }
  return [...map.entries()];
}

/**
 * 把 findings 折叠成建议清单：**一条建议消掉一类问题**。
 * 用户要处理的是"要做什么"，不是逐条告警——按 finding 逐条给建议会让人放弃。
 */
export function buildRemediations(findings: Finding[]): RemediationItem[] {
  const groups = new Map<string, Finding[]>();
  for (const item of findings) {
    const list = groups.get(item.threat);
    if (list) list.push(item);
    else groups.set(item.threat, [item]);
  }
  const items: RemediationItem[] = [];
  const worstByThreat = new Map<string, Severity>();
  for (const [threat, list] of groups) {
    const entry: ThreatEntry | undefined = THREAT_BY_ID[threat];
    if (!entry) continue;
    const worst = list.reduce<Severity>(
      (acc, cur) => (SEVERITY_ORDER[cur.severity] < SEVERITY_ORDER[acc] ? cur.severity : acc),
      'low',
    );
    const item: RemediationItem = {
      threat,
      affects: [...new Set(list.map((f) => f.harness))].sort(),
      priority: 0,
      action: entry.remediation.action,
      why: entry.remediation.why,
      automation: entry.remediation.automation,
      coverage: entry.coverage,
      count: list.length,
    };
    if (entry.remediation.command) item.command = entry.remediation.command;
    // 最严重级别只用于排序，不进对外结构（RemediationItem 里没有这个字段）
    worstByThreat.set(threat, worst);
    items.push(item);
  }
  items.sort(
    (a, b) =>
      SEVERITY_ORDER[worstByThreat.get(a.threat) ?? 'low'] - SEVERITY_ORDER[worstByThreat.get(b.threat) ?? 'low'] ||
      b.count - a.count ||
      a.threat.localeCompare(b.threat),
  );
  items.forEach((item, index) => {
    item.priority = index + 1;
  });
  return items;
}

function refsBlock(entries: ThreatEntry[]): string[] {
  const lines: string[] = [];
  for (const entry of entries) {
    lines.push(`- **${entry.id} ${entry.title}**（OWASP ${entry.asi.join('、')}${entry.localThreats.length > 0 ? ` · 威胁模型 ${entry.localThreats.join('/')}` : ''}）`);
    for (const ref of entry.refs) {
      lines.push(`  - [${ref.id}](${ref.url}) — ${ref.by}`);
    }
  }
  return lines;
}

export function renderGuardReport(report: GuardReport): string {
  const lines: string[] = [t('# pod guard — 多 agent / 多 harness 漏洞扫描'), ''];
  lines.push(t('生成时间：{ts}', { ts: report.generatedAt }));
  lines.push(t('机器：{home}', { home: report.home }));
  lines.push('');
  lines.push(t('> 只读扫描：不联网、不上传、不修改任何文件。判定规则来自你的 rules.json。'));
  lines.push('');

  // ---------- 0 概览 ----------
  lines.push(t('## 0. 概览'));
  lines.push('');
  const high = report.findings.filter((f) => f.severity === 'high').length;
  const medium = report.findings.filter((f) => f.severity === 'medium').length;
  const low = report.findings.filter((f) => f.severity === 'low').length;
  lines.push(t('| 严重级别 | 数量 |'));
  lines.push('|----------|-----:|');
  lines.push(`| 🔴 high | ${high} |`);
  lines.push(`| 🟠 medium | ${medium} |`);
  lines.push(`| 🟡 low | ${low} |`);
  lines.push('');
  lines.push(
    t('扫描范围：{harnesses} 个 harness（{installed} 个已安装）、{servers} 个 MCP server、{hooks} 个钩子、{secrets} 处明文凭据、{projects} 个工作区。', {
      harnesses: report.scanned.harnesses,
      installed: report.scanned.installedHarnesses,
      servers: report.scanned.servers,
      hooks: report.scanned.hooks,
      secrets: report.scanned.secrets,
      projects: report.scanned.projects,
    }),
  );
  lines.push(
    t('覆盖声明：{automated} 类有确定性判定、{partial} 类只能给信号、{gap} 类 pod 看不到（见 §4）。', {
      automated: report.coverage.automated,
      partial: report.coverage.partial,
      gap: report.coverage.gap,
    }),
  );
  lines.push('');
  if (report.findings.length === 0) {
    lines.push(t('本轮没有发现可判定的问题。注意这不等于"安全"——§4 列了 pod 看不到的那部分。'));
    lines.push('');
  }

  // ---------- 1 漏洞清单 ----------
  lines.push(t('## 1. 漏洞清单'));
  lines.push('');
  if (report.findings.length === 0) {
    lines.push(t('（空）'));
    lines.push('');
  } else {
    const bySeverity: Array<[Severity, string]> = [
      ['high', '🔴 high — 现在就该处理'],
      ['medium', '🟠 medium — 本周处理'],
      ['low', '🟡 low — 记录在案'],
    ];
    for (const [severity, heading] of bySeverity) {
      const list = report.findings.filter((f) => f.severity === severity);
      if (list.length === 0) continue;
      lines.push(`### ${heading}（${list.length}）`);
      lines.push('');
      // 按威胁分组：同一类问题（比如 20 个 server 都没走网关）读成一条，
      // 逐条平铺会让清单在第一屏就失去可读性。
      for (const [threat, group] of groupBy(list, (f) => f.threat)) {
        const entry = THREAT_BY_ID[threat];
        lines.push(
          `#### ${threat}${entry ? ` ${entry.title}` : ''} · \`${categoryLabel(group[0]!.category)}\`（${group.length} 处）`,
        );
        lines.push('');
        const shown = group.slice(0, MAX_PER_THREAT);
        for (const item of shown) {
          lines.push(`- \`${item.harness}\` · \`${item.subject}\``);
          lines.push(`  ${item.message}`);
          for (const evidence of item.evidence.slice(0, 3)) {
            lines.push(`  - 证据：\`${evidence}\``);
          }
        }
        if (group.length > shown.length) {
          lines.push('');
          lines.push(t('（其余 {n} 处见 guard-findings.json）', { n: group.length - shown.length }));
        }
        lines.push('');
      }
    }
  }

  // ---------- 2 建议清单 ----------
  lines.push(t('## 2. 建议清单（按优先级）'));
  lines.push('');
  if (report.remediations.length === 0) {
    lines.push(t('（没有需要处理的项）'));
    lines.push('');
  } else {
    for (const item of report.remediations) {
      const entry = THREAT_BY_ID[item.threat];
      lines.push(
        `### ${item.priority}. ${item.action}`,
      );
      lines.push('');
      lines.push(
        t('对应威胁：`{threat}`{title} · 影响 {count} 处 · harness：{affects}', {
          threat: item.threat,
          title: entry ? ` ${entry.title}` : '',
          count: item.count,
          affects: item.affects.join('、') || '—',
        }),
      );
      lines.push(t('为什么：{why}', { why: item.why }));
      lines.push(
        item.coverage === 'covered'
          ? t('pod 覆盖：有确定性判定 + 有执行点——处理完这类问题就消失了。')
          : item.coverage === 'partial'
            ? t('pod 覆盖：能发现，但拦不住（缺口见 §4）。')
            : t('pod 覆盖：pod 看不到这类问题，只能靠人工与外部工具。'),
      );
      if (item.command) {
        lines.push('');
        lines.push('```bash');
        lines.push(item.command);
        lines.push('```');
      }
      if (item.automation === 'proposal') {
        lines.push(t('可以让模型生成加固建议物：`pod guard remediate --llm`（建议物不自动生效，先过放宽守卫）。'));
      }
      lines.push('');
    }
  }

  // ---------- 3 下一步 ----------
  lines.push(t('## 3. 让扫描持续跑起来'));
  lines.push('');
  lines.push('```bash');
  lines.push(t('pod guard baseline            # 把当前状态冻结为基线（此后只对新增/变化报警）'));
  lines.push(t('pod guard watch --interval 300  # 每 5 分钟扫一轮，有变化就写进审计链'));
  lines.push(t('pod guard scan --strict       # high 时退出码 1，可直接挂 CI / 定时任务'));
  lines.push('```');
  lines.push('');

  // ---------- 4 覆盖边界与出处 ----------
  lines.push(t('## 4. 覆盖边界与出处'));
  lines.push('');
  const triggered = [...new Set(report.findings.map((f) => f.threat))];
  const catalogEntries = triggered.map((id) => THREAT_BY_ID[id]).filter((e): e is ThreatEntry => Boolean(e));
  const partial = catalogEntries.filter((e) => e.coverage === 'partial');
  // AG-18（无沙箱）是结构性的：只要这台机器上有 MCP server 就成立，不依赖本轮是否触发
  const gapEntries = new Map<string, ThreatEntry>();
  if (report.scanned.servers > 0 && THREAT_BY_ID['AG-18']) gapEntries.set('AG-18', THREAT_BY_ID['AG-18']);
  for (const entry of catalogEntries.filter((e) => e.coverage === 'gap')) gapEntries.set(entry.id, entry);
  const gaps = [...gapEntries.values()];
  if (partial.length > 0) {
    lines.push(t('**能发现但拦不住（缺口必须说清楚）**'));
    lines.push('');
    for (const entry of partial) {
      lines.push(`- ${entry.id} ${entry.title}：${entry.gap ?? ''}`);
    }
    lines.push('');
  }
  if (gaps.length > 0) {
    lines.push(t('**pod 看不到的**'));
    lines.push('');
    for (const entry of gaps) {
      lines.push(`- ${entry.id} ${entry.title}：${entry.gap ?? ''}`);
    }
    lines.push('');
  }
  lines.push(t('**触发到的威胁与出处**'));
  lines.push('');
  if (catalogEntries.length === 0) {
    lines.push(t('（本轮没有触发任何目录条目）'));
  } else {
    lines.push(...refsBlock(catalogEntries));
  }
  lines.push('');
  if (report.notes.length > 0) {
    lines.push(t('**采集说明**'));
    lines.push('');
    for (const note of report.notes) lines.push(`- ${note}`);
    lines.push('');
  }
  lines.push('---');
  lines.push(t('pod guard 只读、不联网、不上传任何数据。'));
  lines.push('');
  return lines.join('\n');
}

/** 机器可读的清单：给 CI / 控制台 / 云端消费，字段与 GuardReport 同源 */
export function guardReportJson(report: GuardReport): string {
  return JSON.stringify(report, null, 2) + '\n';
}

/**
 * 威胁目录的可读版：`pod guard catalog`。
 * 目录是"我们声称懂什么"的公开清单，所以它必须能被单独读一遍——
 * 包括每条的外部出处，和 pod 到底覆盖到哪。
 */
export function renderThreatCatalog(entries: ThreatEntry[] = THREAT_CATALOG_ALL): string {
  const lines: string[] = [t('# pod guard 威胁目录'), ''];
  lines.push(t('> 每条都对应一个可自动执行的检测器，并带上可核查的外部出处。'));
  lines.push('');
  lines.push(t('| 编号 | 严重级别 | 类别 | 覆盖 | 标题 |'));
  lines.push('|------|----------|------|------|------|');
  for (const entry of entries) {
    lines.push(
      `| ${entry.id} | ${SEVERITY_ICON[entry.severity]} ${entry.severity} | ${categoryLabel(entry.category)} | ${entry.coverage} | ${entry.title} |`,
    );
  }
  lines.push('');
  for (const entry of entries) {
    lines.push(`## ${entry.id} ${entry.title}`);
    lines.push('');
    lines.push(entry.summary);
    lines.push('');
    lines.push(
      t('OWASP：{asi} · 威胁模型：{local} · pod 覆盖：{coverage}', {
        asi: entry.asi.join('、'),
        local: entry.localThreats.join('/') || '—',
        coverage: entry.coverage,
      }),
    );
    lines.push('');
    if (entry.existingControls?.length) {
      lines.push(t('已有防线：'));
      lines.push('');
      for (const control of entry.existingControls) lines.push(`- ${control}`);
      lines.push('');
    }
    if (entry.gap) {
      lines.push(t('缺口：{gap}', { gap: entry.gap }));
      lines.push('');
    }
    lines.push(t('建议：{action}', { action: entry.remediation.action }));
    lines.push(t('理由：{why}', { why: entry.remediation.why }));
    lines.push('');
    lines.push(t('出处：'));
    lines.push('');
    for (const ref of entry.refs) lines.push(`- [${ref.id}](${ref.url}) — ${ref.by}`);
    lines.push('');
  }
  return lines.join('\n');
}
