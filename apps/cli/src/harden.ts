/**
 * pod harden — 一次性加固审计的交付物（方向 A）。
 *
 * 这是一条**编排**命令，不是新能力：把已有四个部件
 *   pod scan（暴露面）+ pod posture（控制平面姿态）
 *   + pod policy draft（最小权限编译）+ pod export-evidence（证据包）
 * 汇成一份客户可交付的报告目录，并给出 manifest（每份产物 + sha256）。
 *
 * 为什么值得单独做一条命令：审计服务卖的是"一份可复核、可自证的报告"，
 * 而不是"你自己跑四条命令再把输出拼起来"。交付物的**边界**就是产品。
 *
 * 两条硬约束：
 * - 全程不出机器（D3）：所有事实本地采集，报告落本地目录，零上报；
 * - 报告里不出现密钥原文：scan 已做掩码，本模块再把前 8 位前缀一并丢掉
 *   （那份前缀留在 pod scan 的交互输出里够用了，不该进客户交付物）。
 */
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { sha256Hex, type AuditEntry } from '@podsec/audit';
import { renderMarkdown, scanMachine, type ScanResult } from '@podsec/scan';
import type { Policy, RuleSet, Severity } from '@podsec/policy';
import {
  exportEvidence,
  loadAllAuditFiles,
  renderVerifyReport,
  verifyAll,
  type VerifyResult,
} from './evidence.js';
import { draftPolicy, mostCommonAgent } from './policy-draft.js';
import { runPosture } from './control-plane.js';

export interface HardenOptions {
  /** 用户 home（scan 的发现器与 posture 的冻结项都相对它解析） */
  home: string;
  auditDir: string;
  policyDir: string;
  baselinePath: string;
  /** 当前生效的判定规则——报告要写明"这份结论是哪版规则算出来的" */
  rules: RuleSet;
  outDir: string;
  agent?: string;
  server?: string;
  /** 是否导出证据包（审计目录为空时自动跳过） */
  includeEvidence?: boolean;
  /** true = 把本次发现写进控制平面审计链（默认 false，与 pod posture 一致） */
  writeAudit?: boolean;
  now?: Date;
}

export interface HardenFinding {
  severity: Severity;
  /** 来自哪一层：scan 是静态暴露面，posture 是控制平面姿态 */
  source: 'scan' | 'posture';
  category: string;
  message: string;
  subject?: string;
  evidence?: string[];
}

export interface HardenSummary {
  high: number;
  medium: number;
  low: number;
  /** 发现的本机 agent 平台 */
  platforms: string[];
  mcpServers: number;
  exposedSecrets: number;
  auditChains: number;
  brokenChains: number;
  auditEntries: number;
  baselineMissing: boolean;
  draftedServers: number;
  draftedTools: number;
  rulesVersion: string;
}

export interface HardenArtifact {
  file: string;
  sha256: string;
  bytes: number;
}

export interface HardenResult {
  outDir: string;
  generatedAt: string;
  summary: HardenSummary;
  artifacts: HardenArtifact[];
  reportPath: string;
}

/** 报告里的机器可读部分：给客户的自查工具、也给下次审计做 diff */
export interface HardenFindingsFile {
  format: 'pod-harden-findings/v1';
  generatedAt: string;
  home: string;
  rulesVersion: string;
  findings: HardenFinding[];
  scan: {
    platforms: Array<{ platform: string; found: boolean; detail?: string }>;
    mcpServers: ScanResult['mcpServers'];
    secrets: Array<{ file: string; category: string; masked: string }>;
  };
  audits: VerifyResult[];
}

function collectFindings(scan: ScanResult, postureFindings: Array<{
  severity: Severity;
  category: string;
  message: string;
  subject: string;
  evidence?: string[];
}>): HardenFinding[] {
  const out: HardenFinding[] = [];
  for (const f of scan.findings) {
    out.push({ severity: f.severity, source: 'scan', category: 'scan', message: f.message });
  }
  for (const f of postureFindings) {
    out.push({
      severity: f.severity,
      source: 'posture',
      category: f.category,
      message: f.message,
      subject: f.subject,
      ...(f.evidence ? { evidence: f.evidence } : {}),
    });
  }
  const rank: Record<Severity, number> = { high: 0, medium: 1, low: 2 };
  return out.sort((a, b) => rank[a.severity] - rank[b.severity]);
}

/**
 * 把内嵌子报告的标题降两级：章节标题是 `##`，子报告标题落到 `###`、
 * 其内部小节落到 `####`——这样整份交付物只有一个一级标题，且层级是嵌套的
 * （降一级会让子报告标题与章节标题同级，读起来像并列章节）。
 * 跳过围栏代码块：里面的 `# 注释` 不是标题，降级会改坏示例。
 */
function demoteHeadings(md: string): string {
  let fenced = false;
  return md
    .split('\n')
    .map((line) => {
      if (/^\s*```/.test(line)) {
        fenced = !fenced;
        return line;
      }
      if (fenced) return line;
      return line.replace(/^(#{1,4}) /, '##$1 ');
    })
    .join('\n');
}

const SEVERITY_ICON: Record<Severity, string> = { high: '🔴', medium: '🟠', low: '🟡' };

export function renderHardenReport(input: {
  generatedAt: string;
  home: string;
  summary: HardenSummary;
  findings: HardenFinding[];
  scanReport: string;
  postureReport: string;
  draftReport: string | null;
  verifyReport: string;
  artifacts: HardenArtifact[];
}): string {
  const { summary, findings } = input;
  const lines: string[] = ['# pod 加固审计报告', ''];
  lines.push(`生成时间：${input.generatedAt}`);
  lines.push(`机器：${input.home}`);
  lines.push(`判定规则版本：${summary.rulesVersion}`);
  lines.push('');
  lines.push('> 本报告由 pod 在本机生成，采集与计算全程不出机器。');
  lines.push('> 所有结论都可追溯到具体事实与规则版本；报告附件的哈希见 §6。');
  lines.push('');

  lines.push('## 0. 摘要');
  lines.push('');
  lines.push('| 严重级别 | 数量 |');
  lines.push('|----------|-----:|');
  lines.push(`| 🔴 high | ${summary.high} |`);
  lines.push(`| 🟠 medium | ${summary.medium} |`);
  lines.push(`| 🟡 low | ${summary.low} |`);
  lines.push('');
  lines.push(
    `发现 agent 平台 ${summary.platforms.length} 个、MCP server ${summary.mcpServers} 个、` +
      `疑似暴露密钥 ${summary.exposedSecrets} 处；审计链 ${summary.auditChains} 条（${summary.auditEntries} 条记录），` +
      `其中断裂 ${summary.brokenChains} 条。`,
  );
  lines.push(
    summary.baselineMissing
      ? '⚠️ 尚未建立姿态基线：本次只能做静态判定，配置/记忆/钩子的**变更**类检查未生效——这是当前最大的可见性缺口。'
      : '✅ 已建立姿态基线：配置、记忆、钩子、包来源的漂移检查均已生效。',
  );
  lines.push('');

  lines.push('## 1. 结论与待办');
  lines.push('');
  if (findings.length === 0) {
    lines.push('未发现 high/medium/low 问题。');
  } else {
    const actionable = findings.filter((f) => f.severity !== 'low').slice(0, 15);
    lines.push(`按严重级别排序，优先处理以下 ${actionable.length} 项：`);
    lines.push('');
    lines.push('| 级别 | 来源 | 类别 | 问题 | 位置 |');
    lines.push('|------|------|------|------|------|');
    for (const f of actionable) {
      lines.push(
        `| ${SEVERITY_ICON[f.severity]} ${f.severity} | ${f.source} | \`${f.category}\` | ${f.message} | ${
          f.subject ? `\`${f.subject}\`` : '—'
        } |`,
      );
    }
    if (findings.length > actionable.length) {
      lines.push('');
      lines.push(`（其余 ${findings.length - actionable.length} 项见 \`findings.json\`）`);
    }
  }
  lines.push('');
  lines.push('### 建议的执行顺序');
  lines.push('');
  lines.push('```bash');
  lines.push('pod identity init --agent <agent>   # 1. 每个 agent 一个身份');
  lines.push('pod posture freeze                  # 2. 冻结当前姿态（此后任何变更都会报出来）');
  lines.push('pod serve --agent <a> --server <s> \\');
  lines.push('  --policy <draft> --policy-signature <sig>   # 3. 用编译出的最小权限策略接管流量');
  lines.push('pod posture --strict                # 4. 挂进 CI / 定时任务，漂移即退出码非 0');
  lines.push('pod rules pull --url <pack> --key <pub.pem>   # 5. 订阅规则更新（放宽守卫默认拦截）');
  lines.push('pod quarantine add --agent <agent>  # 出事时熔断，网关下一次调用即生效');
  lines.push('```');
  lines.push('');

  lines.push('## 2. 暴露面（静态扫描）');
  lines.push('');
  lines.push(demoteHeadings(input.scanReport));
  lines.push('');

  lines.push('## 3. 控制平面姿态');
  lines.push('');
  lines.push(demoteHeadings(input.postureReport));
  lines.push('');

  lines.push('## 4. 最小权限策略建议');
  lines.push('');
  if (input.draftReport) {
    lines.push(demoteHeadings(input.draftReport));
  } else {
    lines.push('审计目录为空，无法从真实行为编译最小权限策略。');
    lines.push('');
    lines.push('先采集语料：`pod record --config <mcp-manager.json> --server <name>`，');
    lines.push('日常使用一段时间后再跑 `pod harden`——**没有语料的策略只是猜测**。');
  }
  lines.push('');

  lines.push('## 5. 证据与可验证性');
  lines.push('');
  lines.push(demoteHeadings(input.verifyReport));
  lines.push('');

  lines.push('## 6. 产物清单');
  lines.push('');
  lines.push('| 文件 | 字节 | sha256 |');
  lines.push('|------|-----:|--------|');
  for (const a of input.artifacts) {
    lines.push(`| \`${a.file}\` | ${a.bytes} | \`${a.sha256.slice(0, 16)}…\` |`);
  }
  lines.push('');
  lines.push('完整哈希见 `manifest.json`。校验方式：对同名文件重算 sha256 比对。');
  lines.push('');
  return lines.join('\n');
}

/** 从审计目录编译策略草稿；无记录时返回 null（不编空策略骗人） */
function buildDraft(opts: HardenOptions): ReturnType<typeof draftPolicy> | null {
  const byServer = new Map<string, AuditEntry[]>();
  for (const file of loadAllAuditFiles(opts.auditDir)) {
    for (const e of file.log.entries) {
      if (opts.server && e.server !== opts.server) continue;
      const list = byServer.get(e.server);
      if (list) list.push(e);
      else byServer.set(e.server, [e]);
    }
  }
  const rows = [...byServer.entries()].map(([server, entries]) => ({ server, entries }));
  if (rows.length === 0) return null;
  const agent = opts.agent ?? mostCommonAgent(rows) ?? 'local';
  return draftPolicy(rows, { agent });
}

/** 草稿里覆盖的工具数（allow + approve + deny），用来回答"这份策略管住了多少东西" */
function countDraftedTools(policy: Policy): number {
  let total = 0;
  for (const sp of Object.values(policy.servers ?? {})) {
    total += (sp.allow?.length ?? 0) + (sp.approve?.length ?? 0) + (sp.deny?.length ?? 0);
  }
  return total;
}

export function runHarden(opts: HardenOptions): HardenResult {
  const now = opts.now ?? new Date();
  const generatedAt = now.toISOString();
  mkdirSync(opts.outDir, { recursive: true });

  const scan = scanMachine({ home: opts.home });
  // 先写审计（可选）再校验，否则本次审计事件不在自检范围里
  const posture = runPosture({
    rules: opts.rules,
    auditDir: opts.auditDir,
    baselinePath: opts.baselinePath,
    home: opts.home,
    now,
    writeAudit: opts.writeAudit === true,
  });
  const audits = verifyAll(opts.auditDir);
  const draft = buildDraft(opts);
  const findings = collectFindings(scan, posture.result.findings);
  const summary: HardenSummary = {
    high: findings.filter((f) => f.severity === 'high').length,
    medium: findings.filter((f) => f.severity === 'medium').length,
    low: findings.filter((f) => f.severity === 'low').length,
    platforms: scan.agents.filter((a) => a.found).map((a) => a.platform),
    mcpServers: scan.mcpServers.length,
    exposedSecrets: scan.secrets.length,
    auditChains: audits.length,
    brokenChains: audits.filter((a) => !a.ok).length,
    auditEntries: audits.reduce((sum, a) => sum + a.entries, 0),
    baselineMissing: posture.result.baselineMissing,
    draftedServers: draft ? Object.keys(draft.policy.servers ?? {}).length : 0,
    draftedTools: draft ? countDraftedTools(draft.policy) : 0,
    rulesVersion: opts.rules.version,
  };

  const findingsFile: HardenFindingsFile = {
    format: 'pod-harden-findings/v1',
    generatedAt,
    home: opts.home,
    rulesVersion: opts.rules.version,
    findings,
    scan: {
      platforms: scan.agents,
      mcpServers: scan.mcpServers,
      // 只留掩码：客户交付物里不该出现密钥前缀
      secrets: scan.secrets.map((s) => ({ file: s.file, category: s.category, masked: s.masked })),
    },
    audits,
  };

  const written: HardenArtifact[] = [];
  const write = (name: string, content: string): void => {
    writeFileSync(join(opts.outDir, name), content, 'utf8');
    written.push({ file: name, sha256: sha256Hex(content), bytes: Buffer.byteLength(content, 'utf8') });
  };

  write('findings.json', JSON.stringify(findingsFile, null, 2) + '\n');
  if (draft) write('policy-draft.json', JSON.stringify(draft.policy, null, 2) + '\n');

  let evidenceNote = '';
  if (opts.includeEvidence !== false && audits.length > 0) {
    const evidencePath = join(opts.outDir, 'evidence.json');
    exportEvidence({ auditDir: opts.auditDir, policyDir: opts.policyDir, outPath: evidencePath });
    const content = readFileSync(evidencePath, 'utf8');
    written.push({
      file: 'evidence.json',
      sha256: sha256Hex(content),
      bytes: Buffer.byteLength(content, 'utf8'),
    });
  } else if (audits.length === 0) {
    evidenceNote = '（审计目录为空，未导出证据包——**没有记录就没有可证明的历史**）';
  }

  const verifyReport =
    (audits.length === 0
      ? '# 审计完整性自检\n\n（审计目录为空）'
      : renderVerifyReport(audits, opts.auditDir)) + (evidenceNote ? `\n\n${evidenceNote}` : '');
  const report = renderHardenReport({
    generatedAt,
    home: opts.home,
    summary,
    findings,
    scanReport: renderMarkdown(scan),
    postureReport: posture.report,
    draftReport: draft ? draft.report : null,
    verifyReport,
    artifacts: written,
  });

  const reportName = 'report.md';
  writeFileSync(join(opts.outDir, reportName), report, 'utf8');
  const artifacts: HardenArtifact[] = [
    ...written,
    { file: reportName, sha256: sha256Hex(report), bytes: Buffer.byteLength(report, 'utf8') },
  ];

  // manifest 列的是"除自己以外"的产物，所以最后写、且不进自己的清单
  const manifest = {
    format: 'pod-harden-manifest/v1',
    generatedAt,
    home: opts.home,
    rulesVersion: opts.rules.version,
    summary,
    artifacts,
  };
  write('manifest.json', JSON.stringify(manifest, null, 2) + '\n');

  return {
    outDir: opts.outDir,
    generatedAt,
    summary,
    artifacts: written,
    reportPath: join(opts.outDir, reportName),
  };
}
