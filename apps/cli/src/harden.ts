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
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { sha256Hex, type AuditEntry } from '@podsec/audit';
import { t } from '@podsec/i18n';
import { renderMarkdown, scanMachine, type ScanResult } from '@podsec/scan';
import type { Policy, RuleSet, Severity } from '@podsec/policy';
import {
  buildFunnelPlan,
  findingsLabel,
  paren,
  renderGuardReport,
  runGuardScan,
  type GuardReport,
} from '@podsec/guard';
import {
  exportEvidence,
  loadAllAuditFiles,
  renderVerifyReport,
  verifyAll,
  type VerifyResult,
} from './evidence.js';
import { draftPolicy, mostCommonAgent } from './policy-draft.js';
import { runPosture } from './control-plane.js';

/**
 * 交付元信息：审计服务的交付物必须能回答"这是给谁、谁出的、哪一单"。
 * 三个字段都可选——没有它们报告照常生成，只是封面少一行。
 */
export interface HardenEngagement {
  /** 交付对象（客户名 / 团队名） */
  client?: string;
  /** 出具方（审计执行人 / 服务方） */
  auditor?: string;
  /** 报告编号 / 工单号，用于同一个客户多次审计时做区分 */
  engagementId?: string;
}

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
  /** 交付元信息（客户 / 出具方 / 报告编号） */
  engagement?: HardenEngagement;
  now?: Date;
}

export interface HardenFinding {
  severity: Severity;
  /** 来自哪一层：scan 是静态暴露面，posture 是控制平面姿态，guard 是多 harness 扫描 */
  source: 'scan' | 'posture' | 'guard';
  category: string;
  message: string;
  subject?: string;
  evidence?: string[];
  /** guard 类发现带威胁编号，便于和威胁目录对上 */
  threat?: string;
  /** 可直接复制执行的处置命令（来自 guard 的下一步映射） */
  command?: string;
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
  /** 多 harness 扫描的发现数（guard 层） */
  harnessFindings: number;
  /** 扫了多少类 harness / 其中装了多少类 */
  harnessesScanned: number;
  installedHarnesses: number;
  /** 扫描到但没纳管的 harness 数 */
  unmanagedHarnesses: number;
  /** 报告目录里记录了多少条真实调用语料 */
  corpusEntries: number;
  /**
   * 覆盖声明：能确定性判定 / 只能给信号 / pod 看不到。
   * 交付物里必须写清楚这三类各有多少——"看不到"比"看起来干净"重要。
   */
  coverage: { automated: number; partial: number; gap: number };
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
  /** 交付元信息（有则写入，便于客户归档时与本单对上） */
  engagement?: HardenEngagement;
  findings: HardenFinding[];
  scan: {
    platforms: Array<{ platform: string; found: boolean; detail?: string }>;
    mcpServers: ScanResult['mcpServers'];
    secrets: Array<{ file: string; category: string; masked: string }>;
  };
  /** 多 harness 扫描的机器可读清单（完整版写进 harness-scan.json） */
  harness: {
    harnesses: number;
    installedHarnesses: number;
    unmanagedHarnesses: string[];
    hooks: number;
    servers: number;
    projects: number;
  };
  audits: VerifyResult[];
}

function collectFindings(
  scan: ScanResult,
  postureFindings: Array<{
    severity: Severity;
    category: string;
    message: string;
    subject: string;
    evidence?: string[];
  }>,
  guard: GuardReport,
  home: string,
): HardenFinding[] {
  const out: HardenFinding[] = [];
  // guard 的发现同时带上威胁编号与"下一步命令"：客户看的是一份待办，
  // 不是一份需要自己去查文档的清单。
  // guard 先收：同一处问题被多层各报一次时（钩子既在 posture 也在 harness 扫描里），
  // 保留信息量更大的那条——guard 带 AG 编号和处置命令。
  for (const f of guard.findings) {
    const remediation = guard.remediations.find((r) => r.threat === f.threat);
    out.push({
      severity: f.severity,
      source: 'guard',
      category: f.category,
      message: f.message,
      subject: `${f.harness} · ${f.subject}`,
      threat: f.threat,
      evidence: f.evidence,
      ...(remediation?.command ? { command: remediation.command } : {}),
    });
  }
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
  // 稳定排序：同级别时保持 guard → scan → posture 的收集顺序，去重才不会把
  // 信息量大的那条丢掉
  return dedupeAcrossLayers(out, home).sort((a, b) => rank[a.severity] - rank[b.severity]);
}

/** 把证据里指向同一个文件（含 `~` 缩写与 `#序号` 后缀差别）的写法归一 */
function normalizeEvidence(text: string, home: string): string {
  return text.replace(home, '~').replace(/#\d+$/, '').replace(/\s+/g, ' ').trim();
}

/** 抽出证据 / 位置 / 描述里出现的路径 token（`~/...` 或 `/...`） */
function pathTokens(finding: HardenFinding, home: string): string[] {
  const texts = [...(finding.evidence ?? []), finding.subject ?? '', finding.message];
  const tokens = new Set<string>();
  for (const text of texts) {
    const normalized = normalizeEvidence(text, home);
    for (const match of normalized.match(/(?:~|\/)[^\s,，、（）()#：:]*/g) ?? []) {
      const token = match.replace(/[.;]+$/, '');
      if (/[/\\]/.test(token) || /\.(json|jsonc|toml|ya?ml|md)$/i.test(token)) tokens.add(token);
    }
  }
  return [...tokens];
}

/**
 * scan / posture 的哪类发现会和 guard 的哪条威胁指同一处问题。
 *
 * 只按"路径相同"去重会把不同问题合掉（同一个 `~/.claude.json` 上既可能缺版本锁定、
 * 又可能是影子 agent），所以必须同时限定威胁类别。映射之外的发现一律不合并——
 * 宁可让客户多看到一条，也不能让一条真问题被悄悄吞掉。
 */
const CROSS_LAYER_THREATS: Record<string, { threats: string[]; requires?: RegExp }> = {
  'posture:hook': { threats: ['AG-05'] },
  'posture:memory': { threats: ['AG-07'] },
  'posture:config': { threats: ['AG-12'] },
  'posture:package': { threats: ['AG-02', 'AG-14'] },
  'posture:audit': { threats: ['AG-16'] },
  'posture:identity': { threats: ['AG-10'] },
  // scan 只有明文凭据这一条会与 guard 重叠（消息里一定带"明文"）
  'scan:scan': { threats: ['AG-01'], requires: /明文/ },
};

/**
 * 跨层去重：同一个钩子会被 posture 和 guard 各报一次，同一个明文密钥可能被
 * scan 和 guard 各报一次。交付物里同一处问题出现两遍，客户会以为问题更多、
 * 或者以为服务方没做整理。
 *
 * 入参必须按 guard → scan → posture 收集：保留先出现的那条（guard 带 AG 编号
 * 与可执行命令，信息量最大）。
 */
function dedupeAcrossLayers(findings: HardenFinding[], home: string): HardenFinding[] {
  const kept: HardenFinding[] = [];
  for (const finding of findings) {
    const mapping = CROSS_LAYER_THREATS[`${finding.source}:${finding.category}`];
    if (mapping && (!mapping.requires || mapping.requires.test(finding.message))) {
      const tokens = new Set(pathTokens(finding, home));
      const duplicate = kept.some(
        (other) =>
          other.source === 'guard' &&
          other.severity === finding.severity &&
          mapping.threats.includes(other.threat ?? '') &&
          pathTokens(other, home).some((token) => tokens.has(token)),
      );
      if (duplicate) continue;
    }
    kept.push(finding);
  }
  return kept;
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
  engagement?: HardenEngagement;
  summary: HardenSummary;
  findings: HardenFinding[];
  guardReport: GuardReport;
  scanReport: string;
  postureReport: string;
  draftReport: string | null;
  verifyReport: string;
  artifacts: HardenArtifact[];
}): string {
  const { summary, findings } = input;
  const plan = buildFunnelPlan(input.guardReport);
  const lines: string[] = [t('# pod 加固审计报告'), ''];

  // ---------- 封面：谁给谁、哪一单、哪一版 ----------
  lines.push('| | |');
  lines.push('|------|------|');
  if (input.engagement?.client) lines.push(`| ${t('交付对象')} | ${input.engagement.client} |`);
  if (input.engagement?.auditor) lines.push(`| ${t('出具方')} | ${input.engagement.auditor} |`);
  if (input.engagement?.engagementId) lines.push(`| ${t('报告编号')} | ${input.engagement.engagementId} |`);
  lines.push(`| ${t('生成时间')} | ${input.generatedAt} |`);
  lines.push(`| ${t('机器')} | ${input.home} |`);
  lines.push(`| ${t('判定规则版本')} | ${summary.rulesVersion} |`);
  lines.push('');
  lines.push(t('> 本报告由 pod 在本机生成，采集与计算全程不出机器。'));
  lines.push(t('> 所有结论都可追溯到具体事实与规则版本；报告附件的 sha256 见 §10，可用 `pod harden --verify <目录>` 独立复验。'));
  lines.push('');

  // ---------- 0 执行摘要 ----------
  lines.push(t('## 0. 执行摘要'));
  lines.push('');
  lines.push(...renderExecutiveSummary({ summary, plan, findings }));

  // ---------- 1 范围与方法 ----------
  lines.push(t('## 1. 范围与方法'));
  lines.push('');
  lines.push(t('这次审计读了什么：本机（{home}）上各个 agent harness 的配置文件、项目级 MCP 配置、生命周期钩子、长期记忆文件与 MCP server 启动命令。', { home: input.home }));
  lines.push(t('怎么得出结论的：只读采集事实 → 按你的规则版本（{version}）做确定性判定 → 从真实调用语料编译最小权限策略 → 对审计链做完整性校验。全程不联网、不上传、不修改被审计的配置。', { version: summary.rulesVersion }));
  lines.push('');
  lines.push(t('本报告的边界（先读这一段再看结论）：'));
  lines.push('');
  lines.push(t('- 这是**某个时点**的快照。没有建立姿态基线时，配置/钩子/记忆的变更类判定不生效。'));
  lines.push(t('- 没有真实调用语料时，§7 的策略只是从静态事实推断的草稿，不是最小权限。'));
  lines.push(t('- pod 不做沙箱隔离，也看不到 harness 进程内部的推理与对话；§3 写清了看不到的那部分。'));
  lines.push('');
  lines.push(t('复现这次审计：'));
  lines.push('');
  lines.push('```bash');
  lines.push(t('pod harden --out <目录>          # 重跑一次，产出与本次同构的报告'));
  lines.push(t('pod harden --verify <目录>       # 校验已交付的报告包有没有被改动'));
  lines.push('```');
  lines.push('');

  // ---------- 2 结论与待办 ----------
  lines.push(t('## 2. 结论与待办'));
  lines.push('');
  if (findings.length === 0) {
    lines.push(t('本轮没有可判定的问题。**这不等于"安全"**——§3 列了 pod 看不到的部分。'));
    lines.push('');
  } else {
    const actionable = findings.filter((f) => f.severity !== 'low').slice(0, 15);
    lines.push(t('按严重级别排序，共 {total} 条；先处理以下 {n} 条：', { total: findings.length, n: actionable.length }));
    lines.push('');
    lines.push(t('| 级别 | 来源 | 类别 | 问题 | 位置 |'));
    lines.push('|------|------|------|------|------|');
    for (const f of actionable) {
      lines.push(
        `| ${SEVERITY_ICON[f.severity]} ${f.severity} | ${f.source} | \`${f.category}\`${f.threat ? ` ${f.threat}` : ''} | ${f.message} | ${
          f.subject ? `\`${f.subject}\`` : '—'
        } |`,
      );
    }
    if (findings.length > actionable.length) {
      lines.push('');
      lines.push(t('（其余 {n} 项见 `findings.json`）', { n: findings.length - actionable.length }));
    }
  }
  lines.push('');
  lines.push(...renderTodoList(plan));
  lines.push(t('### 建议的执行顺序'));
  lines.push('');
  lines.push('```bash');
  lines.push(t('pod identity init --agent <agent>   # 1. 每个 agent 一个身份'));
  lines.push(t('pod posture freeze                  # 2. 冻结当前姿态（此后任何变更都会报出来）'));
  lines.push('pod serve --agent <a> --server <s> \\');
  lines.push(t('  --policy <draft> --policy-signature <sig>   # 3. 用编译出的最小权限策略接管流量'));
  lines.push(t('pod posture --strict                # 4. 挂进 CI / 定时任务，漂移即退出码非 0'));
  lines.push(t('pod rules pull --url <pack> --key <pub.pem>   # 5. 订阅规则更新（放宽守卫默认拦截）'));
  lines.push(t('pod quarantine add --agent <agent>  # 出事时熔断，网关下一次调用即生效'));
  lines.push('```');
  lines.push('');

  // ---------- 3 覆盖边界 ----------
  lines.push(t('## 3. 覆盖边界（本报告不能证明什么）'));
  lines.push('');
  lines.push(t('威胁目录共 {total} 类：有确定性判定 {automated} 类、只能给信号 {partial} 类、pod 看不到 {gap} 类。本机触发到的部分见 §5 的覆盖边界小节。', {
    total: summary.coverage.automated + summary.coverage.partial + summary.coverage.gap,
    automated: summary.coverage.automated,
    partial: summary.coverage.partial,
    gap: summary.coverage.gap,
  }));
  lines.push('');
  lines.push(t('- **不能替代沙箱**：pod 在工具边界与配置层做判定，不做进程隔离。'));
  lines.push(t('- **看不到 harness 进程内部**：钩子在 harness 里直接执行、项目级配置自动加载、`--dangerously-skip-permissions` 这类开关，pod 能发现与取证，拦不住。'));
  lines.push(t('- **不校验包签名与发布者**：版本锁定只回答"装的是哪一版"。'));
  lines.push(t('- **没有审计链就没有历史**：本机的审计链状态见 §8；链为空时，"它做过什么"无法证明。'));
  lines.push('');

  // ---------- 4 暴露面 ----------
  lines.push(t('## 4. 暴露面（静态扫描）'));
  lines.push('');
  lines.push(demoteHeadings(stripOperatorCtas(input.scanReport)));
  lines.push('');

  // ---------- 5 多 harness ----------
  lines.push(t('## 5. 多 agent / 多 harness 覆盖面'));
  lines.push('');
  lines.push(t('扫描了 {harnesses} 类 harness（{installed} 类已安装）、{servers} 个 MCP server、{hooks} 个钩子、{projects} 个工作区；其中未纳管的 harness {unmanaged} 个。', {
    harnesses: input.guardReport.scanned.harnesses,
    installed: input.guardReport.scanned.installedHarnesses,
    servers: input.guardReport.scanned.servers,
    hooks: input.guardReport.scanned.hooks,
    projects: input.guardReport.scanned.projects,
    unmanaged: summary.unmanagedHarnesses,
  }));
  lines.push('');
  lines.push(demoteHeadings(renderGuardEmbed(input.guardReport)));
  lines.push('');

  // ---------- 6 控制平面姿态 ----------
  lines.push(t('## 6. 控制平面姿态'));
  lines.push('');
  lines.push(demoteHeadings(input.postureReport));
  lines.push('');

  // ---------- 7 最小权限策略 ----------
  lines.push(t('## 7. 最小权限策略建议'));
  lines.push('');
  if (input.draftReport) {
    lines.push(demoteHeadings(input.draftReport));
  } else {
    lines.push(t('审计目录为空，无法从真实行为编译最小权限策略。'));
    lines.push('');
    lines.push(t('先采集语料：`pod record --config <mcp-manager.json> --server <name>`，'));
    lines.push(t('日常使用一段时间后再跑 `pod harden`——**没有语料的策略只是猜测**。'));
  }
  lines.push('');

  // ---------- 8 证据 ----------
  lines.push(t('## 8. 证据与可验证性'));
  lines.push('');
  lines.push(demoteHeadings(input.verifyReport));
  lines.push('');

  // ---------- 9 如何验证 ----------
  lines.push(t('## 9. 如何验证这份交付物'));
  lines.push('');
  lines.push(t('这份报告不需要你信任 pod 或它的运营者——三条命令都能独立复验：'));
  lines.push('');
  lines.push('```bash');
  lines.push(t('pod harden --verify <报告目录>        # 逐文件重算 sha256，比对 manifest.json'));
  // 不用带引号的 jq 一行流：key 里带引号会破坏覆盖率脚本的抽取（\\' 会被当成串尾），
  // 而这条命令的用途只是"手工再算一遍哈希"，sha256sum 就够了。
  lines.push(t('sha256sum <报告目录>/*   # 与 manifest.json 里记录的 sha256 逐一比对'));
  lines.push(t('pod verify-evidence <报告目录>/evidence.json   # 校验证据包本身（如有）'));
  lines.push('```');
  lines.push('');
  lines.push(t('任何一份产物被改动一个字节，第一步就会失败并指出是哪个文件。'));
  lines.push('');

  // ---------- 10 产物清单与声明 ----------
  lines.push(t('## 10. 产物清单与交付声明'));
  lines.push('');
  lines.push(t('| 文件 | 字节 | sha256 |'));
  lines.push('|------|-----:|--------|');
  for (const a of input.artifacts) {
    lines.push(`| \`${a.file}\` | ${a.bytes} | \`${a.sha256.slice(0, 16)}…\` |`);
  }
  lines.push('');
  lines.push(t('完整哈希见 `manifest.json`；`manifest.json` 本身不进清单（否则会自我引用）。'));
  lines.push('');
  lines.push(t('**声明**：本报告由 pod 在 {home} 于 {ts} 生成，生成后未被修改；采集与判定全程未离开该机器；报告中的凭据只保留掩码，不含任何密钥原文。', {
    home: input.home,
    ts: input.generatedAt,
  }));
  lines.push('');
  return lines.join('\n');
}

/** §0 的执行摘要：给不读附件的人看的一屏 */
function renderExecutiveSummary(input: {
  summary: HardenSummary;
  plan: ReturnType<typeof buildFunnelPlan>;
  findings: HardenFinding[];
}): string[] {
  const { summary, plan, findings } = input;
  const lines: string[] = [];
  const high = findings.filter((f) => f.severity === 'high').length;
  lines.push(t('**结论**：本机扫出 {high} 条 high、{medium} 条 medium、{low} 条 low；agent 平台 {platforms} 个、MCP server {servers} 个、疑似暴露凭据 {secrets} 处；审计链 {chains} 条（{entries} 条记录），断裂 {broken} 条。', {
    high,
    medium: findings.filter((f) => f.severity === 'medium').length,
    low: findings.filter((f) => f.severity === 'low').length,
    platforms: summary.platforms.length,
    servers: summary.mcpServers,
    secrets: summary.exposedSecrets,
    chains: summary.auditChains,
    entries: summary.auditEntries,
    broken: summary.brokenChains,
  }));
  lines.push('');
  lines.push(t('| 严重级别 | 数量 |'));
  lines.push('|----------|-----:|');
  lines.push(`| 🔴 high | ${summary.high} |`);
  lines.push(`| 🟠 medium | ${summary.medium} |`);
  lines.push(`| 🟡 low | ${summary.low} |`);
  lines.push('');
  if (plan.actions.length > 0) {
    lines.push(t('**本次最重要的三件事**（完整待办见 §2）：'));
    lines.push('');
    plan.actions.forEach((item) => {
      lines.push(
        `${item.priority}. ${SEVERITY_ICON[item.severity]} ${item.threat} ${item.title} · \`${item.harness}\` ${paren(
          findingsLabel(item.affects),
        )} — ${item.action}`,
      );
    });
    lines.push('');
  }
  lines.push(
    summary.baselineMissing
      ? t('⚠️ 尚未建立姿态基线：本次只能做静态判定，配置/记忆/钩子的**变更**类检查未生效——这是当前最大的可见性缺口（`pod posture freeze` 可消除）。')
      : t('✅ 已建立姿态基线：配置、记忆、钩子、包来源的漂移检查均已生效。'),
  );
  lines.push('');
  lines.push(t('覆盖声明：有确定性判定 {automated} 类 · 只能给信号 {partial} 类 · pod 看不到 {gap} 类。', {
    automated: summary.coverage.automated,
    partial: summary.coverage.partial,
    gap: summary.coverage.gap,
  }));
  lines.push('');
  return lines;
}

/** §2 的待办：每条都带一条能直接复制的 pod 命令 */
function renderTodoList(plan: ReturnType<typeof buildFunnelPlan>): string[] {
  const lines: string[] = [];
  if (plan.actions.length === 0) return lines;
  lines.push(t('### 待办（命令可直接复制）'));
  lines.push('');
  for (const item of plan.actions) {
    lines.push(`${item.priority}. **${item.threat} ${item.title}** — ${item.action}`);
    lines.push('');
    lines.push('```bash');
    lines.push(item.command);
    lines.push('```');
    lines.push('');
    lines.push(t('确认：`{cmd}`{residual}', {
      cmd: item.verify,
      residual: item.residualRisk ? t('（pod 只能发现/降低风险，做完不会消失）') : '',
    }));
    lines.push('');
  }
  return lines;
}

/**
 * 把 guard 的报告收进交付物。
 *
 * guard 的完整报告里有"先做这三件事"与交付入口——那是对**操作者**说的，
 * 放进客户交付物会重复且跑题。所以这里只保留它的清单部分（概览 + 漏洞清单 +
 * 建议清单 + 覆盖边界），并在前面补一句出处。
 */
function renderGuardEmbed(report: GuardReport): string {
  const markdown = renderGuardReport(report);
  // 从「先做这三件事」起整段切掉：那是对操作者说的下一步，客户交付物里
  // 已经有自己的 §2 待办，重复出现只会让报告看起来像一份工具输出。
  const marker = t('### 先做这三件事');
  const index = markdown.indexOf(marker);
  return index > 0 ? markdown.slice(0, index).trimEnd() + '\n' : markdown;
}

/**
 * 去掉嵌进交付物的子报告里的"获客话术"行。
 *
 * `pod scan` 的结尾会告诉操作者"想扫 16 类 harness 用 guard / 要交付用 harden"——
 * 那是给还没决定用不用 pod 的人看的。同一段嵌进 `pod harden` 的客户报告里就变成了
 * 荒谬的自我指涉（报告里叫你去生成这份报告）。
 *
 * 只按命令行引用匹配（而不是按中文/英文文案），所以中英切换下都成立。
 */
function stripOperatorCtas(markdown: string): string {
  return markdown
    .split('\n')
    .filter(
      (line) =>
        !(line.startsWith('**') && (line.includes('`pod guard scan`') || line.includes('`pod harden --out'))),
    )
    .join('\n');
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
  // 多 harness 扫描：scan 只认 6 类平台，guard 认 16 类，还看钩子 / 记忆 / 远程端点 /
  // 项目级配置。审计交付物不能只在半个扫描面上说"没发现问题"。
  const guard = runGuardScan({
    home: opts.home,
    rules: opts.rules,
    auditDir: opts.auditDir,
    now,
  });
  const findings = collectFindings(scan, posture.result.findings, guard.report, opts.home);
  const corpusEntries = loadAllAuditFiles(opts.auditDir).reduce((sum, file) => sum + file.log.entries.length, 0);
  const summary: HardenSummary = {
    high: findings.filter((f) => f.severity === 'high').length,
    medium: findings.filter((f) => f.severity === 'medium').length,
    low: findings.filter((f) => f.severity === 'low').length,
    platforms: scan.agents.filter((a) => a.found).map((a) => a.platform),
    // harness 扫描的覆盖面更大（16 类 harness、5 种配置格式），用它的 server 数：
    // 交付物里 §0 说 0 个、§5 说 2 个，客户第一个问题就是"到底几个"
    mcpServers: Math.max(scan.mcpServers.length, guard.report.scanned.servers),
    exposedSecrets: scan.secrets.length,
    auditChains: audits.length,
    brokenChains: audits.filter((a) => !a.ok).length,
    auditEntries: audits.reduce((sum, a) => sum + a.entries, 0),
    baselineMissing: posture.result.baselineMissing,
    draftedServers: draft ? Object.keys(draft.policy.servers ?? {}).length : 0,
    draftedTools: draft ? countDraftedTools(draft.policy) : 0,
    rulesVersion: opts.rules.version,
    harnessFindings: guard.report.findings.length,
    harnessesScanned: guard.report.scanned.harnesses,
    installedHarnesses: guard.report.scanned.installedHarnesses,
    unmanagedHarnesses: guard.facts.harnesses.filter((h) => h.installed && !h.managed).length,
    corpusEntries,
    coverage: guard.report.coverage,
  };

  const findingsFile: HardenFindingsFile = {
    format: 'pod-harden-findings/v1',
    generatedAt,
    home: opts.home,
    rulesVersion: opts.rules.version,
    ...(opts.engagement ? { engagement: opts.engagement } : {}),
    findings,
    scan: {
      platforms: scan.agents,
      mcpServers: scan.mcpServers,
      // 只留掩码：客户交付物里不该出现密钥前缀
      secrets: scan.secrets.map((s) => ({ file: s.file, category: s.category, masked: s.masked })),
    },
    harness: {
      harnesses: guard.report.scanned.harnesses,
      installedHarnesses: guard.report.scanned.installedHarnesses,
      unmanagedHarnesses: guard.facts.harnesses.filter((h) => h.installed && !h.managed).map((h) => h.id),
      hooks: guard.report.scanned.hooks,
      servers: guard.report.scanned.servers,
      projects: guard.report.scanned.projects,
    },
    audits,
  };

  const written: HardenArtifact[] = [];
  const write = (name: string, content: string): void => {
    writeFileSync(join(opts.outDir, name), content, 'utf8');
    written.push({ file: name, sha256: sha256Hex(content), bytes: Buffer.byteLength(content, 'utf8') });
  };

  write('findings.json', JSON.stringify(findingsFile, null, 2) + '\n');
  // 完整的多 harness 扫描明细：客户/审计方要复核时看这一份，不用重跑
  write('harness-scan.md', guard.markdown);
  write('harness-findings.json', JSON.stringify(guard.report, null, 2) + '\n');
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
    evidenceNote = t('（审计目录为空，未导出证据包——**没有记录就没有可证明的历史**）');
  }

  const verifyReport =
    (audits.length === 0
      ? t('# 审计完整性自检\n\n（审计目录为空）')
      : renderVerifyReport(audits, opts.auditDir)) + (evidenceNote ? `\n\n${evidenceNote}` : '');
  const report = renderHardenReport({
    generatedAt,
    home: opts.home,
    ...(opts.engagement ? { engagement: opts.engagement } : {}),
    summary,
    findings,
    guardReport: guard.report,
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
    ...(opts.engagement ? { engagement: opts.engagement } : {}),
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

export interface HardenVerifyResult {
  dir: string;
  /** true = manifest 里列的每一份产物都存在，且重算 sha256 完全一致 */
  ok: boolean;
  checked: number;
  mismatches: Array<{ file: string; expected: string; actual: string }>;
  missing: string[];
  generatedAt?: string;
  /** 明显不是一份交付目录时的原因（例如没有 manifest.json） */
  error?: string;
}

/**
 * 校验一份已交付的报告目录（`pod harden --verify <dir>`）。
 *
 * 存在的意义是让**收到报告的一方**能自己验：不需要重新跑 pod、不需要信任出具方，
 * 只要 manifest.json 里的 sha256 对得上，就说明这份交付物从生成到现在没被改过。
 * 这正是"证据优先"和"口头保证"的分界线。
 */
export function verifyHardenPackage(dir: string): HardenVerifyResult {
  const manifestPath = join(dir, 'manifest.json');
  if (!existsSync(manifestPath)) {
    return {
      dir,
      ok: false,
      checked: 0,
      mismatches: [],
      missing: [],
      error: t('找不到 {path}——这不是一份 pod harden 交付目录', { path: manifestPath }),
    };
  }
  let manifest: { generatedAt?: string; artifacts?: Array<{ file: string; sha256: string }> };
  try {
    manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
  } catch (err) {
    return {
      dir,
      ok: false,
      checked: 0,
      mismatches: [],
      missing: [],
      error: t('manifest.json 解析失败：{reason}', { reason: err instanceof Error ? err.message : String(err) }),
    };
  }
  const mismatches: HardenVerifyResult['mismatches'] = [];
  const missing: string[] = [];
  let checked = 0;
  for (const artifact of manifest.artifacts ?? []) {
    const path = join(dir, artifact.file);
    if (!existsSync(path)) {
      missing.push(artifact.file);
      continue;
    }
    const content = readFileSync(path, 'utf8');
    const actual = sha256Hex(content);
    checked++;
    if (actual !== artifact.sha256) {
      mismatches.push({ file: artifact.file, expected: artifact.sha256, actual });
    }
  }
  const result: HardenVerifyResult = {
    dir,
    ok: missing.length === 0 && mismatches.length === 0,
    checked,
    mismatches,
    missing,
  };
  if (manifest.generatedAt) result.generatedAt = manifest.generatedAt;
  return result;
}
