/**
 * `pod guard` —— 多 agent / 多 harness 的持续漏洞扫描与加固建议。
 *
 * 与既有命令的分工：
 *   pod scan    一次性暴露面（获客楔子）
 *   pod posture 控制平面姿态与漂移
 *   pod harden  一次性交付物（审计服务）
 *   pod guard   **持续**：同一个判定口径反复跑，只对"变化"说话
 *
 * 三条纪律：
 * 1. **扫描只读**：采集、判定、报表全程不联网、不改任何文件（写状态的只有
 *    `pod guard baseline` / `watch` 自己的 state，且只写指纹）；
 * 2. **判定归用户**：阈值与清单来自 `~/.pod/rules.json` 的 `guard` 段；
 * 3. **模型只有建议权**：`pod guard remediate --llm` 产出的是**建议物**
 *    （处置步骤 + 规则增量），落地前必须过 pod 既有的放宽守卫；模型永远
 *    拿不到执行权，也看不到任何路径、主机名或配置原文。
 */
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { t } from '@podsec/i18n';
import {
  buildGuardBaseline,
  parseGuardSnapshot,
  readGuardBaseline,
  renderGuardReport,
  resolveBaselinePath,
  runGuardScan,
  snapshotOf,
  THREAT_BY_ID,
  THREAT_CATALOG,
  diffFindings,
  type Finding,
  type GuardReport,
  type GuardScanResult,
} from '@podsec/guard';
import {
  detectRelaxations,
  diffRules,
  mergeRules,
  validateRules,
  type RuleSet,
  type RuleSetOverride,
} from '@podsec/policy';
import { callChat, extractJsonObject, resolveLlmConfig, LlmConfigError } from './llm.js';
import { appendControlEvent } from './control-plane.js';

export interface GuardCliOptions {
  home: string;
  podHome: string;
  rules: RuleSet;
  auditDir: string;
  workspaces?: string[];
  baselinePath?: string;
  outDir?: string;
  json?: boolean;
  strict?: boolean;
  /** true = 把本轮发现写进控制平面哈希链（默认 false，扫描本身不产生状态） */
  writeAudit?: boolean;
  now?: Date;
  log: (message: string) => void;
}

// ---------- 扫描 ----------

export function scanOnce(opts: GuardCliOptions): GuardScanResult {
  const result = runGuardScan({
    home: opts.home,
    rules: opts.rules,
    auditDir: opts.auditDir,
    ...(opts.workspaces && opts.workspaces.length > 0 ? { workspaces: opts.workspaces } : {}),
    ...(opts.baselinePath ? { baselinePath: opts.baselinePath } : {}),
    ...(opts.now ? { now: opts.now } : {}),
  });
  if (opts.writeAudit) writeFindingsToChain(opts, result.findings);
  return result;
}

/**
 * 把发现写进该 agent 的审计链。
 * 写不进去不能反过来让扫描失败（例如链本身断了），但必须说出来——
 * "看起来在记、其实没记"是 pod 明确要避免的状态。
 */
function writeFindingsToChain(opts: GuardCliOptions, findings: Finding[]): void {
  const failures: string[] = [];
  for (const finding of findings) {
    try {
      appendControlEvent({
        auditDir: opts.auditDir,
        agent: finding.harness === 'unknown' || finding.harness === 'machine' ? '_control' : finding.harness,
        kind: 'anomaly',
        reason: `guard:${finding.threat}:${finding.subject}:${finding.message}`,
        tool: finding.category,
        decision: 'allow',
        payload: { severity: finding.severity, threat: finding.threat, subject: finding.subject },
      });
    } catch (err) {
      failures.push(`${finding.id}: ${err instanceof Error ? err.message : String(err)}`);
    }
  }
  if (failures.length > 0) {
    opts.log(t('⚠️ {n} 条发现未能写入审计链：', { n: failures.length }));
    for (const failure of failures.slice(0, 5)) opts.log(`   - ${failure}`);
  }
}

export interface GuardScanOutput {
  result: GuardScanResult;
  exitCode: number;
  outDir?: string;
}

export function cmdGuardScan(opts: GuardCliOptions): GuardScanOutput {
  const result = scanOnce(opts);
  const report = result.report;

  let outDir: string | undefined;
  if (opts.outDir) {
    outDir = opts.outDir;
    mkdirSync(outDir, { recursive: true });
    writeFileSync(join(outDir, 'guard-report.md'), result.markdown, 'utf8');
    writeFileSync(join(outDir, 'guard-findings.json'), JSON.stringify(report, null, 2) + '\n', 'utf8');
  }

  if (opts.json) {
    process.stdout.write(JSON.stringify(report, null, 2) + '\n');
  } else {
    process.stdout.write(result.markdown);
  }
  if (outDir) {
    opts.log(t('guard 报告已写入：{path}', { path: join(outDir, 'guard-report.md') }));
    opts.log(t('  机器可读清单：{path}', { path: join(outDir, 'guard-findings.json') }));
  }
  const high = report.findings.filter((f) => f.severity === 'high').length;
  return { result, exitCode: opts.strict && high > 0 ? 1 : 0, ...(outDir ? { outDir } : {}) };
}

// ---------- 基线 ----------

export function cmdGuardBaseline(opts: GuardCliOptions): { path: string; servers: number; hooks: number } {
  const result = scanOnce({ ...opts, writeAudit: false });
  const path = opts.baselinePath ?? resolveBaselinePath(opts.rules, opts.home);
  const baseline = buildGuardBaseline(result.facts, { home: opts.home, ...(opts.now ? { now: opts.now } : {}) });
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, JSON.stringify(baseline, null, 2) + '\n', 'utf8');
  appendControlEvent({
    auditDir: opts.auditDir,
    agent: '_control',
    kind: 'config-change',
    reason: `guard:baseline:${path}`,
    payload: { servers: Object.keys(baseline.servers).length, hooks: Object.keys(baseline.hooks).length },
  });
  return { path, servers: Object.keys(baseline.servers).length, hooks: Object.keys(baseline.hooks).length };
}

// ---------- 实时监控 ----------

export interface GuardWatchOptions extends GuardCliOptions {
  intervalSec: number;
  once?: boolean;
  statePath: string;
  /** 测试用：跑满这么多轮就退出 */
  maxRounds?: number;
  /** 测试用：注入等待实现 */
  sleep?: (ms: number) => Promise<void>;
}

export interface GuardWatchSummary {
  rounds: number;
  added: number;
  changed: number;
  resolved: number;
  quietRounds: number;
}

function readState(path: string): ReturnType<typeof parseGuardSnapshot> | null {
  if (!existsSync(path)) return null;
  try {
    return parseGuardSnapshot(readFileSync(path, 'utf8'));
  } catch {
    // 状态文件损坏 = 当作没有上一轮（全部算新增）。它只是增量依据，
    // 不是安全判定的输入，所以不值得让整轮扫描失败。
    return null;
  }
}

export async function cmdGuardWatch(opts: GuardWatchOptions): Promise<GuardWatchSummary> {
  const sleep = opts.sleep ?? ((ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms)));
  const summary: GuardWatchSummary = { rounds: 0, added: 0, changed: 0, resolved: 0, quietRounds: 0 };
  let round = 0;
  // 第一次迭代用 now() 让循环体至少跑一轮
  for (;;) {
    round++;
    summary.rounds = round;
    opts.now = new Date();
    const result = scanOnce(opts);
    const previous = readState(opts.statePath);
    const diff = diffFindings(previous, result.findings);

    const stamp = new Date().toISOString().slice(11, 19);
    if (diff.quiet) {
      summary.quietRounds++;
      // 常驻循环里"没变化"不占屏幕（否则三分钟后就没人看它了）；
      // `--once` 是一次性报告，必须明确说"没有变化"，不能静默结束。
      if (opts.once) opts.log(t('[{ts}] 无变化（{total} 条已知问题）', { ts: stamp, total: result.findings.length }));
    } else {
      summary.added += diff.added.length;
      summary.changed += diff.changed.length;
      summary.resolved += diff.resolved.length;
      opts.log(
        t('[{ts}] 新增 {added} · 变化 {changed} · 消失 {resolved}（共 {total} 条）', {
          ts: stamp,
          added: diff.added.length,
          changed: diff.changed.length,
          resolved: diff.resolved.length,
          total: result.findings.length,
        }),
      );
      for (const item of diff.added) printChange(opts, '新增', item);
      for (const item of diff.changed) printChange(opts, '变化', item);
      for (const id of diff.resolved) opts.log(`   ✅ [消失] ${id}（确认是真修好，还是扫描面变小了）`);
      // 只有变化的那部分进审计链：每轮把同一份告警写一遍会淹掉真正的信号
      if (opts.writeAudit) writeFindingsToChain(opts, [...diff.added, ...diff.changed]);
    }

    mkdirSync(dirname(opts.statePath), { recursive: true });
    writeFileSync(opts.statePath, JSON.stringify(snapshotOf(result.findings, opts.now), null, 2) + '\n', 'utf8');

    if (opts.once) break;
    if (opts.maxRounds !== undefined && round >= opts.maxRounds) break;
    await sleep(opts.intervalSec * 1000);
  }
  return summary;
}

function printChange(opts: GuardCliOptions, label: string, finding: Finding): void {
  const icon = finding.severity === 'high' ? '🔴' : finding.severity === 'medium' ? '🟠' : '🟡';
  const entry = THREAT_BY_ID[finding.threat];
  opts.log(`   ${icon} [${label}] ${finding.threat}${entry ? ` ${entry.title}` : ''} · ${finding.harness} · ${finding.subject}`);
  opts.log(`      ${finding.message}`);
  if (entry?.remediation.command) opts.log(`      建议：${entry.remediation.command}`);
}

// ---------- 模型辅助加固（建议物，不自动生效） ----------

/**
 * 出网面：**只有 pod 自己的目录文本 + 计数**。
 *
 * 具体说：不发文件路径、不发主机名、不发配置原文、不发 finding 的描述文本
 * （描述里可能带路径）。模型拿到的是"哪些类问题、各多少处、落在哪个 harness"，
 * 加上目录里我们自己的 summary 与处置建议——够它排优先级，不够它反推客户环境。
 */
export interface GuardModelInput {
  hostSummary: {
    harnesses: number;
    installedHarnesses: number;
    servers: number;
    hooks: number;
    secrets: number;
  };
  findings: Array<{
    threat: string;
    title: string;
    severity: string;
    category: string;
    harness: string;
    count: number;
  }>;
  controlsOff: string[];
}

export function buildGuardModelInput(report: GuardReport): GuardModelInput {
  const grouped = new Map<string, { harnesses: Set<string>; count: number }>();
  for (const finding of report.findings) {
    const key = finding.threat;
    const bucket = grouped.get(key) ?? { harnesses: new Set<string>(), count: 0 };
    bucket.count++;
    bucket.harnesses.add(finding.harness);
    grouped.set(key, bucket);
  }
  const findings = [...grouped.entries()].map(([threat, bucket]) => {
    const entry = THREAT_BY_ID[threat];
    return {
      threat,
      title: entry?.title ?? threat,
      severity: entry?.severity ?? 'medium',
      category: entry?.category ?? 'boundary',
      harness: [...bucket.harnesses].sort().join(','),
      count: bucket.count,
    };
  });
  // 闸门关着这类信号是从 rules 推出来的，不涉及客户数据
  const controlsOff: string[] = [];
  for (const finding of report.findings) {
    if (['AG-15', 'AG-17'].includes(finding.threat)) controlsOff.push(finding.subject);
  }
  return { hostSummary: report.scanned, findings, controlsOff };
}

function catalogForPrompt(): string {
  return THREAT_CATALOG.map(
    (entry) =>
      `- ${entry.id} ${entry.title}（${entry.category}，severity=${entry.severity}，coverage=${entry.coverage}）\n` +
      `  现象：${entry.summary}\n` +
      `  建议动作：${entry.remediation.action}${entry.remediation.command ? `（命令：${entry.remediation.command}）` : ''}\n` +
      `  理由：${entry.remediation.why}`,
  ).join('\n');
}

const GUARD_SYSTEM_PROMPT = [
  '你是 AI agent / MCP 环境的安全加固顾问。给定一台机器上扫描出的问题类别与数量，产出处置方案。',
  '硬约束：',
  '① 只输出一个 JSON 对象，不要 markdown 代码块、不要解释文字；',
  '② 形如 {"summary":"...","actions":[{"threat","step","command","rationale"}],"ruleSuggestions":{}}；',
  '③ actions[].threat 必须是给定问题清单里出现过的编号，**不得编造**——编造的一律被丢弃；',
  '④ ruleSuggestions 是可选的 rules.json 增量（对象），只允许**收紧**：任何削弱现有防线的字段都会被放宽守卫拒绝；',
  '⑤ command 只能写 pod 自己的命令（pod ...），不要写 shell 管道、重定向、curl、rm 之类会被误当成可执行动作的东西；',
  '⑥ 按"先消掉最危险的、且能一次覆盖多处的"排序，最多 8 条。',
].join('\n');

export function buildGuardPrompt(input: GuardModelInput): string {
  return [
    `本机概况：harness ${input.hostSummary.harnesses} 个（已安装 ${input.hostSummary.installedHarnesses}）、MCP server ${input.hostSummary.servers} 个、钩子 ${input.hostSummary.hooks} 个、明文凭据 ${input.hostSummary.secrets} 处。`,
    input.controlsOff.length > 0 ? `当前关着的闸门：${input.controlsOff.join('、')}` : '闸门配置未见明显关闭项。',
    '',
    '本轮扫出的问题（已聚合，无路径、无主机名、无配置原文）：',
    ...input.findings.map(
      (item) => `- ${item.threat} ${item.title} severity=${item.severity} 落在=${item.harness} 处数=${item.count}`,
    ),
    '',
    '参考知识库（pod 自己的威胁目录，可作为处置依据）：',
    catalogForPrompt(),
  ].join('\n');
}

export interface GuardAction {
  threat: string;
  step: string;
  command?: string;
  rationale?: string;
}

export interface GuardRemediation {
  summary: string;
  actions: GuardAction[];
  /** 被丢弃的模型产出（含原因）——不假装模型的输出全都能用 */
  rejected: Array<{ raw: unknown; reason: string }>;
  /** 规则增量（已经过放宽守卫） */
  ruleSuggestions: RuleSetOverride | null;
  /** 放宽守卫拒绝的项 */
  relaxations: string[];
  /** 应用后的完整规则（未应用时也给出来，便于人工比对） */
  mergedRules: RuleSet | null;
  provider: string;
  model: string;
  notes: string[];
}

/**
 * 只保留 pod 自己的命令形态。
 *
 * 建议里的命令是给用户**照抄**的，所以它必须长得像一条 pod 命令，而不是一段
 * 任意 shell：允许 `pod a && pod b`，其余元字符（; | < > $ 反引号 换行）一律拒绝。
 * 这不是执行前的沙箱，而是"别让建议看起来像指令"的表述纪律。
 */
export function sanitizeCommand(raw: unknown): string | undefined {
  if (typeof raw !== 'string') return undefined;
  const command = raw.trim().replace(/`/g, '').replace(/\s+/g, ' ');
  if (!command) return undefined;
  const parts = command
    .split('&&')
    .map((part) => part.trim())
    .filter(Boolean);
  if (parts.length === 0) return undefined;
  if (!parts.every((part) => /^pod\s+[a-z][a-z-]*(\s|$)/.test(part))) return undefined;
  if (/[;|<>\n`$&]/.test(command.replace(/&&/g, ''))) return undefined;
  return command.length > 200 ? `${command.slice(0, 197)}…` : command;
}

export interface GuardRemediateOptions extends GuardCliOptions {
  useLlm: boolean;
  provider?: string;
  model?: string;
  baseUrl?: string;
  /** 把完整规则（含模型增量）写进 ~/.pod/rules.json；放宽项会被拒 */
  apply?: boolean;
  /** 离线交接：把发出去的上下文写到文件（这是唯一需要交给模型的东西） */
  exportContextPath?: string;
}

export async function cmdGuardRemediate(opts: GuardRemediateOptions): Promise<GuardRemediation> {
  const result = scanOnce({ ...opts, writeAudit: false });
  const report = result.report;
  const input = buildGuardModelInput(report);
  const outDir = opts.outDir ?? join(opts.podHome, 'guard');
  mkdirSync(outDir, { recursive: true });

  const prompt = buildGuardPrompt(input);
  if (opts.exportContextPath) {
    writeFileSync(opts.exportContextPath, prompt + '\n', 'utf8');
    opts.log(t('出网上下文已导出：{path}（这是唯一需要交给模型的东西）', { path: opts.exportContextPath }));
  }

  const observed = new Set(input.findings.map((item) => item.threat));
  const rejected: GuardRemediation['rejected'] = [];
  const notes: string[] = [];
  let summary = t('本轮没有扫出需要处置的问题。');
  let actions: GuardAction[] = [];
  let ruleSuggestions: RuleSetOverride | null = null;
  let provider = 'none';
  let model = 'none';

  if (opts.useLlm) {
    if (input.findings.length === 0) {
      notes.push(t('没有发现可处置的问题，未调用模型（不为了"用上模型"而发数据出去）。'));
    } else {
      const cfg = resolveLlmConfig(opts.podHome, {
        ...(opts.provider ? { provider: opts.provider } : {}),
        ...(opts.model ? { model: opts.model } : {}),
        ...(opts.baseUrl ? { baseUrl: opts.baseUrl } : {}),
      });
      provider = cfg.provider;
      model = cfg.model;
      opts.log(
        `模型：${cfg.provider}/${cfg.model}${cfg.provider === 'mock' ? '（离线模拟，不发请求）' : ' — 只发送问题类别与计数，不发送路径、主机名、配置原文'}`,
      );
      const outcome = await callChat(
        cfg,
        [
          { role: 'system', content: GUARD_SYSTEM_PROMPT },
          { role: 'user', content: prompt },
        ],
        {
          feature: 'guard.remediate',
          temperature: 0.2,
          maxTokens: 2000,
          jsonMode: true,
          mockShape: 'object',
          auditDir: opts.auditDir,
        },
      );
      const parsed = extractJsonObject(outcome.content) as Record<string, unknown>;
      if (typeof parsed.summary === 'string') summary = parsed.summary;
      actions = normalizeActions(parsed.actions, observed, rejected);
      ruleSuggestions = normalizeRuleSuggestions(parsed.ruleSuggestions, rejected);
      notes.push(
        `模型（${cfg.provider}/${cfg.model}）产出：接收 ${actions.length} 条处置动作，丢弃 ${rejected.length} 条；` +
          `本次发送 ${outcome.promptChars} 字符，返回 ${outcome.responseChars} 字符（已写入审计链 kind=llm-call）。`,
      );
    }
  } else {
    // 不静默：用户可能以为不加 --llm 也会得到处置步骤
    notes.push(
      t('未加 --llm：本次只做本地扫描与产物落盘。处置步骤来自 `pod guard scan` 的建议清单；加 --llm 才会生成模型建议物。'),
    );
  }

  // 放宽守卫：与 pod rules apply 同一套判定（diffRules + detectRelaxations）
  let mergedRules: RuleSet | null = null;
  const relaxations: string[] = [];
  if (ruleSuggestions && Object.keys(ruleSuggestions).length > 0) {
    // 非法增量与放宽增量是同一种处理：整体不应用，并写清楚为什么
    let merged: RuleSet | null = null;
    try {
      merged = mergeRules(opts.rules, ruleSuggestions);
      validateRules(merged);
    } catch (err) {
      rejected.push({ raw: ruleSuggestions, reason: `规则增量不合法：${err instanceof Error ? err.message : String(err)}` });
      ruleSuggestions = null;
    }
    if (merged) {
      for (const change of detectRelaxations(diffRules(opts.rules, merged))) {
        relaxations.push(`${change.where}（${change.kind}${change.from ? `: ${change.from}` : ''}）`);
      }
      if (relaxations.length === 0) {
        mergedRules = merged;
      } else {
        notes.push(
          t('规则增量会放宽 {n} 处现有防线，已整体拒绝应用（与 pod rules apply 的放宽守卫同一口径）。', {
            n: relaxations.length,
          }),
        );
      }
    }
  }

  const remediation: GuardRemediation = {
    summary,
    actions,
    rejected,
    ruleSuggestions: mergedRules ? ruleSuggestions : null,
    relaxations,
    mergedRules,
    provider,
    model,
    notes,
  };

  writeFileSync(join(outDir, 'guard-remediation.md'), renderRemediationMarkdown(report, remediation), 'utf8');
  writeFileSync(join(outDir, 'guard-remediation.json'), JSON.stringify(remediation, null, 2) + '\n', 'utf8');
  if (mergedRules) {
    writeFileSync(join(outDir, 'rules-suggested.json'), JSON.stringify(ruleSuggestions, null, 2) + '\n', 'utf8');
    writeFileSync(join(outDir, 'rules-merged.json'), JSON.stringify(mergedRules, null, 2) + '\n', 'utf8');
  }

  if (opts.apply) {
    if (!mergedRules) {
      opts.log(t('没有可应用的规则增量（未生成，或被放宽守卫拒绝），rules.json 保持不变。'));
    } else {
      applyRules(opts, mergedRules);
      opts.log(t('规则已应用到 {path}（原文件已备份为 rules.json.bak）', { path: join(opts.podHome, 'rules.json') }));
    }
  }

  opts.log(t('加固建议已写入：{path}', { path: join(outDir, 'guard-remediation.md') }));
  for (const note of notes) opts.log(`  ${note}`);
  return remediation;
}

function normalizeActions(
  raw: unknown,
  observed: Set<string>,
  rejected: GuardRemediation['rejected'],
): GuardAction[] {
  if (!Array.isArray(raw)) return [];
  const out: GuardAction[] = [];
  for (const item of raw) {
    if (!item || typeof item !== 'object' || Array.isArray(item)) {
      rejected.push({ raw: item, reason: '不是对象' });
      continue;
    }
    const entry = item as Record<string, unknown>;
    const threat = typeof entry.threat === 'string' ? entry.threat : '';
    if (!observed.has(threat)) {
      // 与 redteam 的校验器同一立场：编造的条目一律丢弃，否则会刷出漂亮的空建议
      rejected.push({ raw: item, reason: `threat "${threat}" 不在本轮问题清单里（不许编造）` });
      continue;
    }
    const step = typeof entry.step === 'string' ? entry.step.trim() : '';
    if (!step) {
      rejected.push({ raw: item, reason: '缺少 step' });
      continue;
    }
    const action: GuardAction = { threat, step };
    const command = sanitizeCommand(entry.command);
    if (command) action.command = command;
    else if (entry.command !== undefined) rejected.push({ raw: entry.command, reason: '命令不是 pod 命令，已从建议里去掉（避免照抄一条会乱跑的 shell）' });
    if (typeof entry.rationale === 'string' && entry.rationale.trim()) action.rationale = entry.rationale.trim();
    out.push(action);
  }
  return out;
}

function normalizeRuleSuggestions(raw: unknown, rejected: GuardRemediation['rejected']): RuleSetOverride | null {
  if (raw === undefined || raw === null) return null;
  if (typeof raw !== 'object' || Array.isArray(raw)) {
    rejected.push({ raw, reason: 'ruleSuggestions 必须是对象' });
    return null;
  }
  if (Object.keys(raw as object).length === 0) return null;
  return raw as RuleSetOverride;
}

function applyRules(opts: GuardRemediateOptions, merged: RuleSet): void {
  const target = join(opts.podHome, 'rules.json');
  mkdirSync(opts.podHome, { recursive: true });
  if (existsSync(target)) {
    writeFileSync(`${target}.bak`, readFileSync(target, 'utf8'), 'utf8');
  }
  // 临时文件 + rename：半截 rules.json 会让 loadRules 抛错、整个 pod 进入 fail-closed
  const tmp = `${target}.tmp`;
  writeFileSync(tmp, JSON.stringify(merged, null, 2) + '\n', 'utf8');
  renameSync(tmp, target);
  appendControlEvent({
    auditDir: opts.auditDir,
    agent: '_control',
    kind: 'config-change',
    reason: 'guard:remediate:apply',
    payload: { provider: 'llm', path: target },
  });
}

function renderRemediationMarkdown(report: GuardReport, remediation: GuardRemediation): string {
  const lines: string[] = [t('# pod guard — 加固建议（模型辅助）'), ''];
  lines.push(t('生成时间：{ts}', { ts: new Date().toISOString() }));
  lines.push(t('模型：{provider}/{model}', { provider: remediation.provider, model: remediation.model }));
  lines.push('');
  lines.push(t('> 建议物不自动生效。规则增量必须过放宽守卫（与 pod rules apply 同一套判定）。'));
  lines.push('');
  lines.push(t('## 结论'));
  lines.push('');
  lines.push(remediation.summary);
  lines.push('');
  lines.push(t('## 处置步骤'));
  lines.push('');
  if (remediation.actions.length === 0) {
    lines.push(t('（没有可用步骤——模型未产出，或产出全部被校验器丢弃）'));
  } else {
    remediation.actions.forEach((action, index) => {
      lines.push(`${index + 1}. **${action.threat}** ${action.step}`);
      if (action.rationale) lines.push(`   ${action.rationale}`);
      if (action.command) {
        lines.push('');
        lines.push('   ```bash');
        lines.push(`   ${action.command}`);
        lines.push('   ```');
      }
    });
  }
  lines.push('');
  lines.push(t('## 规则增量'));
  lines.push('');
  if (remediation.mergedRules) {
    lines.push(t('增量已通过放宽守卫。写入 `rules-suggested.json`（增量）与 `rules-merged.json`（合并结果）。'));
    lines.push('');
    lines.push('```json');
    lines.push(JSON.stringify(remediation.ruleSuggestions, null, 2));
    lines.push('```');
    lines.push('');
    lines.push(t('应用：`pod guard remediate --llm --apply`，或 `pod rules apply` 走签名包通道。'));
  } else if (remediation.relaxations.length > 0) {
    lines.push(t('**被放宽守卫拒绝**——这份增量会削弱现有防线，不应用：'));
    lines.push('');
    for (const item of remediation.relaxations) lines.push(`- ${item}`);
  } else {
    lines.push(t('（本次没有规则增量）'));
  }
  lines.push('');
  if (remediation.rejected.length > 0) {
    lines.push(t('## 被丢弃的模型产出'));
    lines.push('');
    for (const item of remediation.rejected) {
      lines.push(`- ${item.reason}：\`${JSON.stringify(item.raw).slice(0, 160)}\``);
    }
    lines.push('');
  }
  lines.push(t('## 参考：本轮扫描结论'));
  lines.push('');
  lines.push(t('{high} high · {medium} medium · {low} low（完整清单见 guard-report.md）', {
    high: report.findings.filter((f) => f.severity === 'high').length,
    medium: report.findings.filter((f) => f.severity === 'medium').length,
    low: report.findings.filter((f) => f.severity === 'low').length,
  }));
  lines.push('');
  if (remediation.notes.length > 0) {
    for (const note of remediation.notes) lines.push(`- ${note}`);
    lines.push('');
  }
  return lines.join('\n');
}

export { LlmConfigError, renderGuardReport };
