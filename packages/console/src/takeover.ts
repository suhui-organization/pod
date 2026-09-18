import {
  chmodSync,
  copyFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { dirname, join } from 'node:path';
import { appendControlEvent } from '@podsec/audit';
import {
  applyOnboard,
  buildWrapArgs,
  discoverTargets,
  isPodCommand,
  revertOnboard,
  type OnboardTarget,
} from '@podsec/onboard';
import { HARNESSES, expandPattern } from '@podsec/guard';
import { t } from '@podsec/i18n';
import { enrollmentStatePath, readEnrollment } from './enroll.js';

/**
 * 接管：把某个 harness 的 MCP server 包进 pod 网关。
 *
 * 与纳管的差别（也是为什么它要单独一次确认）：
 * - 纳管只写 ~/.pod 下的产物，harness 配置一个字节都不动；
 * - **接管会改写 harness 的配置**（把 command 换成 `pod serve --record-only …`），
 *   所以它必须有备份、必须能回滚、必须把"改前 / 改后"逐条摆给用户看。
 *
 * 三条硬约束：
 * 1. 只改**用户级**配置，不碰仓库里的项目级配置（那是 CurXecute 的面，
 *    改它等于改用户的工作区，超出这个按钮的授权）；
 * 2. `pod` 不在 PATH 上就**拒绝执行**——包装后的命令跑不起来会让用户所有
 *    MCP server 一起失效，这比"没接管"糟得多；
 * 3. 默认 record-only（只录不拦）。接管 ≠ 拦住，这一点写在计划与结果里。
 */

export interface TakeoverServerPlan {
  name: string;
  /** 改前的启动命令 */
  from: string;
  /** 改后的启动命令 */
  to: string;
}

export interface TakeoverEntryPlan {
  configPath: string;
  configLabel: string;
  servers: TakeoverServerPlan[];
  /** 改写前会创建的备份文件（apply 之前是"将要创建"） */
  backupPath: string;
  backupLabel: string;
}

export interface TakeoverPlan {
  harness: string;
  agent: string;
  /** 会被改写的配置（每条带 before/after） */
  entries: TakeoverEntryPlan[];
  /** 会被创建/沿用的包装策略 */
  policyPath: string;
  policyLabel: string;
  /** 沿用已有策略（不新建 allow-all 模板） */
  reusesExistingPolicy: boolean;
  /** 跳过的 server 及原因（已包装 / transport 不支持） */
  skipped: string[];
  /** 配置格式暂不支持自动改写的文件 */
  unsupported: string[];
  /** 必须让用户看见的边界与风险 */
  notes: string[];
  /** false = 不能执行（例如 pod 不在 PATH，或没有可改写的 server） */
  applicable: boolean;
  /** 不可执行的原因 */
  blockedReason: string | null;
}

export interface TakeoverOptions {
  home: string;
  podHome: string;
  harness: string;
  /** 默认取纳管台账里的 agent 名，否则用 harness id */
  agent?: string;
  policyDir?: string;
  auditDir?: string;
  /** 包装命令用的 pod 可执行文件（默认 "pod"，必须在 PATH 上） */
  podBin?: string;
  actor?: string;
  now?: Date;
}

/** pod 是否可执行：绝对路径看文件，裸名字看 PATH */
function podExecutableAvailable(podBin: string): boolean {
  if (podBin.includes('/')) {
    try {
      return statSync(podBin).isFile();
    } catch {
      return false;
    }
  }
  for (const dir of (process.env.PATH ?? '').split(':')) {
    if (!dir) continue;
    const candidate = join(dir, podBin);
    try {
      if (statSync(candidate).isFile()) return true;
    } catch {
      // 继续找
    }
  }
  return false;
}

function tilde(path: string, home: string): string {
  return path.startsWith(`${home}/`) ? `~/${path.slice(home.length + 1)}` : path;
}

function commandLine(command: string, args: string[]): string {
  return [command, ...args]
    .map((part) => (part.includes(' ') ? JSON.stringify(part) : part))
    .join(' ');
}

function configPathsFor(harnessId: string, home: string): string[] {
  const def = HARNESSES.find((h) => h.id === harnessId);
  if (!def) return [];
  const out = new Set<string>();
  for (const spec of def.configs) {
    // 只碰用户级配置：项目级配置属于工作区，不在这个按钮的授权范围内
    if (spec.scope !== 'user') continue;
    for (const file of expandPattern(spec.path, home)) out.add(file);
  }
  return [...out].sort();
}

export function resolveTakeoverAgent(opts: {
  podHome: string;
  harness: string;
  agent?: string;
}): string {
  if (opts.agent) return opts.agent;
  const enrolled = readEnrollment(enrollmentStatePath(opts.podHome)).agents[opts.harness];
  return enrolled?.agent ?? opts.harness;
}

/** 生成接管计划（只读：不写任何文件，不改任何配置） */
export function planTakeover(opts: TakeoverOptions): TakeoverPlan {
  const home = opts.home;
  const podHome = opts.podHome;
  const policyDir = opts.policyDir ?? join(podHome, 'policies');
  const agent = resolveTakeoverAgent({ podHome, harness: opts.harness, ...(opts.agent ? { agent: opts.agent } : {}) });
  const podBin = opts.podBin ?? 'pod';
  const stamp = (opts.now ?? new Date()).toISOString().replace(/[:.]/g, '-');

  const existingEnrollmentPolicy = join(policyDir, `${agent}.json`);
  const reusesExistingPolicy = existsSync(existingEnrollmentPolicy);
  const policyPath = reusesExistingPolicy
    ? existingEnrollmentPolicy
    : join(policyDir, `onboard-${agent}.json`);

  const entries: TakeoverEntryPlan[] = [];
  const skipped: string[] = [];
  const unsupported: string[] = [];
  const targets: OnboardTarget[] = [];

  for (const configPath of configPathsFor(opts.harness, home)) {
    const label = tilde(configPath, home);
    if (configPath.endsWith('.toml')) {
      unsupported.push(
        t('{file}：TOML 配置暂不支持自动改写（`pod onboard` 只写 JSON 形态的 mcpServers）', { file: label }),
      );
      continue;
    }
    const found = discoverTargets({ home, config: configPath, agent });
    if (found.length === 0) {
      unsupported.push(
        t('{file}：没读到可改写的 server 列表（只认 JSON 的 mcpServers 或 servers 数组）', { file: label }),
      );
      continue;
    }
    const target = found[0]!;
    const actionable = target.servers.filter(
      (s) => !s.wrapped && (!s.transport || s.transport === 'stdio'),
    );
    for (const s of target.servers) {
      if (s.wrapped) skipped.push(t('{file} → {name}：已经指向 pod，跳过', { file: label, name: s.name }));
      else if (s.transport && s.transport !== 'stdio') {
        skipped.push(
          t('{file} → {name}：transport={transport}，v0 只支持 stdio', {
            file: label,
            name: s.name,
            transport: s.transport,
          }),
        );
      }
    }
    if (actionable.length === 0) continue;
    targets.push({ ...target, servers: actionable });
    entries.push({
      configPath,
      configLabel: label,
      servers: actionable.map((s) => {
        const wrap = buildWrapArgs(s, agent, policyPath, podBin);
        return {
          name: s.name,
          from: commandLine(s.command, s.args),
          to: commandLine(wrap.command, wrap.args),
        };
      }),
      backupPath: `${configPath}.pod-backup-${stamp}`,
      backupLabel: tilde(`${configPath}.pod-backup-${stamp}`, home),
    });
  }

  const notes: string[] = [
    t('接管会把 MCP server 的启动命令改写为 `pod serve --record-only …`，**默认只录不拦**：先采几天语料，再用 pod policy draft 编译最小权限策略、复核后切执法。'),
    t('改写前会把原配置备份成 <配置>.pod-backup-<时间戳>；移除接管会从最近的备份还原。'),
    t('只改用户级配置，不动仓库里的项目级配置（.mcp.json / .cursor/mcp.json 等）。'),
    t('接管改写了配置：如果你之前跑过 pod posture freeze，之后会看到配置漂移告警——确认这次改写无误后重新 pod posture freeze 即可。'),
  ];
  if (reusesExistingPolicy) {
    notes.push(
      t('包装沿用你已有的策略 {file}（不新建 allow-all 模板）——即使哪天去掉 --record-only，行为也是 fail-closed 而不是全部放行。', {
        file: tilde(policyPath, home),
      }),
    );
  }

  let blockedReason: string | null = null;
  if (!podExecutableAvailable(podBin)) {
    blockedReason = t(
      '在 PATH 上找不到 `{bin}`：包装后的命令会启动失败，导致该 harness 的 MCP server 全部不可用。先安装 pod 或改用 --pod-bin <绝对路径>。',
      { bin: podBin },
    );
  } else if (entries.length === 0) {
    blockedReason =
      unsupported.length > 0
        ? t('这个 harness 的配置格式暂不支持自动改写（见下方说明）；可以手动跑 pod onboard --config <路径> --yes。')
        : t('没有需要接管的 server（可能都已经在网关后面）。');
  }

  return {
    harness: opts.harness,
    agent,
    entries,
    policyPath,
    policyLabel: tilde(policyPath, home),
    reusesExistingPolicy,
    skipped,
    unsupported,
    notes,
    applicable: blockedReason === null,
    blockedReason,
  };
}

// ---------- 接管台账（用于精确回滚与界面展示） ----------

export interface TakeoverRecord {
  agent: string;
  harness: string;
  takenOverAt: string;
  takenOverBy: string;
  configs: Array<{ path: string; backup: string }>;
  policyPath: string;
  /** 当前模式：只录不拦 / 已切执法 */
  mode: 'record-only' | 'enforce';
  /**
   * 每次改写配置都留一条历史（含它自己的备份）。
   * 「还原配置」按"撤销上一步"工作：恢复最近一次备份并弹掉这条历史；
   * 历史空了才移除整条接管记录。
   */
  history: Array<{ at: string; mode: 'record-only' | 'enforce'; configs: Array<{ path: string; backup: string }> }>;
}

export interface TakeoverState {
  v: 1;
  agents: Record<string, TakeoverRecord>;
}

export function takeoverStatePath(podHome: string): string {
  return join(podHome, 'console', 'takeover.json');
}

/** 找到某个 harness 的接管记录（台账按 agent 键，但记录里带 harness） */
export function findTakeoverForHarness(
  state: TakeoverState,
  harness: string,
): TakeoverRecord | null {
  for (const record of Object.values(state.agents)) {
    if (record.harness === harness) return record;
  }
  return null;
}

export function readTakeover(statePath: string): TakeoverState {
  if (!existsSync(statePath)) return { v: 1, agents: {} };
  try {
    const raw = JSON.parse(readFileSync(statePath, 'utf8')) as Partial<TakeoverState>;
    if (raw.v !== 1 || typeof raw.agents !== 'object' || raw.agents === null) return { v: 1, agents: {} };
    return { v: 1, agents: raw.agents };
  } catch {
    return { v: 1, agents: {} };
  }
}

function writeTakeover(statePath: string, state: TakeoverState): void {
  // 必须先建目录：这条路径在 apply 之后才写，若这里 ENOENT，就会出现
  // "配置已经改了、台账没记上"的半截状态（revert 只能靠兜底路径猜）。
  mkdirSync(dirname(statePath), { recursive: true });
  writeFileSync(statePath, JSON.stringify(state, null, 2) + '\n', { encoding: 'utf8', mode: 0o600 });
  // 已存在的文件不会被 mode 改写，显式收紧（台账里有备份路径，属于运维信息）
  try {
    chmodSync(statePath, 0o600);
  } catch {
    // 权限收紧失败不影响功能
  }
}

export interface TakeoverResult {
  agent: string;
  harness: string;
  changed: Array<{ configPath: string; backup: string; servers: string[] }>;
  policyPath: string;
  notes: string[];
}

/** 执行接管：备份 + 改写配置 + 写包装策略 + 入链（唯一的写路径） */
export function applyTakeover(opts: TakeoverOptions): TakeoverResult {
  const plan = planTakeover(opts);
  if (!plan.applicable) throw new Error(plan.blockedReason ?? t('接管计划不可执行'));

  const podHome = opts.podHome;
  const policyDir = opts.policyDir ?? join(podHome, 'policies');
  const auditDir = opts.auditDir ?? join(podHome, 'audit');
  const now = opts.now ?? new Date();
  const actor = opts.actor ?? 'pod ui';

  const targets: OnboardTarget[] = [];
  for (const entry of plan.entries) {
    const found = discoverTargets({ home: opts.home, config: entry.configPath, agent: plan.agent });
    const target = found[0];
    if (!target) continue;
    const actionable = target.servers.filter((s) => !s.wrapped && (!s.transport || s.transport === 'stdio'));
    if (actionable.length > 0) targets.push({ ...target, servers: actionable });
  }

  const result = applyOnboard(targets, {
    policyDir,
    dryRun: false,
    timestamp: now.toISOString().replace(/[:.]/g, '-'),
    podBin: opts.podBin ?? 'pod',
    policyPathFor: () => plan.policyPath,
    // 沿用已有策略时绝不覆盖：包装模板是 allow:['*']，覆盖会把 fail-closed 换成 fail-open
    keepExistingPolicy: plan.reusesExistingPolicy,
  });

  const statePath = takeoverStatePath(podHome);
  const state = readTakeover(statePath);
  const previous = state.agents[plan.agent];
  const written = result.changes.map((c) => ({ path: c.configPath, backup: c.backup ?? '' }));
  state.agents[plan.agent] = {
    agent: plan.agent,
    harness: opts.harness,
    takenOverAt: previous?.takenOverAt ?? now.toISOString(),
    takenOverBy: actor,
    configs: [...(previous?.configs ?? []), ...written],
    policyPath: plan.policyPath,
    mode: 'record-only',
    history: [...(previous?.history ?? []), { at: now.toISOString(), mode: 'record-only', configs: written }],
  };
  writeTakeover(statePath, state);

  appendControlEvent({
    auditDir,
    // 落在被接管的 agent 链上：pod sync 按绑定 agent 过滤，_control 上不了云
    agent: plan.agent,
    kind: 'config-change',
    tool: 'takeover',
    reason: `console:takeover:${plan.agent}:${result.changes.map((c) => c.configPath).join(',')}`,
    payload: {
      agent: plan.agent,
      harness: opts.harness,
      by: actor,
      configs: result.changes.map((c) => ({ path: c.configPath, servers: c.servers, backup: c.backup })),
      policy: plan.policyPath,
      recordOnly: true,
    },
  });

  return {
    agent: plan.agent,
    harness: opts.harness,
    changed: result.changes.map((c) => ({
      configPath: c.configPath,
      backup: c.backup ?? '',
      servers: c.servers,
    })),
    policyPath: plan.policyPath,
    notes: [
      t('已接管：这些 server 现在经过 pod 网关，**只录不拦**（enforced=false）。'),
      t('下一步：用几天后跑 `pod policy draft` 编译最小权限策略，复核后把包装参数里的 --record-only 去掉即切执法。'),
      t('配置已被改写：跑一次 `pod posture freeze` 把新配置记进基线，否则姿态检查会把这次改写报成漂移。'),
    ],
  };
}

export interface RevertResult {
  agent: string;
  restored: Array<{ configPath: string; backup: string }>;
  notes: string[];
}

// ---------- 切执法 / 回到只录不拦 ----------

export interface EnforceServerPlan {
  name: string;
  from: string;
  to: string;
}

export interface EnforceEntryPlan {
  configPath: string;
  configLabel: string;
  servers: EnforceServerPlan[];
  backupPath: string;
  backupLabel: string;
}

export interface PolicySummary {
  servers: number;
  tools: number;
  allow: number;
  approve: number;
  deny: number;
  /** true = 有 server 规则带 allow:["*"]，等于没保护 */
  allowAll: boolean;
}

export interface EnforcePlan {
  harness: string;
  agent: string;
  /** 目标模式：enforce = 切执法；record-only = 回到只录不拦 */
  mode: 'record-only' | 'enforce';
  entries: EnforceEntryPlan[];
  /** 切执法时会写进包装命令的策略 */
  policyPath: string | null;
  policyLabel: string | null;
  policySummary: PolicySummary | null;
  /** 该 agent 目前的审计条目数（语料够不够编译策略的参考） */
  corpus: number;
  skipped: string[];
  notes: string[];
  applicable: boolean;
  blockedReason: string | null;
}

/** 读出策略概要；策略里没有 server 规则就是"还没编译" */
function summarizePolicy(path: string): PolicySummary | null {
  try {
    const parsed = JSON.parse(readFileSync(path, 'utf8')) as {
      servers?: Record<string, { allow?: string[]; approve?: string[]; deny?: string[] }>;
    };
    const servers = parsed.servers ?? {};
    const names = Object.keys(servers);
    const tools = new Set<string>();
    let allow = 0;
    let approve = 0;
    let deny = 0;
    let allowAll = false;
    for (const sp of Object.values(servers)) {
      for (const tool of sp.allow ?? []) {
        allow++;
        tools.add(tool);
        if (tool === '*') allowAll = true;
      }
      for (const tool of sp.approve ?? []) {
        approve++;
        tools.add(tool);
      }
      for (const tool of sp.deny ?? []) {
        deny++;
        tools.add(tool);
      }
    }
    return { servers: names.length, tools: tools.size, allow, approve, deny, allowAll };
  } catch {
    return null;
  }
}

/**
 * 挑出"可以拿来执法"的策略。
 *
 * 只认**含至少一条 server 规则**的策略：接管时写的 `onboard-*.json` 是
 * `allow:["*"]` 的 record 模板，零权限策略是空表——两者拿去执法，前者等于没保护、
 * 后者等于全部拒绝。所以这里宁可拒绝执行，也不让用户点一个"看起来生效了"的按钮。
 */
function pickEnforcementPolicy(
  policyDir: string,
  agent: string,
  wrapperPolicy: string | null,
): { path: string; summary: PolicySummary } | null {
  const candidates: string[] = [];
  const consider = (path: string): void => {
    const base = path.split('/').pop() ?? '';
    if (base.startsWith('onboard-')) return; // record 模板，不用于执法
    const summary = summarizePolicy(path);
    if (!summary || summary.servers === 0) return;
    candidates.push(path);
  };
  if (wrapperPolicy && existsSync(wrapperPolicy)) consider(wrapperPolicy);
  if (existsSync(policyDir)) {
    for (const file of readdirSync(policyDir).filter((f) => f.endsWith('.json'))) {
      const path = join(policyDir, file);
      try {
        const parsed = JSON.parse(readFileSync(path, 'utf8')) as { agent?: unknown };
        if (parsed.agent !== agent) continue;
      } catch {
        continue;
      }
      consider(path);
    }
  }
  const unique = [...new Set(candidates)];
  if (unique.length === 0) return null;
  // 同分取最近修改的一份：用户刚编译出来的那份通常就是想用的
  const newest = unique
    .map((path) => ({ path, mtime: statSync(path).mtimeMs }))
    .sort((a, b) => b.mtime - a.mtime)[0]!;
  const summary = summarizePolicy(newest.path);
  return summary ? { path: newest.path, summary } : null;
}

/** 包装命令的参数改写：只动 --record-only 与 --policy，其余原样保留 */
export function rewriteWrapperArgs(
  args: string[],
  opts: { mode: 'record-only' | 'enforce'; policyPath: string },
): string[] {
  const cleaned: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const arg = args[i]!;
    if (arg === '--record-only') continue;
    if (arg === '--policy') {
      i++; // 丢掉旧值，最后统一写入
      continue;
    }
    cleaned.push(arg);
  }
  // 插在子命令（serve/record）之后，读起来与 pod onboard 生成的命令一致
  if (opts.mode === 'record-only') cleaned.splice(1, 0, '--record-only');
  cleaned.push('--policy', opts.policyPath);
  return cleaned;
}

/** 找到某个 harness 配置里"已进网关"的 server（只有这些才谈得上切执法） */
function wrappedServers(home: string, harness: string, agent: string): OnboardTarget[] {
  const out: OnboardTarget[] = [];
  for (const configPath of configPathsFor(harness, home)) {
    if (configPath.endsWith('.toml')) continue;
    for (const target of discoverTargets({ home, config: configPath, agent })) {
      const wrapped = target.servers.filter((s) => isPodCommand(s.command, s.args));
      if (wrapped.length > 0) out.push({ ...target, servers: wrapped });
    }
  }
  return out;
}

/**
 * 语料量：该 agent 审计目录里的**数据平面**记录条数
 * （给"够不够编译策略"一个具体数字）。
 *
 * 必须排除控制平面链：identity / config-change 这类事件不是工具调用，
 * 算进语料会让人以为"我已经采到 N 条调用了"，拿一张空表去切执法。
 * 数字骗人比没有数字更糟。
 */
function countCorpus(auditDir: string, agent: string): number {
  const dir = join(auditDir, agent);
  if (!existsSync(dir)) return 0;
  let total = 0;
  try {
    for (const file of readdirSync(dir).filter((f) => f.endsWith('.jsonl'))) {
      if (file === 'control.jsonl') continue; // 控制平面链不算语料
      const path = join(dir, file);
      // 与聚合层同一个上限：异常大的日志不整份读进来
      if (statSync(path).size > 8 * 1024 * 1024) continue;
      for (const line of readFileSync(path, 'utf8').split('\n')) {
        if (!line.trim()) continue;
        try {
          const kind = (JSON.parse(line) as { kind?: string }).kind;
          if (kind === undefined || kind === 'tool-call') total++;
        } catch {
          // 解析失败的行不计入语料（由 pod verify-audit 负责报）
        }
      }
    }
  } catch {
    return total;
  }
  return total;
}

export function planEnforcement(opts: TakeoverOptions & { mode: 'record-only' | 'enforce' }): EnforcePlan {
  const home = opts.home;
  const podHome = opts.podHome;
  const policyDir = opts.policyDir ?? join(podHome, 'policies');
  const agent = resolveTakeoverAgent({ podHome, harness: opts.harness, ...(opts.agent ? { agent: opts.agent } : {}) });
  const stamp = (opts.now ?? new Date()).toISOString().replace(/[:.]/g, '-');
  const wantRecordOnly = opts.mode === 'record-only';

  const targets = wrappedServers(home, opts.harness, agent);
  const entries: EnforceEntryPlan[] = [];
  const skipped: string[] = [];

  // 现有策略：从包装命令里读出来（它决定"切执法"时要不要换文件）
  let wrapperPolicy: string | null = null;
  for (const target of targets) {
    for (const server of target.servers) {
      const idx = server.args.indexOf('--policy');
      if (idx !== -1 && server.args[idx + 1]) wrapperPolicy = server.args[idx + 1]!;
    }
  }

  const picked = wantRecordOnly ? null : pickEnforcementPolicy(policyDir, agent, wrapperPolicy);
  const policyPath = wantRecordOnly ? wrapperPolicy ?? join(policyDir, `${agent}.json`) : picked?.path ?? null;
  const corpus = countCorpus(opts.auditDir ?? join(podHome, 'audit'), agent);

  // 切执法但没有可用的策略：直接给一份"不可执行"的计划，不进改写循环
  if (!wantRecordOnly && !picked) {
    return {
      harness: opts.harness,
      agent,
      mode: opts.mode,
      entries: [],
      policyPath: null,
      policyLabel: null,
      policySummary: null,
      corpus,
      skipped: [],
      notes: [],
      applicable: false,
      blockedReason: t(
        '没有可用于执法的策略：`policies/` 下没有绑定 agent {agent} 且含 server 规则的策略文件。先跑 `pod policy draft --agent {agent} --out <file>` 并复核（当前审计语料 {corpus} 条）。',
        { agent, corpus },
      ),
    };
  }

  for (const target of targets) {
    const actionable = target.servers.filter((s) =>
      wantRecordOnly ? !s.args.includes('--record-only') : s.args.includes('--record-only'),
    );
    for (const server of target.servers) {
      if (actionable.includes(server)) continue;
      skipped.push(
        wantRecordOnly
          ? t('{name}：已经是只录不拦，跳过', { name: server.name })
          : t('{name}：已经不在只录模式，跳过', { name: server.name }),
      );
    }
    if (actionable.length === 0) continue;
    entries.push({
      configPath: target.configPath,
      configLabel: tilde(target.configPath, home),
      servers: actionable.map((s) => ({
        name: s.name,
        from: commandLine(s.command, s.args),
        to: commandLine(
          s.command,
          rewriteWrapperArgs(s.args, { mode: opts.mode, policyPath: policyPath ?? (wrapperPolicy ?? '') }),
        ),
      })),
      backupPath: `${target.configPath}.pod-backup-${stamp}`,
      backupLabel: tilde(`${target.configPath}.pod-backup-${stamp}`, home),
    });
  }

  const notes: string[] = wantRecordOnly
    ? [t('回到只录不拦：策略不变，只是不再阻断——用来在执法打断工作流时快速退一步。')]
    : [
        t('切执法后，命中 approve 的调用会挂起等审批（超时按拒绝处理）。没在跑 `pod watch` 的话，它们会等到超时被拒——这是 fail-closed，不是故障。'),
        t('想免掉人工审批又要保持可审计：用 `pod grant issue` 签发限时/限作用域令牌。'),
        t('策略是刚从语料编译出来的话，先跑 `pod lint --policy <file>` 并人工复核一遍——执法改动直接影响 agent 能不能干活。'),
      ];

  let blockedReason: string | null = null;
  if (entries.length === 0) {
    blockedReason = wantRecordOnly
      ? t('没有处于执法模式的 server（可能已经都在只录不拦）。')
      : t('没有处于只录不拦的 server（先用「接管」把 server 包进网关）。');
  } else if (!wantRecordOnly && picked?.summary.allowAll) {
    blockedReason = t(
      '策略 {file} 的 server 规则是 allow:["*"]（等于全部放行）——直接切执法只会让人以为已经保护了。请先编译最小权限策略。',
      { file: tilde(picked.path, home) },
    );
  }

  return {
    harness: opts.harness,
    agent,
    mode: opts.mode,
    entries,
    policyPath,
    policyLabel: policyPath ? tilde(policyPath, home) : null,
    policySummary: picked?.summary ?? (policyPath ? summarizePolicy(policyPath) : null),
    corpus,
    skipped,
    notes,
    applicable: blockedReason === null,
    blockedReason,
  };
}

/** 还原接管：从最近的备份恢复被改写的配置 */
export interface EnforceResult {
  agent: string;
  harness: string;
  mode: 'record-only' | 'enforce';
  changed: Array<{ configPath: string; backup: string; servers: string[] }>;
  policyPath: string | null;
  notes: string[];
}

/**
 * 切执法 / 回到只录不拦：只动包装命令里的 `--record-only` 与 `--policy`。
 *
 * 与接管共用一条纪律：改写前备份、改动入链、可逐步撤销。区别是它**不新建包装策略**
 * ——执法用的策略必须是用户已经编译并复核过的那份（见 planEnforcement 的前置检查）。
 */
export function applyEnforcement(
  opts: TakeoverOptions & { mode: 'record-only' | 'enforce' },
): EnforceResult {
  const plan = planEnforcement(opts);
  if (!plan.applicable) throw new Error(plan.blockedReason ?? t('执法计划不可执行'));

  const podHome = opts.podHome;
  const auditDir = opts.auditDir ?? join(podHome, 'audit');
  const now = opts.now ?? new Date();
  const actor = opts.actor ?? 'pod ui';
  const stamp = now.toISOString().replace(/[:.]/g, '-');
  const changed: EnforceResult['changed'] = [];

  for (const entry of plan.entries) {
    const raw = JSON.parse(readFileSync(entry.configPath, 'utf8')) as Record<string, unknown>;
    const target = discoverTargets({ home: opts.home, config: entry.configPath, agent: plan.agent })[0];
    if (!target) continue;
    const toChange = target.servers.filter((s) =>
      opts.mode === 'record-only' ? !s.args.includes('--record-only') : s.args.includes('--record-only'),
    );
    for (const server of toChange) {
      const nextArgs = rewriteWrapperArgs(server.args, {
        mode: opts.mode,
        policyPath: plan.policyPath ?? '',
      });
      if (server.location.kind === 'array') {
        const arr = raw.servers as Array<Record<string, unknown>>;
        const item = arr[server.location.index]!;
        item.args = nextArgs;
      } else {
        const obj = raw.mcpServers as Record<string, Record<string, unknown>>;
        const item = obj[server.location.key]!;
        item.args = nextArgs;
      }
    }
    // 与 pod onboard 同一条纪律：改写前先备份
    const backup = `${entry.configPath}.pod-backup-${stamp}`;
    copyFileSync(entry.configPath, backup);
    writeFileSync(entry.configPath, JSON.stringify(raw, null, 2) + '\n', 'utf8');
    changed.push({ configPath: entry.configPath, backup, servers: toChange.map((s) => s.name) });
  }

  const statePath = takeoverStatePath(podHome);
  const state = readTakeover(statePath);
  const previous = state.agents[plan.agent];
  const written = changed.map((c) => ({ path: c.configPath, backup: c.backup }));
  state.agents[plan.agent] = {
    agent: plan.agent,
    harness: previous?.harness ?? opts.harness,
    takenOverAt: previous?.takenOverAt ?? now.toISOString(),
    takenOverBy: previous?.takenOverBy ?? actor,
    configs: [...(previous?.configs ?? []), ...written],
    policyPath: plan.policyPath ?? previous?.policyPath ?? '',
    mode: opts.mode,
    history: [...(previous?.history ?? []), { at: now.toISOString(), mode: opts.mode, configs: written }],
  };
  writeTakeover(statePath, state);

  appendControlEvent({
    auditDir,
    // 同接管：写进该 agent 的链，才会被 pod sync 带上云（按绑定 agent 过滤）
    agent: plan.agent,
    kind: 'config-change',
    tool: opts.mode === 'enforce' ? 'enforce' : 'record-only',
    reason: `console:${opts.mode === 'enforce' ? 'enforce' : 'record-only'}:${plan.agent}`,
    payload: {
      agent: plan.agent,
      harness: opts.harness,
      by: actor,
      policy: plan.policyPath,
      configs: changed.map((c) => ({ path: c.configPath, servers: c.servers, backup: c.backup })),
    },
  });

  return {
    agent: plan.agent,
    harness: opts.harness,
    mode: opts.mode,
    changed,
    policyPath: plan.policyPath,
    notes:
      opts.mode === 'enforce'
        ? [
            t('已切执法：网关现在会按策略判定 deny / approve / allow（未登记的一律拒绝）。'),
            t('命中 approve 的调用会挂起等审批；没在跑 `pod watch` 就会等超时被拒（fail-closed）。'),
            t('要退回可以用卡片上的「回到只录不拦」，或「还原配置」恢复到接管之前。'),
          ]
        : [t('已回到只录不拦：策略不变，只是不再阻断。')],
  };
}

export function revertTakeover(opts: {
  home: string;
  podHome: string;
  agent: string;
  actor?: string;
}): RevertResult {
  const podHome = opts.podHome;
  const auditDir = join(podHome, 'audit');
  const statePath = takeoverStatePath(podHome);
  const state = readTakeover(statePath);
  const record = state.agents[opts.agent];
  const notes: string[] = [];

  // 优先按台账里的配置路径还原；没有台账就按 harness 的候选路径兜底
  const configPaths = record
    ? [...new Set(record.configs.map((c) => c.path))]
    : configPathsFor(opts.agent, opts.home);

  const restored: Array<{ configPath: string; backup: string }> = [];
  for (const configPath of configPaths) {
    if (!existsSync(configPath)) continue;
    for (const item of revertOnboard({ home: opts.home, config: configPath })) {
      restored.push({ configPath: item.configPath, backup: item.backup });
    }
  }

  if (!record) {
    notes.push(t('台账里没有这个 agent 的接管记录；已按该 harness 的配置路径尝试从最近备份还原。'));
  }
  if (restored.length === 0) {
    notes.push(t('没有找到可还原的备份（可能已经还原过，或配置文件被移动了）。'));
  } else {
    notes.push(t('已从最近的备份还原。策略文件与审计记录保留——它们不是配置的一部分。'));
  }

  if (record) {
    // 「还原配置」是"撤销上一步"：弹掉最近一条历史；历史空了才结束这次接管
    const history = record.history ?? [];
    const popped = history.slice(0, -1);
    if (popped.length === 0) {
      delete state.agents[opts.agent];
    } else {
      const last = popped[popped.length - 1]!;
      state.agents[opts.agent] = {
        ...record,
        mode: last.mode,
        history: popped,
        configs: popped.flatMap((h) => h.configs),
      };
      notes.push(t('还可以继续撤销：再点一次「还原配置」会退到上一步（当前 {mode}）。', { mode: last.mode }));
    }
  }
  writeTakeover(statePath, state);

  appendControlEvent({
    auditDir,
    // 同接管：写进该 agent 的链，才会被 pod sync 带上云（按绑定 agent 过滤）
    agent: opts.agent,
    kind: 'config-change',
    tool: 'revert',
    reason: `console:revert:${opts.agent}`,
    payload: { agent: opts.agent, by: opts.actor ?? 'pod ui', restored },
  });

  return { agent: opts.agent, restored, notes };
}
