/**
 * 用户可编辑的规则集（控制平面加固，见 docs/control-plane-hardening.md §2.1）。
 *
 * 立场：**判定规则属于用户，代码只提供默认值。**
 * - 任何一条规则都能被 `~/.pod/rules.json` 覆盖，数组是整体替换（不是叠加），
 *   所以用户写 `"riskPatterns": []` 就等于关掉这类判定；
 * - 解析/校验失败一律抛错（fail-closed），不静默退回默认值——否则用户以为
 *   自己收紧了规则，实际跑的是默认值。
 */
import { existsSync, readFileSync } from 'node:fs';

export type Severity = 'high' | 'medium' | 'low';

export interface RulePattern {
  id: string;
  /** 正则源码（字符串，便于写进 JSON） */
  re: string;
  severity: Severity;
  /** 命中原因，出现在报表里 */
  why?: string;
}

export interface HookWatchPath {
  /** 支持 ~ 展开；含 * 时按 glob 匹配 */
  path: string;
  format: 'claude-hooks' | 'pod-hooks' | 'launchd';
}

export interface HookRiskRules {
  watchPaths: HookWatchPath[];
  riskPatterns: RulePattern[];
  /** 命中的钩子若来自这些 glob，降级为 low（自己写的钩子别天天报警） */
  trustedSources: string[];
  /** true = 钩子配置文件没有配套 .sig 签名就报告 */
  requireSigned: boolean;
}

export interface FreezeRules {
  paths: string[];
  /** true = 冻结项漂移按 high 报；false = medium */
  requireApprovalToChange: boolean;
}

export interface IdentityRules {
  dir: string;
  algorithm: 'ed25519';
  /** true = 有策略/审计记录却没有身份的 agent 也要报 */
  required: boolean;
}

export interface DelegationRuleConfig {
  dir: string;
  policyDirs: string[];
  maxDepth: number;
  requireSubset: boolean;
  forbiddenEscalation: string[];
}

export interface AnomalyRules {
  windowMinutes: number;
  /** 同一窗口内委托签发次数上限 */
  delegationsPerWindow: number;
  /** 同一窗口内高风险能力种类上限 */
  capabilitiesPerWindow: number;
  highRiskCapabilities: string[];
}

export interface MemoryRules {
  paths: string[];
  maxFileBytes: number;
}

export interface PackageRules {
  requireVersionPin: boolean;
  /** true = 必须能在基线里找到该 server 的完整性指纹 */
  requireIntegrity: boolean;
}

export interface MetadataRules {
  suspiciousPatterns: RulePattern[];
  /**
   * true = 命中「置信级别 ≥ blockAtOrAbove」的模式时，把该工具**从 tools/list 里摘掉**。
   *
   * 摘掉而不是报错：G6 的攻击面是工具**描述**这段自由文本，把描述从 agent 眼前拿走
   * 就切断了影响路径；工具本身仍受策略管辖（agent 硬报名字调用照样会被策略判定）。
   */
  block: boolean;
  /** 达到这个级别才摘除（默认 high）。低级别只记账 */
  blockAtOrAbove: Severity;
}

/**
 * 注入信号：子串匹配 + 置信级别。
 *
 * 刻意不做正则——词表是写给人看的，正则容易写错，而写错的代价是 fail-closed。
 * 级别决定"只标记"还是"阻断"：`system prompt` 这种词在正常文档里天天出现，
 * 把它按 high 处理就等于让网关开始随机打断正常工具调用。
 */
export interface InjectionSignal {
  id: string;
  /** 子串（大小写不敏感） */
  text: string;
  severity: Severity;
  why?: string;
}

export interface InjectionRules {
  signals: InjectionSignal[];
  /**
   * 主开关（默认 true）：命中「置信级别 ≥ blockAtOrAbove」的信号时阻断该次工具响应。
   * 只打标是不够的——被污染的内容仍会回到 agent 上下文并影响它下一步的决策。
   */
  block: boolean;
  /** 达到这个级别才阻断（默认 high）。低级别只写 `injection_suspect` 审计 */
  blockAtOrAbove: Severity;
}

/** 置信级别的强弱序：high > medium > low。全项目共用一份，避免两处口径漂移 */
export const SEVERITY_RANK: Record<Severity, number> = { low: 0, medium: 1, high: 2 };

export function severityRank(severity: Severity): number {
  return SEVERITY_RANK[severity] ?? 0;
}

export interface EgressRules {
  enabled: boolean;
  /** 空 = 不限制 */
  allowHosts: string[];
  denyHosts: string[];
  /** 未命中任何列表时的决策 */
  defaultDecision: 'allow' | 'approve' | 'deny';
}

export interface QuarantineRules {
  /** 熔断状态文件；网关每次调用前读它 */
  file: string;
}

export interface GrantRules {
  dir: string;
  /** true = approve 决策必须有有效令牌，不走交互审批兜底 */
  requiredForApprove: boolean;
}

export interface AuditExpectation {
  agent: string;
  /** 这个 agent 期望的最大空闲小时数（覆盖 auditHealth.maxIdleHours） */
  maxIdleHours: number;
  /** 为什么这么设，只用于报表与日后回顾 */
  why?: string;
}

export interface AuditHealthRules {
  /** true = 检查审计链本身（断裂 / 长时间无写入） */
  enabled: boolean;
  /** 未在 expectations 中列出的 agent 用这个阈值 */
  maxIdleHours: number;
  /** 完全不检查的 agent（测试用 agent、已废弃的 agent） */
  ignore: string[];
  /**
   * 逐 agent 的期望活跃度。语义是"我知道它应该多久动一次"：
   * 每天在用的 agent 给 6h，偶尔用的给 720h。闲置 agent 的阈值放宽后，
   * "空闲"和"写入失败"就不再互相冒充了。
   */
  expectations: AuditExpectation[];
}

export interface RuleSet {
  version: string;
  hookRisk: HookRiskRules;
  freeze: FreezeRules;
  identity: IdentityRules;
  delegation: DelegationRuleConfig;
  anomaly: AnomalyRules;
  memory: MemoryRules;
  packages: PackageRules;
  toolMetadata: MetadataRules;
  injection: InjectionRules;
  egress: EgressRules;
  quarantine: QuarantineRules;
  grant: GrantRules;
  auditHealth: AuditHealthRules;
}

export const DEFAULT_RULES: RuleSet = {
  version: '1',
  hookRisk: {
    watchPaths: [
      { path: '~/.claude/settings.json', format: 'claude-hooks' },
      { path: '~/.pod/hooks.json', format: 'pod-hooks' },
      { path: '~/Library/LaunchAgents/com.pod*.plist', format: 'launchd' },
    ],
    riskPatterns: [
      { id: 'net-egress', re: '\\b(curl|wget|nc|ncat|scp|ssh)\\b', severity: 'high', why: '钩子里出现网络出口' },
      { id: 'persistence', re: 'launchctl|crontab|LaunchAgents|systemctl', severity: 'high', why: '钩子建立持久化' },
      { id: 'shell-init', re: '\\.(zshrc|bashrc|bash_profile|profile)\\b', severity: 'high', why: '钩子改写 shell 启动文件' },
      { id: 'encoded-payload', re: 'base64\\s+-d|\\beval\\b|python3?\\s+-c', severity: 'medium', why: '钩子执行编码/动态载荷' },
    ],
    trustedSources: ['~/.claude/plugins/local/**', '~/.pod/**'],
    requireSigned: false,
  },
  freeze: {
    paths: [
      '~/.claude/settings.json',
      '~/.claude.json',
      '~/.codex/config.toml',
      '~/.dsh/mcp-manager.json',
      '~/.cursor/mcp.json',
    ],
    requireApprovalToChange: true,
  },
  identity: { dir: '~/.pod/identity', algorithm: 'ed25519', required: true },
  delegation: {
    dir: '~/.pod/delegations',
    policyDirs: ['~/.pod/policies'],
    maxDepth: 2,
    requireSubset: true,
    forbiddenEscalation: ['exec', 'credential-access', 'destructive-write'],
  },
  anomaly: {
    windowMinutes: 60,
    delegationsPerWindow: 5,
    capabilitiesPerWindow: 6,
    highRiskCapabilities: ['exec', 'credential-access', 'destructive-write', 'external-communication'],
  },
  memory: {
    paths: ['~/.claude/CLAUDE.md', '~/.codex/AGENTS.md', '~/.pod/memory/**'],
    maxFileBytes: 1_000_000,
  },
  packages: { requireVersionPin: true, requireIntegrity: false },
  toolMetadata: {
    suspiciousPatterns: [
      { id: 'hidden-instruction', re: 'ignore (all )?(previous|above)|忽略(之前|上面)|do not tell', severity: 'high', why: '工具描述里藏着指令' },
      { id: 'credential-harvest', re: '\\.env|credentials|id_rsa|\\.ssh', severity: 'high', why: '工具描述指向凭据文件' },
      { id: 'remote-endpoint', re: 'https?://(?!localhost|127\\.0\\.0\\.1)', severity: 'medium', why: '工具描述里带外部端点' },
    ],
    // 默认摘除 high 命中的工具（描述里的隐藏指令 / 凭据挖掘），medium 只记账
    block: true,
    blockAtOrAbove: 'high',
  },
  injection: {
    signals: [
      // ---- high：几乎只出现在攻击里，命中即阻断 ----
      { id: 'ignore-previous', text: 'ignore previous', severity: 'high', why: '覆盖既有指令的典型句式' },
      { id: 'ignore-all-previous', text: 'ignore all previous', severity: 'high', why: '同上' },
      { id: 'ignore-prior', text: 'ignore prior', severity: 'high', why: '同上' },
      { id: 'disregard-previous', text: 'disregard previous', severity: 'high', why: '同上' },
      { id: 'disregard-all-previous', text: 'disregard all previous', severity: 'high', why: '同上' },
      { id: 'zh-ignore-before', text: '忽略之前', severity: 'high', why: '同上（中文）' },
      { id: 'zh-ignore-above', text: '忽略上面', severity: 'high', why: '同上（中文）' },
      { id: 'zh-ignore-above2', text: '忽略以上', severity: 'high', why: '同上（中文）' },
      { id: 'do-not-tell', text: 'do not tell the user', severity: 'high', why: '要求隐瞒本身就是注入目标' },
      { id: 'zh-do-not-tell', text: '不要告诉用户', severity: 'high', why: '同上（中文）' },
      { id: 'exfiltrate', text: 'exfiltrate', severity: 'high', why: '直接谈论外泄' },
      { id: 'zh-send-secret', text: '把密钥发给我', severity: 'high', why: '直白索取密钥' },
      // ---- medium / low：正常文本里也会出现，默认只标记 ----
      { id: 'jailbreak', text: 'jailbreak', severity: 'medium', why: '可能是讨论，也可能是攻击' },
      { id: 'developer-mode', text: 'developer mode', severity: 'medium', why: '同上' },
      { id: 'system-prompt', text: 'system prompt', severity: 'low', why: '正常文档/讨论里很常见，只标记' },
      { id: 'you-are-now', text: 'you are now', severity: 'low', why: '正常行文也会出现，只标记' },
    ],
    block: true,
    // 只有 high 才阻断：这是"默认打开阻断"能站得住的前提
    blockAtOrAbove: 'high',
  },
  egress: {
    enabled: false,
    allowHosts: [],
    denyHosts: [],
    defaultDecision: 'allow',
  },
  quarantine: { file: '~/.pod/quarantine.json' },
  grant: { dir: '~/.pod/grants', requiredForApprove: false },
  auditHealth: { enabled: true, maxIdleHours: 72, ignore: [], expectations: [] },
};

type DeepPartial<T> = {
  [K in keyof T]?: T[K] extends readonly unknown[] ? T[K] : T[K] extends object ? DeepPartial<T[K]> : T[K];
};

export type RuleSetOverride = DeepPartial<RuleSet>;

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * 把旧版 `signals: ["ignore previous", …]`（字符串数组）归一成分级对象数组。
 *
 * 兼容策略是**降级而不是报错**：老写法按低置信（low）处理 → 只标记、不阻断。
 * 这样升级 pod 不会让老配置突然开始拦工具调用；想让它阻断，补一个 severity 即可。
 * 反过来"默认按 high 处理"会让所有老配置在升级当天开始误伤——那才是不可接受的方向。
 */
export function normalizeInjectionSignals(value: unknown): InjectionSignal[] {
  if (!Array.isArray(value)) return [];
  const out: InjectionSignal[] = [];
  value.forEach((item, i) => {
    if (typeof item === 'string') {
      const text = item.trim();
      if (text) {
        out.push({
          id: `legacy-${i + 1}`,
          text,
          severity: 'low',
          why: '旧版字符串写法，按低置信处理（只标记，不阻断）',
        });
      }
      return;
    }
    out.push(item as InjectionSignal);
  });
  return out;
}

/** 归一化：目前只有 injection.signals 有历史格式需要兼容 */
export function normalizeRules(rules: RuleSet): RuleSet {
  const raw = rules.injection?.signals;
  if (!Array.isArray(raw) || !raw.some((s) => typeof s === 'string')) return rules;
  return { ...rules, injection: { ...rules.injection, signals: normalizeInjectionSignals(raw) } };
}

/**
 * 深合并：对象逐键合并，数组整体替换（用户写 [] 就是关掉这项）。
 *
 * 合并在出口做一次归一化（`normalizeRules`）：这是所有用户配置的必经点
 * （loadRules / rules pack apply / 测试里的 mergeRules 都走它），
 * 在这里统一处理比让每个调用方各自兼容老格式更不容易漏。
 */
export function mergeRules(base: RuleSet, override: unknown): RuleSet {
  const merge = (b: unknown, o: unknown): unknown => {
    if (o === undefined) return b;
    if (Array.isArray(o)) return o;
    if (isPlainObject(b) && isPlainObject(o)) {
      const out: Record<string, unknown> = { ...b };
      for (const [key, value] of Object.entries(o)) {
        out[key] = merge((b as Record<string, unknown>)[key], value);
      }
      return out;
    }
    return o;
  };
  return normalizeRules(merge(base, override) as RuleSet);
}

export class RuleSetError extends Error {}

const SEVERITIES: Severity[] = ['high', 'medium', 'low'];

/** 校验规则集；任何一处不合法都抛错（fail-closed） */
export function validateRules(rules: RuleSet): void {
  if (rules.identity.algorithm !== 'ed25519') {
    throw new RuleSetError(`identity.algorithm 只支持 ed25519，收到 "${String(rules.identity.algorithm)}"`);
  }
  const patternGroups: Array<[string, RulePattern[]]> = [
    ['hookRisk.riskPatterns', rules.hookRisk.riskPatterns],
    ['toolMetadata.suspiciousPatterns', rules.toolMetadata.suspiciousPatterns],
  ];
  for (const [where, patterns] of patternGroups) {
    if (!Array.isArray(patterns)) throw new RuleSetError(`${where} 必须是数组`);
    for (const p of patterns) {
      if (!p?.id || !p.re) throw new RuleSetError(`${where} 的每条规则都要有 id 与 re`);
      if (!SEVERITIES.includes(p.severity)) {
        throw new RuleSetError(`${where}["${p.id}"].severity 必须是 high|medium|low`);
      }
      try {
        new RegExp(p.re);
      } catch (err) {
        throw new RuleSetError(`${where}["${p.id}"].re 不是合法正则: ${err instanceof Error ? err.message : String(err)}`);
      }
    }
  }
  for (const [where, list] of [
    ['freeze.paths', rules.freeze.paths],
    ['memory.paths', rules.memory.paths],
    ['hookRisk.watchPaths', rules.hookRisk.watchPaths],
  ] as const) {
    if (!Array.isArray(list)) throw new RuleSetError(`${where} 必须是数组`);
  }
  if (!['allow', 'approve', 'deny'].includes(rules.egress.defaultDecision)) {
    throw new RuleSetError('egress.defaultDecision 必须是 allow|approve|deny');
  }
  if (typeof rules.injection.block !== 'boolean') {
    throw new RuleSetError('injection.block 必须是布尔值（true=命中注入信号即阻断该次响应）');
  }
  if (!SEVERITIES.includes(rules.injection.blockAtOrAbove)) {
    throw new RuleSetError(
      `injection.blockAtOrAbove 必须是 high|medium|low，收到 ${JSON.stringify(rules.injection.blockAtOrAbove)}`,
    );
  }
  if (!Array.isArray(rules.injection.signals)) {
    throw new RuleSetError('injection.signals 必须是数组（每项 {id, text, severity}，旧版字符串也接受）');
  }
  for (const s of rules.injection.signals) {
    if (!s?.id || typeof s.text !== 'string' || s.text.trim() === '') {
      throw new RuleSetError('injection.signals 每项需要 id 与非空 text');
    }
    if (!SEVERITIES.includes(s.severity)) {
      throw new RuleSetError(`injection.signals["${s.id}"].severity 必须是 high|medium|low`);
    }
  }
  if (typeof rules.toolMetadata.block !== 'boolean') {
    throw new RuleSetError('toolMetadata.block 必须是布尔值（true=命中即从 tools/list 摘除该工具）');
  }
  if (!SEVERITIES.includes(rules.toolMetadata.blockAtOrAbove)) {
    throw new RuleSetError(
      `toolMetadata.blockAtOrAbove 必须是 high|medium|low，收到 ${JSON.stringify(rules.toolMetadata.blockAtOrAbove)}`,
    );
  }
  if (!Array.isArray(rules.auditHealth.expectations)) {
    throw new RuleSetError('auditHealth.expectations 必须是数组');
  }
  for (const e of rules.auditHealth.expectations) {
    if (!e?.agent || typeof e.maxIdleHours !== 'number' || Number.isNaN(e.maxIdleHours) || e.maxIdleHours < 0) {
      throw new RuleSetError('auditHealth.expectations 每项需要 agent 与非负的 maxIdleHours');
    }
  }
  for (const [where, value] of [
    ['delegation.maxDepth', rules.delegation.maxDepth],
    ['anomaly.windowMinutes', rules.anomaly.windowMinutes],
    ['memory.maxFileBytes', rules.memory.maxFileBytes],
    ['auditHealth.maxIdleHours', rules.auditHealth.maxIdleHours],
  ] as const) {
    if (typeof value !== 'number' || Number.isNaN(value) || value < 0) {
      throw new RuleSetError(`${where} 必须是非负数`);
    }
  }
}

export function expandHome(path: string, home: string): string {
  if (path === '~') return home;
  if (path.startsWith('~/')) return `${home}/${path.slice(2)}`;
  return path;
}

/** 读取规则文件并与默认值合并；文件不存在时返回默认值 */
export function loadRules(path: string | null | undefined): RuleSet {
  if (!path || !existsSync(path)) {
    validateRules(DEFAULT_RULES);
    return DEFAULT_RULES;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(path, 'utf8'));
  } catch (err) {
    throw new RuleSetError(`规则文件不是合法 JSON: ${path} (${err instanceof Error ? err.message : String(err)})`);
  }
  const merged = mergeRules(DEFAULT_RULES, parsed);
  validateRules(merged);
  return merged;
}
