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
}

export interface InjectionRules {
  signals: string[];
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

export interface AuditHealthRules {
  /** true = 检查审计链本身（断裂 / 长时间无写入） */
  enabled: boolean;
  /** 超过这个小时数没有新记录就告警（钩子静默失败的主要信号） */
  maxIdleHours: number;
  /** 只检查这些 agent；空数组 = 审计目录里发现的所有 agent */
  agents: string[];
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
  },
  injection: {
    signals: [
      'ignore previous',
      'ignore all previous',
      '忽略之前',
      '忽略上面',
      'system prompt',
      'you are now',
      'do not tell the user',
      'exfiltrate',
    ],
  },
  egress: {
    enabled: false,
    allowHosts: [],
    denyHosts: [],
    defaultDecision: 'allow',
  },
  quarantine: { file: '~/.pod/quarantine.json' },
  grant: { dir: '~/.pod/grants', requiredForApprove: false },
  auditHealth: { enabled: true, maxIdleHours: 72, agents: [] },
};

type DeepPartial<T> = {
  [K in keyof T]?: T[K] extends readonly unknown[] ? T[K] : T[K] extends object ? DeepPartial<T[K]> : T[K];
};

export type RuleSetOverride = DeepPartial<RuleSet>;

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** 深合并：对象逐键合并，数组整体替换（用户写 [] 就是关掉这项） */
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
  return merge(base, override) as RuleSet;
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
