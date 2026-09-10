/**
 * 策略求值器 v0（threat-model.md 的决策核心）。
 *
 * 设计原则（D2）：
 * - 三态决策：deny > approve > allow（拒绝优先，规则冲突时取更严格者）；
 * - fail-closed：未显式授权的工具/未登记的 server 一律拒绝；
 * - 规则为工具名精确匹配或 "*" 通配，v0 不引入 DSL；
 * - 纯函数、无副作用，便于 100% 单测。
 */

export type Decision = 'allow' | 'deny' | 'approve';

export interface ToolRule {
  allow?: string[];
  approve?: string[];
  deny?: string[];
}

/**
 * server 来源白名单（T4，供应链防线）：
 * 策略声明该 server 的合法启动来源，pod serve/record 启动时校验，
 * 不匹配拒绝启动（防配置被篡改指向恶意/未锁定 server）。
 */
export interface ServerSource {
  /** 允许的启动命令（精确匹配，如 "mcp-server-filesystem"） */
  command?: string;
  /** 允许的 npm 包名（从 npx args 解析，如 "@modelcontextprotocol/server-github"） */
  package?: string;
  /** 允许的包版本（精确；缺省 = 任意版本，lint 会提示未锁定） */
  version?: string;
}

export interface ServerPolicy extends ToolRule {
  source?: ServerSource;
}

/**
 * 敏感信息规则（P0，威胁 T2）：
 * - deny_input_paths：参数中的字符串命中这些路径模式（如 "~/.ssh"、".env"）→ 调用直接拒绝；
 *   匹配前先归一化（展开 ~ / ./ / 多余分隔符），再按路径段匹配：
 *   "~/.ssh" 命中任意位置的 ".ssh" 段，".env" 命中 ".env" / ".env.local"；
 * - deny_output_matching：工具响应的文本命中这些正则 → 网关阻断该响应（在 gateway 层执行）。
 */
export interface SecretRules {
  deny_input_paths?: string[];
  deny_output_matching?: string[];
  /** 输出侧熵检测（P2）：正则之外的未知格式密钥兜底 */
  entropy?: EntropyRules;
}

export interface EntropyRules {
  enabled?: boolean;
  /** 候选串最小长度，默认 24 */
  min_length?: number;
  /** 香农熵阈值（bits/char），默认 4.5；hex 哈希上限 4.0，不会被误伤 */
  threshold?: number;
  /** true（默认）= 命中即阻断；false = 仅审计标记 */
  block?: boolean;
  /** 命中这些正则的候选串跳过（如 UUID、已知哈希格式） */
  allow_patterns?: string[];
}

export interface EntropyFinding {
  /** 掩码样本（不暴露原文） */
  sample: string;
  length: number;
  entropy: number;
}

/** 香农熵（bits/char） */
export function shannonEntropy(s: string): number {
  if (s.length === 0) return 0;
  const counts = new Map<string, number>();
  for (const ch of s) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let h = 0;
  for (const c of counts.values()) {
    const p = c / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

function maskToken(t: string): string {
  if (t.length <= 8) return '***';
  return `${t.slice(0, 4)}…${t.slice(-2)}`;
}

/**
 * 在文本中找高熵候选串（P2，T2 未知格式密钥兜底）。
 * 保守策略：长度 ≥ min_length、含字母+数字、字符种类 ≥ 12、熵 ≥ threshold。
 * hex 哈希熵上限约 4.0，因此默认阈值 4.5 不会误伤 commit hash / SHA。
 */
export function findHighEntropySecrets(text: string, rules: EntropyRules = {}): EntropyFinding[] {
  if (rules.enabled !== true || !text) return [];
  const minLength = rules.min_length ?? 24;
  const threshold = rules.threshold ?? 4.5;
  const allow = (rules.allow_patterns ?? []).flatMap((p) => {
    try {
      return [new RegExp(p)];
    } catch {
      return [];
    }
  });
  const re = new RegExp(`[A-Za-z0-9+/=_-]{${minLength},}`, 'g');
  const out: EntropyFinding[] = [];
  for (const m of text.matchAll(re)) {
    const token = m[0]!;
    if (allow.some((a) => a.test(token))) continue;
    if (!/[A-Za-z]/.test(token) || !/[0-9]/.test(token)) continue;
    if (new Set(token).size < 12) continue;
    const entropy = shannonEntropy(token);
    if (entropy < threshold) continue;
    out.push({ sample: maskToken(token), length: token.length, entropy: Number(entropy.toFixed(2)) });
  }
  return out;
}

export interface Policy {
  version: string;
  /** 策略绑定的 agent 身份（Asset Registry 中一个 agent 一条策略） */
  agent: string;
  servers?: Record<string, ServerPolicy>;
  /** 未登记 server 的默认决策（默认 deny，fail-closed） */
  defaultDecision?: Decision;
  /**
   * 能力覆盖（由 @podsec/graph 消费）：键为 "server.tool" 或 "tool"，
   * 值为 D2 能力标签。policy 引擎本身不解释该字段。
   */
  capabilities?: Record<string, string[]>;
  /** 能力级规则：即使工具在 servers 里被 allow，命中 deny/approve 仍按更严格者执行 */
  capabilityRules?: CapabilityRules;
  /** 工具 → D2 能力映射（由 pod graph apply 生成；网关据此执行 capabilityRules） */
  capabilityMap?: Record<string, string[]>;
  secrets?: SecretRules;
}

export interface CapabilityRules {
  deny?: string[];
  approve?: string[];
  /** 能力级 allow：只对未在 servers 显式登记的工具生效，不会覆盖 tool deny */
  allow?: string[];
}

/** 与 @podsec/graph 的 D2 标签保持一致；policy 不依赖 graph，避免循环依赖 */
export const KNOWN_CAPABILITIES = [
  'read-secret',
  'read-private-data',
  'read-untrusted-input',
  'external-communication',
  'exec',
  'destructive-write',
  'credential-access',
] as const;

export interface EvalContext {
  agent: string;
  server: string;
  tool: string;
  /** 工具参数（敏感路径检查用；递归收集字符串值） */
  args?: unknown;
}

export interface EvalResult {
  decision: Decision;
  reason: string;
  /** 命中的规则位置，便于审计与调试 */
  matched:
    | 'agent'
    | 'server'
    | 'deny'
    | 'secrets-input'
    | 'capability-deny'
    | 'capability-allow'
    | 'approve'
    | 'capability-approve'
    | 'allow'
    | 'default';
}

/** 递归收集参数中的字符串值（数组/对象嵌套） */
export function collectStrings(value: unknown, out: string[] = []): string[] {
  if (typeof value === 'string') {
    out.push(value);
  } else if (Array.isArray(value)) {
    for (const v of value) collectStrings(v, out);
  } else if (value !== null && typeof value === 'object') {
    for (const v of Object.values(value)) collectStrings(v, out);
  }
  return out;
}

/** 解析命令行里的 npx 包名（与 scan 包同构；返回 null 表示非 npx 来源） */
export function parseNpxPackageFromArgs(args: string[]): { name: string; version: string | null } | null {
  const idx = args.findIndex((a) => a === 'npx' || a === 'npx.cmd' || a === 'npmx');
  if (idx === -1) return null;
  for (let i = idx + 1; i < args.length; i++) {
    const a = args[i]!;
    if (a === '-y' || a === '--yes' || a === '-p' || a === '--package' || a === '--') continue;
    if (a.startsWith('-')) continue;
    const m = a.match(/^(@[^/@]+\/[^/@]+|[^/@]+)(?:@([^/]+))?$/);
    if (!m) return null;
    return { name: m[1]!, version: m[2] ?? null };
  }
  return null;
}

/**
 * 校验 server 启动来源是否满足策略白名单。
 * 返回 null = 通过；返回字符串 = 不匹配原因（gateway 据此拒绝启动，fail-closed）。
 */
export function checkServerSource(
  source: ServerSource | undefined,
  command: string,
  args: string[],
): string | null {
  if (!source) return null; // 未声明来源 = 不限制（lint 会提示）
  if (source.command !== undefined && command !== source.command) {
    return `source.command 不匹配：策略要求 "${source.command}"，实际 "${command}"`;
  }
  if (source.package !== undefined) {
    const pkg = parseNpxPackageFromArgs([command, ...args]);
    if (!pkg) return `source.package 要求 "${source.package}"，但启动命令不是 npx 来源`;
    if (pkg.name !== source.package) {
      return `source.package 不匹配：策略要求 "${source.package}"，实际 "${pkg.name}"`;
    }
    if (source.version !== undefined && pkg.version !== source.version) {
      return `source.version 不匹配：策略要求 "${source.version}"，实际 "${pkg.version ?? '(未锁定)'}"`;
    }
  }
  return null;
}

/**
 * 把路径字符串拆成归一化后的路径段：
 * 统一分隔符、丢弃空段与 "."、丢弃开头的 "~"（home 前缀对匹配无意义）。
 * 例："/Users/x/.ssh/id_rsa" → ["Users","x",".ssh","id_rsa"]；"~/.aws" → [".aws"]。
 */
function pathSegments(input: string): string[] {
  return input
    .replace(/\\/g, '/')
    .replace(/\/+/g, '/')
    .split('/')
    .filter((s) => s !== '' && s !== '.' && s !== '~');
}

/** 段匹配：完全相等，或末段允许 ".env" 命中 ".env.local" 这类同前缀变体 */
function segmentMatches(candidate: string, pattern: string): boolean {
  return candidate === pattern || candidate.startsWith(`${pattern}.`);
}

/**
 * 敏感路径匹配（方案 C）：归一化后按"连续路径段"匹配。
 * - "~/.ssh" 与绝对路径 "/Users/x/.ssh/config" 都能命中；
 * - 只匹配完整段，避免 ".ssh" 误伤 ".ssh-backup"。
 * 导出以便单测直接覆盖匹配语义。
 */
export function matchesSensitivePath(value: string, pattern: string): boolean {
  const candidate = pathSegments(value);
  const target = pathSegments(pattern);
  if (target.length === 0 || target.length > candidate.length) return false;
  for (let i = 0; i <= candidate.length - target.length; i++) {
    let hit = true;
    for (let j = 0; j < target.length; j++) {
      const seg = candidate[i + j]!;
      const pat = target[j]!;
      const ok = j === target.length - 1 ? segmentMatches(seg, pat) : seg === pat;
      if (!ok) {
        hit = false;
        break;
      }
    }
    if (hit) return true;
  }
  return false;
}

function hitSensitivePath(policy: Policy, args: unknown): string | null {
  const patterns = policy.secrets?.deny_input_paths;
  if (!patterns || patterns.length === 0) return null;
  const strings = collectStrings(args);
  for (const pattern of patterns) {
    for (const str of strings) {
      if (matchesSensitivePath(str, pattern)) return pattern;
    }
  }
  return null;
}

function matches(patterns: string[] | undefined, tool: string): boolean {
  if (!patterns) return false;
  return patterns.includes('*') || patterns.includes(tool);
}

/**
 * 合并 agent 限定 / server 限定 / 工具名三种键，去重。
 * 优先级：agent 限定键用于未来多 agent 共享策略；当前一策略一 agent 时与共享键等价。
 */
function capabilitiesFor(policy: Policy, agent: string, server: string, tool: string): string[] {
  const keys = [`${agent}/${server}.${tool}`, `${server}.${tool}`, tool];
  const mapped = keys.flatMap((key) => policy.capabilityMap?.[key] ?? []);
  const overrides = keys.flatMap((key) => policy.capabilities?.[key] ?? []);
  return [...new Set([...mapped, ...overrides])];
}

export function evaluate(policy: Policy, ctx: EvalContext): EvalResult {
  if (policy.agent !== ctx.agent) {
    return {
      decision: 'deny',
      reason: `policy is bound to agent "${policy.agent}", got "${ctx.agent}"`,
      matched: 'agent',
    };
  }

  const serverPolicy = policy.servers?.[ctx.server];
  if (!serverPolicy) {
    const decision = policy.defaultDecision ?? 'deny';
    return {
      decision,
      reason: `server "${ctx.server}" is not registered (default ${decision})`,
      matched: 'server',
    };
  }

  if (matches(serverPolicy.deny, ctx.tool)) {
    return { decision: 'deny', reason: `tool "${ctx.tool}" is denied on "${ctx.server}"`, matched: 'deny' };
  }

  const sensitive = hitSensitivePath(policy, ctx.args);
  if (sensitive !== null) {
    return {
      decision: 'deny',
      reason: `argument hits sensitive path pattern "${sensitive}" (secrets.deny_input_paths)`,
      matched: 'secrets-input',
    };
  }

  const capabilities = capabilitiesFor(policy, ctx.agent, ctx.server, ctx.tool);
  const deniedCapability = capabilities.find((capability) => policy.capabilityRules?.deny?.includes(capability));
  if (deniedCapability !== undefined) {
    return {
      decision: 'deny',
      reason: `tool "${ctx.tool}" has denied capability "${deniedCapability}" (capabilityRules.deny)`,
      matched: 'capability-deny',
    };
  }
  if (matches(serverPolicy.approve, ctx.tool)) {
    return { decision: 'approve', reason: `tool "${ctx.tool}" requires approval on "${ctx.server}"`, matched: 'approve' };
  }
  const approvedCapability = capabilities.find((capability) => policy.capabilityRules?.approve?.includes(capability));
  if (approvedCapability !== undefined) {
    return {
      decision: 'approve',
      reason: `tool "${ctx.tool}" has capability "${approvedCapability}" requiring approval (capabilityRules.approve)`,
      matched: 'capability-approve',
    };
  }
  if (matches(serverPolicy.allow, ctx.tool)) {
    return { decision: 'allow', reason: `tool "${ctx.tool}" is allowed on "${ctx.server}"`, matched: 'allow' };
  }
  const allowedCapability = capabilities.find((capability) => policy.capabilityRules?.allow?.includes(capability));
  if (allowedCapability !== undefined) {
    return {
      decision: 'allow',
      reason: `tool "${ctx.tool}" has allowed capability "${allowedCapability}" (capabilityRules.allow)`,
      matched: 'capability-allow',
    };
  }
  return {
    decision: 'deny',
    reason: `tool "${ctx.tool}" is not authorized on "${ctx.server}" (fail-closed)`,
    matched: 'default',
  };
}

// ---------- 策略 lint（P1：误配置防线，T9） ----------

export interface LintIssue {
  severity: 'error' | 'warn' | 'info';
  /** 定位路径，如 servers.filesystem.allow */
  where: string;
  message: string;
}

/** 检查策略中的危险/可疑模式（纯函数，供 pod lint 与 CI 使用） */
export function lintPolicy(policy: Policy): LintIssue[] {
  const issues: LintIssue[] = [];

  if (policy.defaultDecision === 'allow' || policy.defaultDecision === 'approve') {
    issues.push({
      severity: 'warn',
      where: 'defaultDecision',
      message: `defaultDecision="${policy.defaultDecision}" 是 fail-open，未登记 server 将被放行（建议 deny）`,
    });
  }

  const servers = policy.servers ?? {};
  if (Object.keys(servers).length === 0) {
    issues.push({ severity: 'info', where: 'servers', message: '未配置任何 server 规则（空策略）' });
  }

  for (const [server, sp] of Object.entries(servers)) {
    if (!sp.source) {
      issues.push({
        severity: 'info',
        where: `servers.${server}.source`,
        message: '未声明 server 来源白名单（建议声明 command 或 npm package，见 T4）',
      });
    }
    if (sp.deny && sp.deny.length === 0) {
      issues.push({ severity: 'warn', where: `servers.${server}.deny`, message: 'deny 为空数组（无实际拒绝规则）' });
    }
    if (sp.allow && sp.allow.includes('*')) {
      issues.push({
        severity: 'warn',
        where: `servers.${server}.allow`,
        message: `allow 含 "*"（该 server 全部工具放行；建议最小授权）`,
      });
    }
  }

  const secrets = policy.secrets;
  if (!secrets || (!secrets.deny_input_paths?.length && !secrets.deny_output_matching?.length)) {
    issues.push({
      severity: 'info',
      where: 'secrets',
      message: '未配置 secrets 规则（建议加 deny_input_paths 与 deny_output_matching，见 T2）',
    });
  } else {
    for (const pattern of secrets?.deny_input_paths ?? []) {
      if (pattern.startsWith('~/') || pattern.startsWith('./')) {
        issues.push({
          severity: 'info',
          where: 'secrets.deny_input_paths',
          message: `"${pattern}" 的前缀会被归一化，按路径段匹配任意位置；若只想限制当前用户目录，请写绝对路径`,
        });
      }
    }
    for (const pattern of secrets?.deny_output_matching ?? []) {
      try {
        new RegExp(pattern);
      } catch {
        issues.push({
          severity: 'error',
          where: 'secrets.deny_output_matching',
          message: `非法正则: ${pattern}`,
        });
      }
    }
    const entropy = secrets?.entropy;
    if (!entropy?.enabled) {
      issues.push({
        severity: 'info',
        where: 'secrets.entropy',
        message: '未启用输出侧熵检测（建议 enabled=true，兜底未知格式密钥，见 T2）',
      });
    } else {
      if ((entropy.threshold ?? 4.5) < 3.5) {
        issues.push({
          severity: 'warn',
          where: 'secrets.entropy.threshold',
          message: `threshold=${entropy.threshold} 偏低，可能误伤正常文本（建议 ≥4.0）`,
        });
      }
      for (const pattern of entropy.allow_patterns ?? []) {
        try {
          new RegExp(pattern);
        } catch {
          issues.push({
            severity: 'error',
            where: 'secrets.entropy.allow_patterns',
            message: `非法正则: ${pattern}`,
          });
        }
      }
    }
  }

  const knownCapabilities = new Set<string>(KNOWN_CAPABILITIES);
  const capabilityRuleLists: Array<[string, string[] | undefined]> = [
    ['capabilityRules.deny', policy.capabilityRules?.deny],
    ['capabilityRules.approve', policy.capabilityRules?.approve],
    ['capabilityRules.allow', policy.capabilityRules?.allow],
  ];
  for (const [where, values] of capabilityRuleLists) {
    for (const capability of values ?? []) {
      if (!knownCapabilities.has(capability)) {
        issues.push({ severity: 'warn', where, message: `未知能力标签 "${capability}"（不会生效）` });
      }
    }
  }
  for (const [key, values] of Object.entries(policy.capabilityMap ?? {})) {
    for (const capability of values) {
      if (!knownCapabilities.has(capability)) {
        issues.push({ severity: 'warn', where: `capabilityMap.${key}`, message: `未知能力标签 "${capability}"` });
      }
    }
  }
  if (policy.capabilityRules && !policy.capabilityMap && !policy.capabilities) {
    issues.push({
      severity: 'warn',
      where: 'capabilityRules',
      message: '配置了 capabilityRules 但没有 capabilityMap/capabilities，规则不会命中任何工具；先运行 pod graph apply',
    });
  }
  if (policy.capabilityRules?.allow?.length) {
    issues.push({
      severity: 'warn',
      where: 'capabilityRules.allow',
      message: 'capabilityRules.allow 是放宽规则（未在 servers 显式登记的工具会按能力放行）；请确保 capabilityMap 覆盖准确',
    });
  }

  return issues;
}
