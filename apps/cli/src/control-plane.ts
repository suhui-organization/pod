/**
 * 控制平面命令实现（docs/control-plane-hardening.md）。
 *
 * 三个共同点：
 * 1) 判定规则来自用户规则文件（`~/.pod/rules.json` 或 `--rules`），代码不写死阈值；
 * 2) 所有"改变状态"的动作都写进同一条 SHA-256 审计链（kind 标明事件类型）；
 * 3) 只读命令（posture/anomaly/trace）默认不落盘，加 `--audit` 才记账。
 */
import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { homedir } from 'node:os';
import { t } from '@podsec/i18n';
import {
  AuditLog,
  appendControlEvent,
  appendEntryExclusive,
  appendToAuditFile,
  hashValue,
  loadAuditFile,
  CONTROL_CHAIN,
  type AuditEntry,
  type AuditKind,
  type ControlEvent,
} from '@podsec/audit';
import {
  expandHome,
  loadRules,
  type Policy,
  type RuleSet,
} from '@podsec/policy';
// 控制平面事件的实现搬到了 @podsec/audit（只留一份：控制台也要写这类事件）。
// 这里既 import（本模块内部用）又 re-export（既有调用方与测试的 import 路径不变）。
export { appendControlEvent, CONTROL_CHAIN, type ControlEvent };
import {
  generateAgentIdentity,
  grantCovers,
  hasPrivateKey,
  issueDelegation as signDelegation,
  issueGrant as signGrant,
  listAgentIdentities,
  linkOf,
  loadAgentIdentity,
  markGrantConsumed,
  publicKeyResolver,
  readConsumedAt,
  signAsAgent,
  verifyDelegation,
  verifyGrant,
  verifyWithPem,
  type DelegationToken,
  type Grant,
} from '@podsec/identity';
import {
  buildBaseline,
  collectFacts,
  evaluatePosture,
  parseBaseline,
  renderPostureReport,
  type Baseline,
  type Finding,
  type PostureResult,
} from '@podsec/posture';
import { loadAllAuditFiles } from './evidence.js';

export const HOMEDIR = homedir();

/** `~` 展开，供 CLI 传进来的路径用 */
export function expandPath(path: string, home: string = HOMEDIR): string {
  return expandHome(path, home);
}

/** 读取规则：显式 --rules 优先，否则 ~/.pod/rules.json，都不存在则用默认值 */
export function resolveRules(rulesPath: string | undefined, podHome: string): RuleSet {
  const path = rulesPath ?? join(podHome, 'rules.json');
  return loadRules(existsSync(path) ? path : undefined);
}


function agentOf(finding: Finding): string {
  if (finding.category === 'identity' || finding.category === 'delegation') return finding.subject.split('/')[0] ?? '_control';
  // 审计链类发现：subject 是 <audit-dir>/<agent>/<server>.jsonl，取倒数第二段
  if (finding.category === 'audit') {
    const parts = finding.subject.split('/');
    return parts[parts.length - 2] ?? '_control';
  }
  return '_control';
}

// ---------- pod posture（G2/G3/G5/G11/G13/G14） ----------

export interface PostureOptions {
  home?: string;
  auditDir: string;
  rules: RuleSet;
  baselinePath: string;
  /** 只读命令默认不写审计；--audit 打开 */
  writeAudit: boolean;
  now?: Date;
}

export interface PostureRun {
  result: PostureResult;
  report: string;
  /** 有 high 且 strict 时为 1 */
  exitCode: number;
}

export function readBaseline(path: string): Baseline | null {
  if (!existsSync(path)) return null;
  try {
    return parseBaseline(readFileSync(path, 'utf8'));
  } catch {
    // 基线损坏不能当成"没有基线"——那会静默跳过所有漂移检查，改为显式报错
    throw new Error(t('基线文件损坏，无法解析：{path}（删掉它重新 pod posture freeze）', { path }));
  }
}

export function runPosture(opts: PostureOptions & { strict?: boolean }): PostureRun {
  const home = opts.home ?? HOMEDIR;
  const now = opts.now ?? new Date();
  const baseline = readBaseline(opts.baselinePath);
  const facts = collectFacts(opts.rules, { home, auditDir: opts.auditDir, now });
  const findings = evaluatePosture(opts.rules, facts, baseline, { home, now });
  const result: PostureResult = {
    generatedAt: now.toISOString(),
    findings,
    facts,
    baselineMissing: baseline === null,
  };
  if (opts.writeAudit) {
    const failures: string[] = [];
    for (const finding of findings) {
      try {
        appendControlEvent({
          auditDir: opts.auditDir,
          agent: agentOf(finding),
          kind: kindOf(finding),
          reason: `posture:${finding.id}:${finding.message}`,
          // tool 只放短标签：完整定位串在 reason 里（云端 tool 上限 128 字符）
          tool: finding.category,
          decision: 'allow',
          payload: { severity: finding.severity, subject: finding.subject },
        });
      } catch (err) {
        // 记不上账不能等于整个检查失败：比如控制平面链自己就断了（append 会被拒绝）。
        // 收集失败原因一并报出来，避免"看起来跑完了、其实没落盘"。
        failures.push(`${finding.id}: ${err instanceof Error ? err.message : String(err)}`);
      }
    }
    if (failures.length > 0) {
      console.error(t('⚠️ {n} 条发现未能写入审计链：', { n: failures.length }));
      for (const f of failures.slice(0, 5)) console.error(`   - ${f}`);
    }
  }
  const hasHigh = findings.some((f) => f.severity === 'high');
  return { result, report: renderPostureReport(result), exitCode: opts.strict && hasHigh ? 1 : 0 };
}

function kindOf(finding: Finding): AuditKind {
  switch (finding.category) {
    case 'hook':
      return 'hook';
    case 'identity':
      return 'identity';
    case 'delegation':
      return 'delegation';
    case 'memory':
      return 'memory';
    case 'package':
      return 'package';
    case 'audit':
      return 'anomaly';
    default:
      return 'config-change';
  }
}

export interface FreezeResult {
  baselinePath: string;
  baseline: Baseline;
  counts: { configs: number; memory: number; hooks: number; packages: number };
}

/** 记录当前姿态为基线；这是"冻结项"的起点（G2） */
export function freezePosture(opts: Omit<PostureOptions, 'writeAudit' | 'baselinePath'> & { baselinePath: string }): FreezeResult {
  const home = opts.home ?? HOMEDIR;
  const facts = collectFacts(opts.rules, { home, auditDir: opts.auditDir });
  const baseline = buildBaseline(facts, opts.now);
  mkdirSync(dirname(opts.baselinePath), { recursive: true });
  writeFileSync(opts.baselinePath, JSON.stringify(baseline, null, 2) + '\n', 'utf8');
  appendControlEvent({
    auditDir: opts.auditDir,
    agent: '_control',
    kind: 'config-change',
    reason: `posture:freeze:${opts.baselinePath}`,
    payload: {
      configs: Object.keys(baseline.configs).length,
      memory: Object.keys(baseline.memory).length,
      hooks: Object.keys(baseline.hooks).length,
      packages: Object.keys(baseline.packages).length,
    },
  });
  return {
    baselinePath: opts.baselinePath,
    baseline,
    counts: {
      configs: Object.keys(baseline.configs).length,
      memory: Object.keys(baseline.memory).length,
      hooks: Object.keys(baseline.hooks).length,
      packages: Object.keys(baseline.packages).length,
    },
  };
}

// ---------- pod identity（G11） ----------

export interface IdentityCommandOptions {
  agent: string;
  dir: string;
  auditDir: string;
}

export function identityInit(opts: IdentityCommandOptions): { fingerprint: string; publicKeyPem: string } {
  const identity = generateAgentIdentity(opts.agent, opts.dir);
  appendControlEvent({
    auditDir: opts.auditDir,
    agent: opts.agent,
    kind: 'identity',
    reason: `identity:init:fingerprint=${identity.fingerprint}`,
    payload: { fingerprint: identity.fingerprint, algorithm: identity.algorithm },
  });
  return { fingerprint: identity.fingerprint, publicKeyPem: identity.publicKeyPem };
}

export interface IdentityReport {
  agent: string;
  fingerprint: string | null;
  hasPrivateKey: boolean;
  ok: boolean;
}

export function identityList(dir: string): IdentityReport[] {
  return listAgentIdentities(dir).map((identity) => ({
    agent: identity.agent,
    fingerprint: identity.fingerprint,
    hasPrivateKey: hasPrivateKey(identity.agent, dir),
    ok: hasPrivateKey(identity.agent, dir),
  }));
}

/** 自检：用私钥签一个挑战，再用公钥验——证明这把钥匙真的能用 */
export function identityVerify(agent: string, dir: string, now: Date = new Date()): { ok: boolean; reason: string } {
  const identity = loadAgentIdentity(agent, dir);
  if (!identity) return { ok: false, reason: t('没有身份（先 pod identity init）') };
  if (!hasPrivateKey(agent, dir)) return { ok: false, reason: t('私钥缺失') };
  const challenge = { agent, at: now.toISOString() };
  try {
    const sig = signAsAgent(agent, dir, challenge);
    const ok = verifyWithPem(identity.publicKeyPem, challenge, sig);
    return ok
      ? { ok: true, reason: t('签名自检通过（fingerprint={fp}）', { fp: identity.fingerprint ?? '' }) }
      : { ok: false, reason: t('签名自检失败') };
  } catch (err) {
    return { ok: false, reason: err instanceof Error ? err.message : String(err) };
  }
}

// ---------- pod delegate（G13） ----------

export interface DelegateIssueOptions {
  parent: string;
  child: string;
  capabilities: string[];
  ttlSeconds: number;
  identityDir: string;
  delegationDir: string;
  auditDir: string;
  /** 父 agent 已有的祖先链（多跳时传上一跳的令牌文件） */
  parentToken?: string;
}

export function delegateIssue(opts: DelegateIssueOptions): { file: string; token: DelegationToken } {
  const chain: ReturnType<typeof linkOf>[] = [];
  if (opts.parentToken) {
    const previous = JSON.parse(readFileSync(opts.parentToken, 'utf8')) as DelegationToken;
    chain.push(...previous.chain, linkOf(previous));
  }
  const token = signDelegation(
    {
      parent: opts.parent,
      child: opts.child,
      capabilities: opts.capabilities,
      ttlSeconds: opts.ttlSeconds,
      chain,
    },
    { agent: opts.parent, root: opts.identityDir },
  );
  mkdirSync(opts.delegationDir, { recursive: true });
  const file = join(opts.delegationDir, `${opts.parent}__${opts.child}.json`);
  writeFileSync(file, JSON.stringify(token, null, 2) + '\n', 'utf8');
  appendControlEvent({
    auditDir: opts.auditDir,
    agent: opts.parent,
    kind: 'delegation',
    reason: `delegation:issue:${opts.parent}→${opts.child}:capabilities=${token.capabilities.join(',')}`,
    tool: 'delegate',
    payload: { capabilities: token.capabilities, depth: token.depth, expiresAt: token.expiresAt },
  });
  return { file, token };
}

export interface DelegateVerifyOptions {
  file: string;
  identityDir: string;
  rules: RuleSet;
}

export function delegateVerify(opts: DelegateVerifyOptions): {
  ok: boolean;
  errors: string[];
  capabilities: string[];
  depth: number;
  hops: string[];
} {
  const token = JSON.parse(readFileSync(opts.file, 'utf8')) as DelegationToken;
  return verifyDelegation(token, {
    rules: {
      maxDepth: opts.rules.delegation.maxDepth,
      requireSubset: opts.rules.delegation.requireSubset,
      forbiddenEscalation: opts.rules.delegation.forbiddenEscalation,
    },
    resolvePublicKey: publicKeyResolver(opts.identityDir),
  });
}

function capabilitiesOf(policy: Policy): string[] {
  const caps = new Set<string>();
  for (const list of Object.values(policy.capabilities ?? {})) {
    for (const c of list) caps.add(c);
  }
  for (const list of [policy.capabilityRules?.allow, policy.capabilityRules?.approve, policy.capabilityRules?.deny]) {
    for (const c of list ?? []) caps.add(c);
  }
  return [...caps].sort();
}

/** 委托收窄的静态校验：子 agent 的能力必须是父 agent 的严格子集 */
export function delegateCheck(opts: {
  parentPolicy: Policy;
  childPolicy: Policy;
  rules: RuleSet;
}): { ok: boolean; escaped: string[]; parent: string[]; child: string[]; forbidden: string[] } {
  const parent = capabilitiesOf(opts.parentPolicy);
  const child = capabilitiesOf(opts.childPolicy);
  const escaped = child.filter((c) => !parent.includes(c));
  const forbidden = child.filter((c) => opts.rules.delegation.forbiddenEscalation.includes(c));
  const ok = (!opts.rules.delegation.requireSubset || escaped.length === 0) && forbidden.length === 0;
  return { ok, escaped, parent, child, forbidden };
}

// ---------- pod grant（G12） ----------

export interface GrantIssueOptions {
  id: string;
  agent: string;
  issuedBy: string;
  identityDir: string;
  grantDir: string;
  auditDir: string;
  ttlSeconds: number;
  singleUse: boolean;
  servers?: string[];
  tools?: string[];
  capabilities?: string[];
  reason?: string;
}

export function grantIssue(opts: GrantIssueOptions): { file: string; grant: Grant } {
  const grant = signGrant(
    {
      id: opts.id,
      agent: opts.agent,
      servers: opts.servers,
      tools: opts.tools,
      capabilities: opts.capabilities,
      singleUse: opts.singleUse,
      issuedBy: opts.issuedBy,
      reason: opts.reason,
      ttlSeconds: opts.ttlSeconds,
    },
    { agent: opts.issuedBy, root: opts.identityDir },
  );
  mkdirSync(opts.grantDir, { recursive: true });
  const file = join(opts.grantDir, `${opts.id}.json`);
  writeFileSync(file, JSON.stringify(grant, null, 2) + '\n', 'utf8');
  appendControlEvent({
    auditDir: opts.auditDir,
    agent: opts.agent,
    kind: 'grant',
    reason: `grant:issue:${opts.id}:by=${opts.issuedBy}:singleUse=${opts.singleUse}`,
    payload: {
      servers: opts.servers ?? [],
      tools: opts.tools ?? [],
      capabilities: opts.capabilities ?? [],
      ttlSeconds: opts.ttlSeconds,
    },
  });
  return { file, grant };
}

export interface GrantListing {
  file: string;
  id: string;
  agent: string;
  issuedBy: string;
  expiresAt: string;
  singleUse: boolean;
  consumed: boolean;
  valid: boolean;
  servers: string[];
  tools: string[];
  capabilities: string[];
}

export function grantList(grantDir: string, identityDir: string, now: Date = new Date()): GrantListing[] {
  if (!existsSync(grantDir)) return [];
  const resolve = publicKeyResolver(identityDir);
  const out: GrantListing[] = [];
  for (const name of readdirSync(grantDir).filter((n) => n.endsWith('.json')).sort()) {
    const file = join(grantDir, name);
    let grant: Grant;
    try {
      grant = JSON.parse(readFileSync(file, 'utf8')) as Grant;
    } catch {
      continue;
    }
    const consumedAt = readConsumedAt(file);
    out.push({
      file,
      id: grant.claims.id,
      agent: grant.claims.agent,
      issuedBy: grant.claims.issuedBy,
      expiresAt: grant.claims.expiresAt,
      singleUse: grant.claims.singleUse,
      consumed: consumedAt !== null,
      valid: verifyGrant(grant, { resolvePublicKey: resolve, now, consumedAt }).ok,
      servers: grant.claims.servers ?? [],
      tools: grant.claims.tools ?? [],
      capabilities: grant.claims.capabilities ?? [],
    });
  }
  return out;
}

export { grantCovers, markGrantConsumed };

// ---------- pod quarantine（G8） ----------

export interface QuarantineState {
  agents: Record<string, { reason?: string; at?: string; by?: string }>;
}

export function readQuarantineFile(file: string): QuarantineState {
  if (!existsSync(file)) return { agents: {} };
  try {
    const raw = JSON.parse(readFileSync(file, 'utf8')) as Partial<QuarantineState>;
    return { agents: raw.agents ?? {} };
  } catch {
    throw new Error(t('熔断文件损坏：{file}', { file }));
  }
}

export function quarantineAdd(opts: {
  file: string;
  agent: string;
  reason: string;
  by: string;
  auditDir: string;
  now?: Date;
}): QuarantineState {
  const state = readQuarantineFile(opts.file);
  const at = (opts.now ?? new Date()).toISOString();
  state.agents[opts.agent] = { reason: opts.reason, at, by: opts.by };
  mkdirSync(dirname(opts.file), { recursive: true });
  writeFileSync(opts.file, JSON.stringify(state, null, 2) + '\n', 'utf8');
  appendControlEvent({
    auditDir: opts.auditDir,
    agent: opts.agent,
    kind: 'quarantine',
    reason: `quarantine:add:${opts.reason}`,
    decision: 'deny',
    outcome: 'blocked',
    payload: { by: opts.by, at },
  });
  return state;
}

export function quarantineRemove(opts: {
  file: string;
  agent: string;
  by: string;
  auditDir: string;
  now?: Date;
}): QuarantineState {
  const state = readQuarantineFile(opts.file);
  delete state.agents[opts.agent];
  mkdirSync(dirname(opts.file), { recursive: true });
  writeFileSync(opts.file, JSON.stringify(state, null, 2) + '\n', 'utf8');
  appendControlEvent({
    auditDir: opts.auditDir,
    agent: opts.agent,
    kind: 'quarantine',
    reason: `quarantine:remove:by=${opts.by}`,
    payload: { by: opts.by, at: (opts.now ?? new Date()).toISOString() },
  });
  return state;
}

// ---------- pod anomaly（G10） ----------

export interface AnomalyFinding {
  agent: string;
  rule: string;
  severity: 'high' | 'medium';
  detail: string;
}

export interface AnomalyInput {
  auditDir: string;
  grantDir: string;
  delegationDir: string;
  rules: RuleSet;
  now?: Date;
}

/**
 * 信任传播异常：一个平时不委托的 agent 突然在窗口内密集签发委托/令牌，
 * 或一次性拿到多种高风险能力——阈值全部来自 rules.anomaly。
 */
export function detectAnomalies(input: AnomalyInput): AnomalyFinding[] {
  const now = input.now ?? new Date();
  const windowMs = input.rules.anomaly.windowMinutes * 60_000;
  const since = now.getTime() - windowMs;
  const findings: AnomalyFinding[] = [];

  const perAgent = new Map<string, { delegations: number; capabilities: Set<string> }>();
  const bump = (agent: string, capabilities: string[], isDelegation: boolean): void => {
    const entry = perAgent.get(agent) ?? { delegations: 0, capabilities: new Set<string>() };
    if (isDelegation) entry.delegations += 1;
    for (const c of capabilities) entry.capabilities.add(c);
    perAgent.set(agent, entry);
  };

  if (existsSync(input.delegationDir)) {
    for (const name of readdirSync(input.delegationDir).filter((n) => n.endsWith('.json'))) {
      try {
        const token = JSON.parse(readFileSync(join(input.delegationDir, name), 'utf8')) as DelegationToken;
        if (new Date(token.issuedAt).getTime() >= since) bump(token.parent, token.capabilities, true);
      } catch {
        // 坏文件由 posture 报
      }
    }
  }
  if (existsSync(input.grantDir)) {
    for (const name of readdirSync(input.grantDir).filter((n) => n.endsWith('.json'))) {
      try {
        const grant = JSON.parse(readFileSync(join(input.grantDir, name), 'utf8')) as Grant;
        if (new Date(grant.claims.issuedAt).getTime() >= since) {
          bump(grant.claims.issuedBy, grant.claims.capabilities ?? [], false);
        }
      } catch {
        // 同上
      }
    }
  }

  for (const [agent, entry] of perAgent) {
    if (entry.delegations > input.rules.anomaly.delegationsPerWindow) {
      findings.push({
        agent,
        rule: 'delegation-burst',
        severity: 'high',
        detail:
          `${input.rules.anomaly.windowMinutes} 分钟内签发 ${entry.delegations} 次委托` +
          `（阈值 ${input.rules.anomaly.delegationsPerWindow}）`,
      });
    }
    const highRisk = [...entry.capabilities].filter((c) =>
      input.rules.anomaly.highRiskCapabilities.includes(c),
    );
    if (highRisk.length > input.rules.anomaly.capabilitiesPerWindow) {
      findings.push({
        agent,
        rule: 'capability-spread',
        severity: 'medium',
        detail:
          `窗口内触及 ${highRisk.length} 种高风险能力（阈值 ${input.rules.anomaly.capabilitiesPerWindow}）：` +
          highRisk.join('、'),
      });
    }
  }

  // 审计侧的异常信号：窗口内被拒次数异常集中（同一 agent 反复撞墙）
  for (const { log } of loadAllAuditFiles(input.auditDir)) {
    const denied = new Map<string, number>();
    for (const entry of log.entries) {
      if (entry.decision !== 'deny') continue;
      if (new Date(entry.ts).getTime() < since) continue;
      denied.set(entry.agent, (denied.get(entry.agent) ?? 0) + 1);
    }
    for (const [agent, count] of denied) {
      if (count > input.rules.anomaly.capabilitiesPerWindow * 4) {
        findings.push({
          agent,
          rule: 'deny-burst',
          severity: 'medium',
          detail: `窗口内被拒绝 ${count} 次（异常密集，可能是被劫持后反复试探）`,
        });
      }
    }
  }

  return findings.sort((a, b) => a.agent.localeCompare(b.agent) || a.rule.localeCompare(b.rule));
}

// ---------- pod trace（G9） ----------

export interface TraceHop {
  parent: string;
  child: string;
  capabilities: string[];
  issuedAt: string;
  file: string;
}

export interface TraceReport {
  agent: string;
  /** 从根到目标 agent 的委托链（不含目标自身作为 child 的最后一跳之外的部分） */
  hops: TraceHop[];
  upstream: string[];
  downstream: string[];
  entries: AuditEntry[];
  blocked: AuditEntry[];
}

/**
 * 污染溯源：给定一个被确认污染的 agent，沿委托链向上找"毒化点"，
 * 向下找"可能被影响的执行者"，并把该链路相关的审计事件按时间排出来。
 */
export function buildTrace(opts: {
  agent: string;
  auditDir: string;
  delegationDir: string;
  maxHops?: number;
}): TraceReport {
  const maxHops = opts.maxHops ?? 8;
  const hops: TraceHop[] = [];
  const tokens: DelegationToken[] = [];
  if (existsSync(opts.delegationDir)) {
    for (const name of readdirSync(opts.delegationDir).filter((n) => n.endsWith('.json'))) {
      try {
        tokens.push(JSON.parse(readFileSync(join(opts.delegationDir, name), 'utf8')) as DelegationToken);
      } catch {
        // 坏文件跳过
      }
    }
  }

  const upstream: string[] = [];
  let cursor = opts.agent;
  for (let i = 0; i < maxHops; i++) {
    const hop = tokens.find((t) => t.child === cursor);
    if (!hop) break;
    hops.unshift({
      parent: hop.parent,
      child: hop.child,
      capabilities: hop.capabilities,
      issuedAt: hop.issuedAt,
      file: `${hop.parent}__${hop.child}.json`,
    });
    upstream.push(hop.parent);
    cursor = hop.parent;
  }

  const downstream = tokens.filter((t) => t.parent === opts.agent).map((t) => t.child);
  const related = new Set([opts.agent, ...upstream, ...downstream]);
  const entries: AuditEntry[] = [];
  for (const { log } of loadAllAuditFiles(opts.auditDir)) {
    for (const entry of log.entries) {
      if (related.has(entry.agent)) entries.push(entry);
    }
  }
  entries.sort((a, b) => a.ts.localeCompare(b.ts) || a.seq - b.seq);
  return {
    agent: opts.agent,
    hops,
    upstream,
    downstream,
    entries,
    blocked: entries.filter((e) => e.outcome === 'blocked' || e.decision === 'deny'),
  };
}
