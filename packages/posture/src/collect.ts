/**
 * 控制平面事实采集（只读）。
 *
 * 分工：这里只负责"机器上现在是什么样"，判断"算不算风险"全在 evaluate.ts，
 * 判断依据全部来自用户规则（@podsec/policy 的 RuleSet）。
 */
import { createHash } from 'node:crypto';
import { existsSync, globSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { basename, join } from 'node:path';
import { expandHome, type RuleSet } from '@podsec/policy';
import { AuditLog } from '@podsec/audit';
import { loadAgentIdentity, publicKeyResolver, verifyDelegation, type DelegationToken } from '@podsec/identity';
import { scanMachine } from '@podsec/scan';
import type {
  AuditFact,
  ConfigFact,
  DelegationFact,
  Facts,
  HookFact,
  IdentityFact,
  MemoryFact,
  PackageFact,
} from './types.js';

function sha256Short(input: string | Buffer): string {
  return createHash('sha256').update(input).digest('hex').slice(0, 16);
}

function readTextIfSmall(path: string, maxBytes: number): string | null {
  try {
    const stat = statSync(path);
    if (!stat.isFile() || stat.size > maxBytes) return null;
    return readFileSync(path, 'utf8');
  } catch {
    return null;
  }
}

/** 展开 ~ 与 glob；没有通配符时也要返回存在的文件 */
export function expandPaths(pattern: string, home: string): string[] {
  const expanded = expandHome(pattern, home);
  if (!expanded.includes('*')) return existsSync(expanded) ? [expanded] : [];
  try {
    return globSync(expanded).sort();
  } catch {
    return [];
  }
}

// ---------- 钩子（G3） ----------

function pushHook(
  out: HookFact[],
  format: HookFact['format'],
  file: string,
  event: string,
  command: string,
): void {
  if (!command.trim()) return;
  out.push({
    format,
    file,
    event,
    command: command.trim(),
    index: out.length,
    fingerprint: sha256Short(`${file}|${event}|${command.trim()}`),
  });
}

/** Claude Code settings.json：hooks.<Event>[].hooks[].command */
function parseClaudeHooks(text: string, file: string, out: HookFact[]): void {
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    return;
  }
  const hooks = (raw as { hooks?: Record<string, unknown> }).hooks;
  if (!hooks || typeof hooks !== 'object') return;
  for (const [event, entries] of Object.entries(hooks)) {
    if (!Array.isArray(entries)) continue;
    for (const entry of entries) {
      const inner = (entry as { hooks?: unknown }).hooks;
      if (Array.isArray(inner)) {
        for (const h of inner) {
          const command = (h as { command?: unknown }).command;
          if (typeof command === 'string') pushHook(out, 'claude-hooks', file, event, command);
        }
        continue;
      }
      const command = (entry as { command?: unknown }).command;
      if (typeof command === 'string') pushHook(out, 'claude-hooks', file, event, command);
    }
  }
}

/** pod 自定义钩子清单：{ hooks: [{ event, command }] } 或 [{ event, command }] */
function parsePodHooks(text: string, file: string, out: HookFact[]): void {
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    return;
  }
  const list = Array.isArray(raw)
    ? raw
    : Array.isArray((raw as { hooks?: unknown })?.hooks)
      ? ((raw as { hooks: unknown[] }).hooks as unknown[])
      : [];
  for (const item of list) {
    const event = (item as { event?: unknown }).event;
    const command = (item as { command?: unknown }).command;
    if (typeof command === 'string') {
      pushHook(out, 'pod-hooks', file, typeof event === 'string' ? event : 'hook', command);
    }
  }
}

/** launchd plist：不引 XML 依赖，按 ProgramArguments 的 <string> 取值 */
function parseLaunchd(text: string, file: string, out: HookFact[]): void {
  const label = text.match(/<key>Label<\/key>\s*<string>([^<]*)<\/string>/)?.[1] ?? basename(file);
  const block = text.match(/<key>ProgramArguments<\/key>\s*<array>([\s\S]*?)<\/array>/)?.[1];
  if (!block) return;
  const argv = [...block.matchAll(/<string>([\s\S]*?)<\/string>/g)].map((m) => m[1] ?? '');
  if (argv.length === 0) return;
  pushHook(out, 'launchd', file, `launchd:${label}`, argv.join(' '));
}

export function collectHooks(rules: RuleSet, home: string): HookFact[] {
  const out: HookFact[] = [];
  for (const watch of rules.hookRisk.watchPaths) {
    for (const file of expandPaths(watch.path, home)) {
      const text = readTextIfSmall(file, 4_000_000);
      if (text === null) continue;
      if (watch.format === 'claude-hooks') parseClaudeHooks(text, file, out);
      else if (watch.format === 'pod-hooks') parsePodHooks(text, file, out);
      else parseLaunchd(text, file, out);
    }
  }
  return out;
}

// ---------- 配置文件 / 记忆文件（G2、G14） ----------

function collectFiles(patterns: string[], home: string, maxBytes: number): Array<ConfigFact | MemoryFact> {
  const out: Array<ConfigFact | MemoryFact> = [];
  for (const pattern of patterns) {
    const matched = expandPaths(pattern, home);
    if (matched.length === 0) {
      out.push({ path: expandHome(pattern, home), exists: false, hash: null, bytes: 0 });
      continue;
    }
    for (const file of matched) {
      const text = readTextIfSmall(file, maxBytes);
      out.push({
        path: file,
        exists: true,
        hash: text === null ? null : sha256Short(text),
        bytes: text === null ? 0 : Buffer.byteLength(text, 'utf8'),
      });
    }
  }
  return out;
}

export function collectConfigs(rules: RuleSet, home: string): ConfigFact[] {
  return collectFiles(rules.freeze.paths, home, 4_000_000) as ConfigFact[];
}

export function collectMemory(rules: RuleSet, home: string): MemoryFact[] {
  return collectFiles(rules.memory.paths, home, rules.memory.maxFileBytes) as MemoryFact[];
}

// ---------- MCP 包来源（G5） ----------

export function collectPackages(home: string): PackageFact[] {
  const scan = scanMachine({ home });
  return scan.mcpServers.map((server) => {
    const version = server.npxPackage?.version ?? undefined;
    return {
      server: server.name,
      source: [server.command, ...server.args].join(' '),
      package: server.npxPackage?.name,
      version,
      pinned: version !== undefined && version !== null && version !== 'latest',
      fingerprint: sha256Short([server.command, ...server.args].join(' ')),
    };
  });
}

// ---------- 身份（G11） ----------

function policyAgents(rules: RuleSet, home: string): string[] {
  const agents: string[] = [];
  for (const dir of rules.delegation.policyDirs) {
    for (const file of expandPaths(join(expandHome(dir, home), '*.json'), home)) {
      const text = readTextIfSmall(file, 1_000_000);
      if (text === null) continue;
      try {
        const agent = (JSON.parse(text) as { agent?: unknown }).agent;
        if (typeof agent === 'string' && agent) agents.push(agent);
      } catch {
        // 策略文件解析失败由 pod lint / policy verify 负责报，这里跳过
      }
    }
  }
  return agents;
}

function auditAgents(auditDir: string | undefined): string[] {
  if (!auditDir || !existsSync(auditDir)) return [];
  try {
    return readdirSync(auditDir, { withFileTypes: true })
      .filter((e) => e.isDirectory())
      .map((e) => e.name);
  } catch {
    return [];
  }
}

export function collectIdentities(rules: RuleSet, home: string, auditDir?: string): IdentityFact[] {
  const dir = expandHome(rules.identity.dir, home);
  const origins = new Map<string, Set<IdentityFact['origin'][number]>>();
  const add = (agent: string, origin: IdentityFact['origin'][number]): void => {
    // 下划线开头是 pod 自己的记账目录（如 _control 的控制平面事件链），不是 agent
    if (!agent || agent.startsWith('_')) return;
    const set = origins.get(agent) ?? new Set();
    set.add(origin);
    origins.set(agent, set);
  };
  for (const agent of policyAgents(rules, home)) add(agent, 'policy');
  for (const agent of auditAgents(auditDir)) add(agent, 'audit');
  if (existsSync(dir)) {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      if (entry.isDirectory()) add(entry.name, 'identity');
    }
  }
  return [...origins.entries()]
    .map(([agent, origin]) => {
      const identity = loadAgentIdentity(agent, dir);
      return {
        agent,
        hasIdentity: identity !== null,
        hasPrivateKey: identity !== null && existsSync(join(dir, agent, 'private.pem')),
        fingerprint: identity?.fingerprint ?? null,
        origin: [...origin].sort(),
      };
    })
    .sort((a, b) => a.agent.localeCompare(b.agent));
}

// ---------- 委托链（G13） ----------

export function collectDelegations(rules: RuleSet, home: string): DelegationFact[] {
  const dir = expandHome(rules.delegation.dir, home);
  const identityRoot = expandHome(rules.identity.dir, home);
  const out: DelegationFact[] = [];
  for (const file of expandPaths(join(dir, '*.json'), home)) {
    const text = readTextIfSmall(file, 1_000_000);
    if (text === null) continue;
    let token: DelegationToken;
    try {
      token = JSON.parse(text) as DelegationToken;
    } catch {
      out.push({ file, token: null, ok: false, errors: ['令牌不是合法 JSON'], capabilities: [], depth: 0, hops: [] });
      continue;
    }
    const result = verifyDelegation(token, {
      rules: {
        maxDepth: rules.delegation.maxDepth,
        requireSubset: rules.delegation.requireSubset,
        forbiddenEscalation: rules.delegation.forbiddenEscalation,
      },
      resolvePublicKey: publicKeyResolver(identityRoot),
    });
    out.push({
      file,
      token,
      ok: result.ok,
      errors: result.errors,
      capabilities: result.capabilities,
      depth: result.depth,
      hops: result.hops,
    });
  }
  return out.sort((a, b) => a.file.localeCompare(b.file));
}

export interface CollectOptions {
  home: string;
  auditDir?: string;
  /** 判定"多久没写入算异常"的当前时刻（测试可注入） */
  now?: Date;
}

/**
 * 审计链健康（G16）：读每个 <agent>/<server>.jsonl，校验链并算空闲时长。
 *
 * 为什么值得单独采一份事实：链一旦断裂，`loadAuditFile` 会拒绝后续追加——
 * agent 照常工作，本地却一条都不再记录（2026-09-09 就静默丢了 2.5 天）。
 * 这个事实就是把那种"静默失败"变成可见告警的数据来源。
 */
export function collectAudits(rules: RuleSet, auditDir: string | undefined, now: Date): AuditFact[] {
  if (!rules.auditHealth.enabled || !auditDir || !existsSync(auditDir)) return [];
  const ignore = new Set(rules.auditHealth.ignore);
  const out: AuditFact[] = [];
  for (const agentDir of readdirSync(auditDir, { withFileTypes: true })) {
    if (!agentDir.isDirectory()) continue;
    const agent = agentDir.name;
    if (ignore.has(agent)) continue;
    const dirPath = join(auditDir, agent);
    for (const file of readdirSync(dirPath).filter((f) => f.endsWith('.jsonl')).sort()) {
      const path = join(dirPath, file);
      const text = readTextIfSmall(path, 8_000_000);
      if (text === null) continue;
      const log = AuditLog.fromJSONL(text, '');
      const check = log.verify();
      const last = log.entries[log.entries.length - 1];
      const lastTs = last?.ts ?? null;
      const idleHours = lastTs ? (now.getTime() - new Date(lastTs).getTime()) / 3_600_000 : Number.POSITIVE_INFINITY;
      out.push({
        agent,
        server: file.replace(/\.jsonl$/, ''),
        path,
        entries: log.entries.length,
        lastTs,
        idleHours,
        valid: check.ok,
        brokenAt: check.ok ? undefined : check.firstBrokenSeq,
      });
    }
  }
  return out.sort((a, b) => a.agent.localeCompare(b.agent) || a.server.localeCompare(b.server));
}

export function collectFacts(rules: RuleSet, opts: CollectOptions): Facts {
  const now = opts.now ?? new Date();
  return {
    hooks: collectHooks(rules, opts.home),
    configs: collectConfigs(rules, opts.home),
    memory: collectMemory(rules, opts.home),
    packages: collectPackages(opts.home),
    identities: collectIdentities(rules, opts.home, opts.auditDir),
    delegations: collectDelegations(rules, opts.home),
    audits: collectAudits(rules, opts.auditDir, now),
  };
}
