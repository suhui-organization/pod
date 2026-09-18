/**
 * 事实采集（只读、不联网、不改文件）。
 *
 * 与 posture 的分工一致：这里只回答"机器上现在是什么样"，
 * "算不算漏洞"全部在 detect.ts，判定依据全部来自用户规则。
 */
import { createHash } from 'node:crypto';
import { existsSync, globSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { expandHome, type RuleSet } from '@podsec/policy';
import { scanSecretsInText } from '@podsec/scan';
import {
  HARNESSES,
  HARNESS_ALIASES,
  PROJECT_CONFIGS,
  PROJECT_MEMORY_FILES,
  classifyTransport,
  parseClaudeHooks,
  parseCodexNotify,
  parseGenericHooks,
  parseServersConfig,
  parseTomlKeyValues,
  type ConfigFormat,
  type RawServer,
} from './harnesses.js';
import type {
  ControlState,
  Facts,
  HarnessFact,
  HookFact,
  MemoryFact,
  ProjectFact,
  SecretFact,
  ServerFact,
} from './types.js';

const MAX_FILE_BYTES = 1_000_000;

function sha16(input: string): string {
  return createHash('sha256').update(input).digest('hex').slice(0, 16);
}

function readText(path: string): string | null {
  try {
    const stat = statSync(path);
    if (!stat.isFile() || stat.size > MAX_FILE_BYTES) return null;
    return readFileSync(path, 'utf8');
  } catch {
    return null;
  }
}

/** 展开 ~ 与 glob；无通配符时也要返回存在的文件 */
export function expandPattern(pattern: string, home: string): string[] {
  const expanded = expandHome(pattern, home);
  if (!expanded.includes('*')) return existsSync(expanded) ? [expanded] : [];
  try {
    return globSync(expanded).sort();
  } catch {
    return [];
  }
}

/** 报表里用 ~ 缩写，避免把用户名写进交付物 */
export function tilde(path: string, home: string): string {
  return path.startsWith(`${home}/`) ? `~/${path.slice(home.length + 1)}` : path;
}

/**
 * 这份记忆文件是否已被 `rules.memory.paths` 覆盖。
 * 覆盖 = pod posture 已经在为它做漂移检查；没覆盖 = 可以被静默改写。
 */
function isManagedMemory(file: string, home: string, rules: RuleSet): boolean {
  for (const pattern of rules.memory.paths) {
    if (pattern.includes('*')) {
      if (expandPattern(pattern, home).includes(file)) return true;
      continue;
    }
    if (expandHome(pattern, home) === file) return true;
  }
  return false;
}

/**
 * 判断一个 server 是否经过 pod 网关。
 *
 * 与 @podsec/scan 的 checkBypass 同一语义（那边是 v0 的 claude.json + dsh 专用版），
 * 这里要覆盖更多 harness，所以按"命令行里出现 pod 的调用形态"判定。
 */
export function behindGateway(command: string, args: string[]): boolean {
  const joined = [command, ...args].join(' ');
  if (/\bpod\s+(serve|record)\b/.test(joined)) return true;
  if (/(^|\s|\/)pod$/.test(joined.trim())) return true;
  return joined.includes('/pod ');
}

// ---------- 纳管状态 ----------

function listDirs(path: string): string[] {
  if (!existsSync(path)) return [];
  try {
    return readdirSync(path, { withFileTypes: true })
      .filter((entry) => entry.isDirectory())
      .map((entry) => entry.name)
      .filter((name) => !name.startsWith('_'));
  } catch {
    return [];
  }
}

function policyAgents(rules: RuleSet, home: string): string[] {
  const out: string[] = [];
  for (const dir of rules.delegation.policyDirs) {
    for (const file of expandPattern(join(expandHome(dir, home), '*.json'), home)) {
      const text = readText(file);
      if (text === null) continue;
      try {
        const agent = (JSON.parse(text) as { agent?: unknown }).agent;
        if (typeof agent === 'string' && agent) out.push(agent);
      } catch {
        // 策略文件解析失败由 pod lint 负责报，这里不重复报
      }
    }
  }
  return out;
}

export interface CollectOptions {
  home: string;
  rules: RuleSet;
  auditDir?: string;
  /** 项目级配置的扫描根（默认不扫项目，避免误读无关仓库） */
  workspaces?: string[];
  /** 覆盖 rules.guard.baselinePath（CLI 的 --baseline） */
  baselinePath?: string;
  now?: Date;
}

export function collectControlState(opts: CollectOptions): ControlState {
  const { rules, home } = opts;
  const auditAgents = opts.auditDir ? listDirs(opts.auditDir) : [];
  return {
    injectionBlock: rules.injection.block,
    injectionBlockAtOrAbove: rules.injection.blockAtOrAbove,
    egressEnabled: rules.egress.enabled,
    toolMetadataBlock: rules.toolMetadata.block,
    requireVersionPin: rules.packages.requireVersionPin,
    requireIntegrity: rules.packages.requireIntegrity,
    identityRequired: rules.identity.required,
    auditHealthEnabled: rules.auditHealth.enabled,
    policyAgents: policyAgents(rules, home),
    auditAgents,
    identityAgents: listDirs(expandHome(rules.identity.dir, home)),
  };
}

function normalizeAgentName(name: string): string {
  return name.toLowerCase().replace(/[^a-z0-9]/g, '');
}

/** 别名表匹配：harness 是否被某个 agent 名代表 */
export function managedByFor(harnessId: string, controls: ControlState): {
  managed: boolean;
  managedBy: Array<'policy' | 'audit' | 'identity'>;
  agentNames: string[];
} {
  const aliases = HARNESS_ALIASES[harnessId] ?? [harnessId];
  const matches = (agent: string): boolean => {
    const normalized = normalizeAgentName(agent);
    return aliases.some((alias) => normalized.includes(normalizeAgentName(alias)));
  };
  const managedBy: Array<'policy' | 'audit' | 'identity'> = [];
  const agentNames = new Set<string>();
  for (const [origin, list] of [
    ['policy', controls.policyAgents],
    ['audit', controls.auditAgents],
    ['identity', controls.identityAgents],
  ] as const) {
    for (const agent of list) {
      if (!matches(agent)) continue;
      if (!managedBy.includes(origin)) managedBy.push(origin);
      agentNames.add(agent);
    }
  }
  return { managed: managedBy.length > 0, managedBy, agentNames: [...agentNames].sort() };
}

// ---------- 密钥（只报掩码） ----------

function secretsFromConfig(text: string, label: string, format: ConfigFormat): SecretFact[] {
  const out: SecretFact[] = [];
  if (format === 'toml-codex') {
    // 按段落抽标量：密钥不只在 MCP 的 env 里（实测有放在 [model_providers.*] 的），
    // 带上段落名报表才能写出"直接去改哪个变量"。
    for (const pair of parseTomlKeyValues(text)) {
      for (const hit of scanSecretsInText(pair.value, label)) {
        const key = pair.section ? `${pair.section}.${pair.key}` : pair.key;
        out.push({ file: label, key, category: hit.category, masked: hit.masked });
      }
    }
  } else {
    try {
      const parsed = JSON.parse(format === 'json-opencode' ? text.replace(/^\s*\/\/.*$/gm, '') : text) as unknown;
      const map =
        parsed && typeof parsed === 'object' && !Array.isArray(parsed)
          ? pickServerMap(parsed as Record<string, unknown>)
          : {};
      for (const [serverName, raw] of Object.entries(map)) {
        const entry = raw as Record<string, unknown> | null;
        if (!entry || typeof entry !== 'object') continue;
        const env = (entry.env ?? entry.environment ?? entry.envVars) as Record<string, unknown> | undefined;
        for (const [key, value] of Object.entries(env ?? {})) {
          if (typeof value !== 'string' || !value) continue;
          // file 保持配置路径（报表要能按 harness 归类），server 与变量名进 key
          for (const hit of scanSecretsInText(value, label)) {
            out.push({ file: label, key: `${serverName}.${key}`, category: hit.category, masked: hit.masked });
          }
        }
      }
    } catch {
      // 交给全文扫描兜底
    }
  }
  // 全文兜底：结构化路径之外（headers、注释、TOML 里的 env 表）也能抓到
  for (const hit of scanSecretsInText(text, label)) {
    if (out.some((s) => s.masked === hit.masked && s.category === hit.category)) continue;
    out.push({ file: hit.file, key: 'unknown', category: hit.category, masked: hit.masked });
  }
  return out;
}

function pickServerMap(parsed: Record<string, unknown>): Record<string, unknown> {
  for (const candidate of [parsed.mcpServers, parsed.servers, parsed.context_servers, parsed.mcp]) {
    if (candidate && typeof candidate === 'object' && !Array.isArray(candidate)) {
      const record = candidate as Record<string, unknown>;
      // opencode 的 mcp 是 { name: {type:'local', command:[...]} }，与 server 映射同形，直接用
      return record;
    }
  }
  return {};
}

// ---------- 主采集 ----------

export function collectFacts(opts: CollectOptions): Facts {
  const home = opts.home;
  const controls = collectControlState(opts);
  const harnesses: HarnessFact[] = [];
  const servers: ServerFact[] = [];
  const hooks: HookFact[] = [];
  const secrets: SecretFact[] = [];
  const memory: MemoryFact[] = [];
  const notes: string[] = [];

  const addServers = (
    harnessId: string,
    raw: RawServer[],
    scope: ServerFact['scope'],
    fileLabel: string,
  ): void => {
    for (const server of raw) {
      const fingerprint = sha16([server.command, ...server.args].join(' '));
      const wrapped = behindGateway(server.command, server.args);
      const entry: ServerFact = {
        harness: harnessId,
        name: server.name,
        transport: classifyTransport(server),
        command: server.command,
        args: server.args,
        envKeys: server.envKeys,
        headerKeys: server.headerKeys,
        fingerprint,
        behindGateway: wrapped,
        // 只录不拦：包装命令里带 --record-only。没进网关的 server 谈不上"只录"。
        recordOnly: wrapped && server.args.includes('--record-only'),
        file: fileLabel,
        scope,
      };
      if (server.url) entry.url = server.url;
      const pkg = parsePackageFrom(server);
      if (pkg) entry.package = pkg;
      servers.push(entry);
    }
  };

  for (const def of HARNESSES) {
    const evidence = def.probes
      .map((probe) => expandHome(probe, home))
      .filter((path) => existsSync(path));
    const configFiles: string[] = [];

    for (const spec of def.configs) {
      for (const file of expandPattern(spec.path, home)) {
        const text = readText(file);
        if (text === null) continue;
        configFiles.push(file);
        const label = tilde(file, home);
        const parsed = parseServersConfig(text, spec.format);
        if (parsed.error) notes.push(`${label} 解析失败，本轮的 server 清单可能不完整：${parsed.error}`);
        addServers(def.id, parsed.servers, spec.scope, label);
        secrets.push(...secretsFromConfig(text, label, spec.format));
      }
    }

    for (const hookFile of def.hookFiles ?? []) {
      for (const file of expandPattern(hookFile.path, home)) {
        const text = readText(file);
        if (text === null) continue;
        const label = tilde(file, home);
        const parsedHooks =
          hookFile.format === 'claude-hooks'
            ? parseClaudeHooks(text)
            : hookFile.format === 'codex-notify'
              ? parseCodexNotify(text).map((command) => ({ event: 'notify', command }))
              : parseGenericHooks(text);
        for (const item of parsedHooks) {
          hooks.push({
            harness: def.id,
            format: hookFile.format,
            file: label,
            event: item.event,
            command: item.command,
            index: hooks.length,
            fingerprint: sha16(`${label}|${item.event}|${item.command}`),
          });
        }
      }
    }

    for (const mem of def.memoryFiles ?? []) {
      for (const file of expandPattern(mem, home)) {
        const text = readText(file);
        memory.push({
          harness: def.id,
          file: tilde(file, home),
          exists: true,
          bytes: text === null ? 0 : Buffer.byteLength(text, 'utf8'),
          managed: isManagedMemory(file, home, opts.rules),
        });
      }
    }

    const managed = managedByFor(def.id, controls);
    harnesses.push({
      id: def.id,
      label: def.label,
      installed: evidence.length > 0,
      evidence: evidence.map((path) => tilde(path, home)),
      configFiles: configFiles.map((path) => tilde(path, home)),
      managed: managed.managed,
      managedBy: managed.managedBy,
      agentNames: managed.agentNames,
    });
  }

  // 用户自定义路径：注册表没覆盖的 harness 也能被看见（格式按通用 JSON 处理）
  for (const pattern of opts.rules.guard.extraConfigPaths) {
    for (const file of expandPattern(pattern, home)) {
      const text = readText(file);
      if (text === null) continue;
      const label = tilde(file, home);
      const parsed = parseServersConfig(text, 'json-mcpServers');
      if (parsed.error) notes.push(`${label} 解析失败，本轮的 server 清单可能不完整：${parsed.error}`);
      addServers('custom', parsed.servers, 'user', label);
      secrets.push(...secretsFromConfig(text, label, 'json-mcpServers'));
    }
  }

  // ---------- 项目级配置（打开工作区即可能执行） ----------
  const projects: ProjectFact[] = [];
  for (const root of opts.workspaces ?? []) {
    if (!existsSync(root)) continue;
    const autoExecConfigs: string[] = [];
    const memoryFiles: string[] = [];
    for (const spec of PROJECT_CONFIGS) {
      const file = join(root, spec.path);
      const text = readText(file);
      if (text === null) continue;
      autoExecConfigs.push(spec.path);
      const parsed = parseServersConfig(text, spec.format);
      if (parsed.error) notes.push(`${tilde(file, home)} 解析失败，本轮的 server 清单可能不完整：${parsed.error}`);
      addServers(spec.harness, parsed.servers, 'project', tilde(file, home));
      secrets.push(...secretsFromConfig(text, tilde(file, home), spec.format));
    }
    for (const mem of PROJECT_MEMORY_FILES) {
      const file = join(root, mem.path);
      if (readText(file) === null) continue;
      memoryFiles.push(mem.path);
      const bytes = Buffer.byteLength(readFileSync(file, 'utf8'), 'utf8');
      memory.push({
        harness: mem.harness,
        file: tilde(file, home),
        exists: true,
        bytes,
        managed: isManagedMemory(file, home, opts.rules),
      });
    }
    projects.push({ root: tilde(root, home), autoExecConfigs, memoryFiles });
  }

  const baselinePath = opts.baselinePath ?? expandHome(opts.rules.guard.baselinePath, home);

  return {
    harnesses,
    servers,
    hooks,
    secrets,
    memory,
    projects,
    baselinePresent: existsSync(baselinePath),
    controls,
    notes,
  };
}

/**
 * 从启动命令里抽出 npm 包与版本。
 * 与 @podsec/scan 的 parseNpxPackage 同一语义，但这里要额外覆盖 `node <pkg>/dist` 的形态。
 */
export function parsePackageFrom(server: RawServer): { name: string; version: string | null } | null {
  const argv = [server.command, ...server.args];
  const idx = argv.findIndex((a) => a === 'npx' || a === 'npx.cmd' || a === 'npmx' || a === 'pnpm' || a === 'bunx');
  if (idx === -1) return null;
  for (let i = idx + 1; i < argv.length; i++) {
    const arg = argv[i] ?? '';
    if (arg === '-y' || arg === '--yes' || arg === '-p' || arg === '--package' || arg === '--') continue;
    if (arg.startsWith('-')) continue;
    const m = arg.match(/^(@[^/@]+\/[^/@]+|[^/@]+)(?:@([^/]+))?$/);
    if (!m) return null;
    return { name: m[1] ?? arg, version: m[2] ?? null };
  }
  return null;
}
