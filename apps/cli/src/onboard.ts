/**
 * pod onboard — 一键接管本机 MCP server（OPC 缺口 G1：装不起来）。
 *
 * 闭环：pod onboard（发现 + 改写为 pod serve --record-only）→ 正常使用采集语料
 *       → pod policy draft（生成最小权限草稿）→ 人工复核 → 切换执法模式
 *
 * 安全默认：
 * - 默认 dry-run，只打印计划；必须显式 --yes 才改写配置；
 * - 改写前把原配置备份为 <config>.pod-backup-<timestamp>；
 * - 默认用 record-only 包装（只录不拦），避免 onboarding 当天就把用户工作流打断；
 * - 只支持 stdio transport；已包装过的 server 跳过。
 */
import { copyFileSync, existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { basename, join } from 'node:path';
import type { Policy } from '@podsec/policy';

export type ConfigFormat = 'dsh' | 'claude' | 'cursor';

export type ServerLocation =
  | { kind: 'array'; index: number }
  | { kind: 'object'; key: string };

export interface ServerEntry {
  name: string;
  command: string;
  args: string[];
  env?: Record<string, string>;
  transport?: string;
  location: ServerLocation;
  /** true = 已经指向 pod（跳过，避免二次包装） */
  wrapped: boolean;
}

export interface OnboardTarget {
  format: ConfigFormat;
  /** 建议的 agent 身份（用于策略绑定） */
  agent: string;
  configPath: string;
  servers: ServerEntry[];
}

const DEFAULT_AGENT: Record<ConfigFormat, string> = {
  dsh: 'dsh',
  claude: 'claude-code',
  cursor: 'cursor',
};

function candidatePaths(home: string): Array<{ format: ConfigFormat; path: string }> {
  return [
    { format: 'dsh', path: join(home, '.dsh', 'mcp-manager.json') },
    { format: 'claude', path: join(home, '.claude.json') },
    { format: 'cursor', path: join(home, '.cursor', 'mcp.json') },
  ];
}

function inferFormat(configPath: string): ConfigFormat | null {
  const name = basename(configPath);
  if (name === 'mcp-manager.json') return 'dsh';
  if (name === '.claude.json') return 'claude';
  if (name === 'mcp.json' && configPath.includes('.cursor')) return 'cursor';
  return null;
}

/**
 * 判断一个 MCP 条目是否已经被 pod 包装。覆盖三种形态：
 * 1. 直接调用 pod 二进制：`pod serve|record ...`
 * 2. 包装脚本：`node .../pod-serve-xxx.sh|.js`
 * 3. 源码/绝对路径调用：`node .../pod/apps/cli/src/index.ts record ...`
 */
export function isPodCommand(command: string, args: string[]): boolean {
  const base = basename(command).toLowerCase();
  const hasSubcommand = args.includes('serve') || args.includes('record');
  if ((base === 'pod' || base === 'pod.cmd') && hasSubcommand) return true;
  const joined = [command, ...args].join(' ');
  if (/\bpod[-_a-z0-9]*\.(js|mjs|cjs|sh)\b/i.test(joined)) return true;
  if (hasSubcommand && /(^|[/\\])pod([/\\-])/i.test(joined)) return true;
  return false;
}

function parseDsh(raw: unknown, configPath: string): ServerEntry[] {
  const servers = (raw as { servers?: Array<Record<string, unknown>> }).servers ?? [];
  const out: ServerEntry[] = [];
  servers.forEach((s, index) => {
    const name = typeof s.name === 'string' ? s.name : undefined;
    const command = typeof s.command === 'string' ? s.command : undefined;
    if (!name || !command) return;
    const args = Array.isArray(s.args) ? (s.args as string[]) : [];
    out.push({
      name,
      command,
      args,
      env: s.env as Record<string, string> | undefined,
      transport: typeof s.transport === 'string' ? s.transport : undefined,
      location: { kind: 'array', index },
      wrapped: isPodCommand(command, args),
    });
  });
  return out;
}

function parseMcpServersObject(raw: unknown): ServerEntry[] {
  const servers = (raw as { mcpServers?: Record<string, Record<string, unknown>> }).mcpServers ?? {};
  const out: ServerEntry[] = [];
  for (const [key, cfg] of Object.entries(servers)) {
    const command = typeof cfg.command === 'string' ? cfg.command : undefined;
    if (!command) continue;
    const args = Array.isArray(cfg.args) ? (cfg.args as string[]) : [];
    out.push({
      name: key,
      command,
      args,
      env: cfg.env as Record<string, string> | undefined,
      transport: typeof cfg.transport === 'string' ? cfg.transport : undefined,
      location: { kind: 'object', key },
      wrapped: isPodCommand(command, args),
    });
  }
  return out;
}

export interface DiscoverOptions {
  home: string;
  /** 只处理指定配置文件（否则扫描默认候选路径） */
  config?: string;
  /** 覆盖 agent 名（默认按平台推断） */
  agent?: string;
}

/** 发现本机可接管的 MCP server（只读，不改任何文件） */
export function discoverTargets(opts: DiscoverOptions): OnboardTarget[] {
  const candidates = opts.config
    ? [{ format: inferFormat(opts.config), path: opts.config }]
    : candidatePaths(opts.home);
  const out: OnboardTarget[] = [];
  for (const c of candidates) {
    if (!existsSync(c.path)) continue;
    let raw: unknown;
    try {
      raw = JSON.parse(readFileSync(c.path, 'utf8'));
    } catch {
      continue;
    }
    let format = c.format;
    if (!format) format = Array.isArray((raw as { servers?: unknown }).servers) ? 'dsh' : 'claude';
    const servers = format === 'dsh' ? parseDsh(raw, c.path) : parseMcpServersObject(raw);
    if (servers.length === 0) continue;
    out.push({
      format,
      agent: opts.agent ?? DEFAULT_AGENT[format],
      configPath: c.path,
      servers,
    });
  }
  return out;
}

/** 构造 pod serve --record-only 包装命令（保留原始 command/args，env 留在配置条目里） */
export function buildWrapArgs(
  server: ServerEntry,
  agent: string,
  policyPath: string,
  podBin = 'pod',
): { command: string; args: string[] } {
  return {
    command: podBin,
    args: [
      'serve',
      '--record-only',
      '--agent',
      agent,
      '--server',
      server.name,
      '--policy',
      policyPath,
      '--command',
      server.command,
      ...server.args.flatMap((a) => ['--arg', a]),
    ],
  };
}

export interface OnboardApplyOptions {
  policyDir: string;
  /** true = 只打印计划，不写任何文件 */
  dryRun: boolean;
  /** 备份文件时间戳（测试可注入，默认当前时间） */
  timestamp?: string;
  /** pod 可执行文件路径（默认 "pod"，需在 PATH 中） */
  podBin?: string;
}

export interface OnboardChange {
  configPath: string;
  servers: string[];
  backup?: string;
}

export interface OnboardResult {
  changes: OnboardChange[];
  policies: string[];
  skipped: string[];
}

export interface CoverageEntry {
  configPath: string;
  agent: string;
  server: string;
  command: string;
}

export interface CoverageReport {
  /** 已指向 pod 网关的 server */
  managed: CoverageEntry[];
  /** 未经过 pod 的 server（可绕过策略/审计） */
  unmanaged: CoverageEntry[];
  /** v0 不支持的 transport（如 sse），无法包装 */
  unsupported: Array<CoverageEntry & { transport: string }>;
}

/** 计算受管覆盖率（P1 缺口 G5：防线盲区） */
export function computeCoverage(targets: OnboardTarget[]): CoverageReport {
  const managed: CoverageEntry[] = [];
  const unmanaged: CoverageEntry[] = [];
  const unsupported: Array<CoverageEntry & { transport: string }> = [];
  for (const t of targets) {
    for (const s of t.servers) {
      const base = { configPath: t.configPath, agent: t.agent, server: s.name, command: s.command };
      if (s.transport && s.transport !== 'stdio') {
        unsupported.push({ ...base, transport: s.transport });
      } else if (s.wrapped) {
        managed.push(base);
      } else {
        unmanaged.push(base);
      }
    }
  }
  return { managed, unmanaged, unsupported };
}

function policyForAgent(agent: string, servers: ServerEntry[]): Policy {
  const entries: Record<string, { allow: string[] }> = {};
  for (const s of servers) entries[s.name] = { allow: ['*'] };
  return { version: '0.1.0', agent, defaultDecision: 'deny', servers: entries };
}

/** 执行接管：写策略（record 模板）+ 备份并改写各 agent 配置 */
export function applyOnboard(targets: OnboardTarget[], opts: OnboardApplyOptions): OnboardResult {
  const stamp = opts.timestamp ?? new Date().toISOString().replace(/[:.]/g, '-');
  const changes: OnboardChange[] = [];
  const policies: string[] = [];
  const skipped: string[] = [];

  const byAgent = new Map<string, ServerEntry[]>();
  for (const t of targets) {
    for (const s of t.servers) {
      if (s.wrapped) {
        skipped.push(`${t.configPath} → "${s.name}" (已由 pod 包装)`);
        continue;
      }
      if (s.transport && s.transport !== 'stdio') {
        skipped.push(`${t.configPath} → "${s.name}" (transport=${s.transport}，v0 只支持 stdio)`);
        continue;
      }
      const list = byAgent.get(t.agent) ?? [];
      list.push(s);
      byAgent.set(t.agent, list);
    }
  }

  for (const [agent, servers] of byAgent) {
    const path = join(opts.policyDir, `onboard-${agent}.json`);
    policies.push(path);
    if (!opts.dryRun) {
      mkdirSync(opts.policyDir, { recursive: true });
      writeFileSync(path, JSON.stringify(policyForAgent(agent, servers), null, 2) + '\n', 'utf8');
    }
  }

  for (const t of targets) {
    const active = t.servers.filter(
      (s) => !s.wrapped && (!s.transport || s.transport === 'stdio'),
    );
    if (active.length === 0) continue;
    const policyPath = join(opts.policyDir, `onboard-${t.agent}.json`);
    if (opts.dryRun) {
      changes.push({ configPath: t.configPath, servers: active.map((s) => s.name) });
      continue;
    }
    const raw = JSON.parse(readFileSync(t.configPath, 'utf8')) as Record<string, unknown>;
    for (const s of active) {
      const wrap = buildWrapArgs(s, t.agent, policyPath, opts.podBin ?? 'pod');
      if (s.location.kind === 'array') {
        const arr = raw.servers as Array<Record<string, unknown>>;
        const item = arr[s.location.index]!;
        item.command = wrap.command;
        item.args = wrap.args;
      } else {
        const obj = raw.mcpServers as Record<string, Record<string, unknown>>;
        const item = obj[s.location.key]!;
        item.command = wrap.command;
        item.args = wrap.args;
      }
    }
    const backup = `${t.configPath}.pod-backup-${stamp}`;
    copyFileSync(t.configPath, backup);
    writeFileSync(t.configPath, JSON.stringify(raw, null, 2) + '\n', 'utf8');
    changes.push({ configPath: t.configPath, servers: active.map((s) => s.name), backup });
  }

  return { changes, policies, skipped };
}

/** 从最近的备份恢复配置 */
export function revertOnboard(opts: { home: string; config?: string }): Array<{ configPath: string; backup: string }> {
  const candidates = opts.config
    ? [opts.config]
    : candidatePaths(opts.home).map((c) => c.path);
  const restored: Array<{ configPath: string; backup: string }> = [];
  for (const configPath of candidates) {
    if (!existsSync(configPath)) continue;
    const dir = join(configPath, '..');
    const prefix = `${basename(configPath)}.pod-backup-`;
    const backups = readdirSync(dir)
      .filter((f) => f.startsWith(prefix))
      .sort();
    const latest = backups[backups.length - 1];
    if (!latest) continue;
    const backup = join(dir, latest);
    copyFileSync(backup, configPath);
    restored.push({ configPath, backup });
  }
  return restored;
}
