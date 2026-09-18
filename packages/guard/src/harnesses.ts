/**
 * Harness 注册表 + 配置解析器。
 *
 * 这里只做两件事：**认识哪些 harness**、**把它们的配置读成同一份结构**。
 * 判定"算不算风险"全在 detect.ts，依据来自用户规则——这一层不做判断。
 *
 * 诚实边界：路径清单是"已知常见位置"，不是"全部可能位置"。用户可以把
 * 自己的配置路径写进 `rules.guard.extraConfigPaths`（通用 JSON 解析），
 * 所以注册表没覆盖到的 harness 也能被看见。
 */
import { expandHome } from '@podsec/policy';
import type { ServerTransport } from './types.js';

export type ConfigFormat =
  | 'json-mcpServers'
  | 'json-opencode'
  | 'json-dsh-manager'
  | 'json-vscode-servers'
  | 'json-zed-context'
  | 'toml-codex';

export interface ConfigSpec {
  /** 相对 home 的路径，支持 ~ 展开与 * glob */
  path: string;
  format: ConfigFormat;
  scope: 'user' | 'project';
}

export interface HarnessDef {
  id: string;
  label: string;
  /** 存在任一即视为已安装 */
  probes: string[];
  configs: ConfigSpec[];
  /** 生命周期钩子来源（format 见 parseHooks） */
  hookFiles?: Array<{ path: string; format: 'claude-hooks' | 'pod-hooks' | 'codex-notify' | 'gemini-hooks' }>;
  /** 长期记忆文件 */
  memoryFiles?: string[];
}

export const HARNESSES: HarnessDef[] = [
  {
    id: 'claude-code',
    label: 'Claude Code',
    probes: ['~/.claude.json', '~/.claude'],
    configs: [{ path: '~/.claude.json', format: 'json-mcpServers', scope: 'user' }],
    hookFiles: [{ path: '~/.claude/settings.json', format: 'claude-hooks' }],
    memoryFiles: ['~/.claude/CLAUDE.md'],
  },
  {
    id: 'codex',
    label: 'Codex',
    probes: ['~/.codex'],
    configs: [{ path: '~/.codex/config.toml', format: 'toml-codex', scope: 'user' }],
    hookFiles: [{ path: '~/.codex/config.toml', format: 'codex-notify' }],
    memoryFiles: ['~/.codex/AGENTS.md'],
  },
  {
    id: 'cursor',
    label: 'Cursor',
    probes: ['~/.cursor'],
    configs: [{ path: '~/.cursor/mcp.json', format: 'json-mcpServers', scope: 'user' }],
  },
  {
    id: 'dsh',
    label: 'DeepSeek Harness (DSH)',
    probes: ['~/.dsh/mcp-manager.json'],
    configs: [{ path: '~/.dsh/mcp-manager.json', format: 'json-dsh-manager', scope: 'user' }],
  },
  {
    id: 'openclaw',
    label: 'OpenClaw',
    probes: ['~/.openclaw'],
    configs: [
      { path: '~/.openclaw/config.json', format: 'json-mcpServers', scope: 'user' },
      { path: '~/.openclaw/mcp.json', format: 'json-mcpServers', scope: 'user' },
    ],
  },
  {
    id: 'opencode',
    label: 'OpenCode',
    probes: ['~/.config/opencode'],
    configs: [
      { path: '~/.config/opencode/opencode.json', format: 'json-opencode', scope: 'user' },
      { path: '~/.config/opencode/opencode.jsonc', format: 'json-opencode', scope: 'user' },
    ],
    memoryFiles: ['~/.config/opencode/AGENTS.md'],
  },
  {
    id: 'gemini-cli',
    label: 'Gemini CLI',
    probes: ['~/.gemini'],
    configs: [{ path: '~/.gemini/settings.json', format: 'json-mcpServers', scope: 'user' }],
    hookFiles: [{ path: '~/.gemini/settings.json', format: 'gemini-hooks' }],
    memoryFiles: ['~/.gemini/GEMINI.md'],
  },
  {
    id: 'windsurf',
    label: 'Windsurf',
    probes: ['~/.codeium/windsurf'],
    configs: [{ path: '~/.codeium/windsurf/mcp_config.json', format: 'json-mcpServers', scope: 'user' }],
  },
  {
    id: 'continue',
    label: 'Continue',
    probes: ['~/.continue'],
    configs: [
      { path: '~/.continue/config.json', format: 'json-mcpServers', scope: 'user' },
      { path: '~/.continue/mcpServers/*.json', format: 'json-mcpServers', scope: 'user' },
    ],
  },
  {
    id: 'zed',
    label: 'Zed',
    probes: ['~/.config/zed'],
    configs: [{ path: '~/.config/zed/settings.json', format: 'json-zed-context', scope: 'user' }],
  },
  {
    id: 'vscode',
    label: 'VS Code / Copilot',
    probes: ['~/.config/Code/User', '~/Library/Application Support/Code/User'],
    configs: [
      { path: '~/.config/Code/User/mcp.json', format: 'json-vscode-servers', scope: 'user' },
      { path: '~/Library/Application Support/Code/User/mcp.json', format: 'json-vscode-servers', scope: 'user' },
    ],
  },
  {
    id: 'cline',
    label: 'Cline / Roo',
    probes: [
      '~/Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev',
      '~/.config/Code/User/globalStorage/saoudrizwan.claude-dev',
    ],
    configs: [
      {
        path: '~/Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json',
        format: 'json-mcpServers',
        scope: 'user',
      },
      {
        path: '~/.config/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json',
        format: 'json-mcpServers',
        scope: 'user',
      },
    ],
  },
  {
    id: 'kilo-code',
    label: 'Kilo Code',
    probes: [
      '~/Library/Application Support/Code/User/globalStorage/kilocode.kilo-code',
      '~/.config/Code/User/globalStorage/kilocode.kilo-code',
    ],
    configs: [
      {
        path: '~/Library/Application Support/Code/User/globalStorage/kilocode.kilo-code/settings/mcp_settings.json',
        format: 'json-mcpServers',
        scope: 'user',
      },
      {
        path: '~/.config/Code/User/globalStorage/kilocode.kilo-code/settings/mcp_settings.json',
        format: 'json-mcpServers',
        scope: 'user',
      },
    ],
  },
  {
    id: 'amazon-q',
    label: 'Amazon Q Developer',
    probes: ['~/.aws/amazonq'],
    configs: [{ path: '~/.aws/amazonq/mcp.json', format: 'json-mcpServers', scope: 'user' }],
  },
  {
    id: 'copilot-cli',
    label: 'GitHub Copilot CLI',
    probes: ['~/.copilot'],
    configs: [{ path: '~/.copilot/mcp-config.json', format: 'json-mcpServers', scope: 'user' }],
  },
  {
    id: 'amp',
    label: 'Amp',
    probes: ['~/.config/amp'],
    configs: [{ path: '~/.config/amp/settings.json', format: 'json-mcpServers', scope: 'user' }],
  },
];

/** 项目级配置：**打开工作区即可能执行**，所以单独列一份（AG-04） */
export const PROJECT_CONFIGS: Array<{ path: string; format: ConfigFormat; harness: string }> = [
  { path: '.mcp.json', format: 'json-mcpServers', harness: 'claude-code' },
  { path: '.cursor/mcp.json', format: 'json-mcpServers', harness: 'cursor' },
  { path: '.vscode/mcp.json', format: 'json-vscode-servers', harness: 'vscode' },
  { path: '.codex/config.toml', format: 'toml-codex', harness: 'codex' },
  { path: '.gemini/settings.json', format: 'json-mcpServers', harness: 'gemini-cli' },
  { path: 'opencode.json', format: 'json-opencode', harness: 'opencode' },
];

/** 项目级记忆文件：随仓库分发，写入即影响之后每一次会话 */
export const PROJECT_MEMORY_FILES: Array<{ path: string; harness: string }> = [
  { path: 'CLAUDE.md', harness: 'claude-code' },
  { path: '.claude/CLAUDE.md', harness: 'claude-code' },
  { path: 'AGENTS.md', harness: 'codex' },
  { path: 'GEMINI.md', harness: 'gemini-cli' },
];

/**
 * 策略/审计/身份里的 agent 名与 harness id 不一定同名（用户会叫 `openclaw-main`）。
 * 这份别名表是**唯一**的匹配依据——宁可不匹配（报成影子 agent，用户手动改名即可），
 * 也不要用模糊匹配把两个不同的东西认成一个。
 */
export const HARNESS_ALIASES: Record<string, string[]> = {
  'claude-code': ['claude', 'claudecode', 'claude-code'],
  codex: ['codex'],
  cursor: ['cursor'],
  dsh: ['dsh', 'deepseek'],
  openclaw: ['openclaw'],
  opencode: ['opencode'],
  'gemini-cli': ['gemini'],
  windsurf: ['windsurf', 'codeium'],
  continue: ['continue'],
  zed: ['zed'],
  vscode: ['vscode', 'copilot', 'code'],
  cline: ['cline', 'roo'],
  'kilo-code': ['kilo'],
  'amazon-q': ['amazonq', 'q-developer'],
  'copilot-cli': ['copilotcli', 'gh-copilot'],
  amp: ['amp'],
};

// ---------- 原始 server 描述 ----------

export interface RawServer {
  name: string;
  command: string;
  args: string[];
  url?: string;
  envKeys: string[];
  headerKeys: string[];
}

function asStringArray(value: unknown): string[] {
  if (Array.isArray(value)) return value.filter((v): v is string => typeof v === 'string');
  if (typeof value === 'string') return [value];
  return [];
}

function objectKeys(value: unknown): string[] {
  if (value && typeof value === 'object' && !Array.isArray(value)) return Object.keys(value as object);
  return [];
}

function normalizeEntry(name: string, raw: unknown): RawServer | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const entry = raw as Record<string, unknown>;
  // command 可能是字符串（标准写法）或数组（opencode 的 local 写法）
  const commandParts = asStringArray(entry.command);
  const command = commandParts[0] ?? '';
  const args = commandParts.length > 1 ? [...commandParts.slice(1), ...asStringArray(entry.args)] : asStringArray(entry.args);
  const url = [entry.url, entry.serverUrl, entry.httpUrl, entry.endpoint].find(
    (v): v is string => typeof v === 'string' && v.length > 0,
  );
  if (!command && !url) return null;
  return {
    name,
    command,
    args,
    ...(url ? { url } : {}),
    envKeys: objectKeys(entry.env ?? entry.environment ?? entry.envVars),
    headerKeys: objectKeys(entry.headers ?? entry.httpHeaders),
  };
}

/** 从任意位置取出 server 映射：兼容 mcpServers / servers / context_servers / mcp */
function serverMapFrom(parsed: Record<string, unknown>): Record<string, unknown> {
  const candidates: unknown[] = [
    parsed.mcpServers,
    parsed.servers,
    parsed.context_servers,
    parsed.mcpServers === undefined && parsed.mcp && typeof parsed.mcp === 'object'
      ? (parsed.mcp as Record<string, unknown>).servers
      : undefined,
    parsed.mcp,
  ];
  for (const candidate of candidates) {
    if (candidate && typeof candidate === 'object' && !Array.isArray(candidate)) {
      return candidate as Record<string, unknown>;
    }
  }
  return {};
}

/** DSH 的 mcp-manager.json 是数组形态的 servers（不是映射） */
function dshServers(parsed: Record<string, unknown>): RawServer[] {
  const list = Array.isArray(parsed.servers) ? parsed.servers : [];
  const out: RawServer[] = [];
  for (const item of list) {
    if (!item || typeof item !== 'object') continue;
    const entry = item as Record<string, unknown>;
    const name = typeof entry.name === 'string' ? entry.name : '';
    if (!name) continue;
    const command = typeof entry.command === 'string' ? entry.command : '';
    const url = typeof entry.url === 'string' ? entry.url : undefined;
    if (!command && !url) continue;
    out.push({
      name,
      command,
      args: asStringArray(entry.args),
      ...(url ? { url } : {}),
      envKeys: objectKeys(entry.env),
      headerKeys: objectKeys(entry.headers),
    });
  }
  return out;
}

// ---------- TOML 子集（只解析 codex config.toml 用到的形态） ----------

function tomlStringValue(raw: string): string | null {
  const m = raw.match(/^"((?:[^"\\]|\\.)*)"\s*(?:#.*)?$/);
  if (!m) return null;
  return (m[1] ?? '').replace(/\\(.)/g, '$1');
}

function tomlStringArray(raw: string): string[] {
  const inner = raw.match(/^\[([\s\S]*)\]\s*(?:#.*)?$/);
  if (!inner) return [];
  return [...(inner[1] ?? '').matchAll(/"((?:[^"\\]|\\.)*)"/g)].map((m) => (m[1] ?? '').replace(/\\(.)/g, '$1'));
}

/**
 * 解析 `[mcp_servers.NAME]` 段落。只认 command / args / env / url / headers，
 * 其余键原样忽略——多认一个键就多一个"解析错了但看起来成功了"的机会。
 */
export function parseCodexToml(text: string): RawServer[] {
  const out: RawServer[] = [];
  let current: { name: string; raw: Record<string, string> } | null = null;
  const flush = (): void => {
    if (!current) return;
    const raw = current.raw;
    const command = raw.command ? tomlStringValue(raw.command) ?? '' : '';
    const args = raw.args ? tomlStringArray(raw.args) : [];
    const url = raw.url ? tomlStringValue(raw.url) ?? undefined : undefined;
    if (command || url) {
      out.push({
        name: current.name,
        command,
        args,
        ...(url ? { url } : {}),
        // inline table 的键可能带引号（env = { "API_KEY" = "v" }），两种写法都要认
        envKeys: raw.env ? [...raw.env.matchAll(/"?([A-Za-z_][A-Za-z0-9_]*)"?\s*=/g)].map((m) => m[1] ?? '') : [],
        headerKeys: raw.headers
          ? [...raw.headers.matchAll(/"?([A-Za-z_][A-Za-z0-9_-]*)"?\s*=/g)].map((m) => m[1] ?? '')
          : [],
      });
    }
    current = null;
  };
  for (const line of text.split('\n')) {
    const trimmed = line.trim();
    const section = trimmed.match(/^\[mcp_servers\.(?:"([^"]+)"|([A-Za-z0-9_.-]+))\]\s*(?:#.*)?$/);
    if (section) {
      flush();
      const name = section[1] ?? section[2] ?? '';
      if (name) current = { name, raw: {} };
      continue;
    }
    if (/^\[/.test(trimmed)) {
      flush();
      continue;
    }
    if (!current) continue;
    const kv = trimmed.match(/^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)$/);
    if (!kv) continue;
    const key = kv[1] ?? '';
    const value = kv[2] ?? '';
    if (['command', 'args', 'env', 'url', 'headers'].includes(key)) current.raw[key] = value;
  }
  flush();
  return out;
}

/** codex 的 notify：顶层 `notify = ["cmd", "arg"]`，命令以宿主权限在事件时执行 */
export function parseCodexNotify(text: string): string[] {
  const out: string[] = [];
  for (const line of text.split('\n')) {
    const m = line.trim().match(/^notify\s*=\s*(\[.*)$/);
    if (!m) continue;
    const argv = tomlStringArray(m[1] ?? '');
    if (argv.length > 0) out.push(argv.join(' '));
  }
  return out;
}

// ---------- 各格式入口 ----------

export interface ParsedConfig {
  servers: RawServer[];
  /** 解析失败时给报表的说明（不静默吞掉） */
  error?: string;
}

export function parseServersConfig(text: string, format: ConfigFormat): ParsedConfig {
  if (format === 'toml-codex') return { servers: parseCodexToml(text) };
  // jsonc：只剥行注释与尾逗号，不做完整 JSON5（复杂语法宁可报错也不猜）
  const cleaned = format === 'json-opencode' ? text.replace(/^\s*\/\/.*$/gm, '') : text;
  let parsed: unknown;
  try {
    parsed = JSON.parse(cleaned);
  } catch (err) {
    return { servers: [], error: err instanceof Error ? err.message : String(err) };
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return { servers: [] };
  const record = parsed as Record<string, unknown>;
  if (format === 'json-dsh-manager') return { servers: dshServers(record) };
  const map = serverMapFrom(record);
  const servers: RawServer[] = [];
  for (const [name, raw] of Object.entries(map)) {
    const normalized = normalizeEntry(name, raw);
    if (normalized) servers.push(normalized);
  }
  return { servers };
}

export function classifyTransport(raw: RawServer): ServerTransport {
  if (!raw.url) return 'stdio';
  return raw.url.startsWith('https://') || raw.url.startsWith('http://') ? 'http' : 'sse';
}

/** Claude Code settings.json 的 hooks：{ hooks: { Event: [{hooks:[{command}]}] } } */
export function parseClaudeHooks(text: string): Array<{ event: string; command: string }> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return [];
  }
  if (!parsed || typeof parsed !== 'object') return [];
  const hooks = (parsed as { hooks?: unknown }).hooks;
  if (!hooks || typeof hooks !== 'object' || Array.isArray(hooks)) return [];
  const out: Array<{ event: string; command: string }> = [];
  for (const [event, entries] of Object.entries(hooks as Record<string, unknown>)) {
    if (!Array.isArray(entries)) continue;
    for (const entry of entries) {
      const inner = (entry as { hooks?: unknown })?.hooks;
      if (Array.isArray(inner)) {
        for (const h of inner) {
          const command = (h as { command?: unknown })?.command;
          if (typeof command === 'string' && command.trim()) out.push({ event, command: command.trim() });
        }
        continue;
      }
      const command = (entry as { command?: unknown })?.command;
      if (typeof command === 'string' && command.trim()) out.push({ event, command: command.trim() });
    }
  }
  return out;
}

/**
 * 抽出 TOML 里所有 `KEY = "value"` 标量，并带上它所在的段落。
 *
 * 为什么按段落扫而不是只看 `[mcp_servers.*]`：密钥不只藏在 MCP 的 env 里。
 * 实测一份 Codex 配置把 bearer token 放在 `[model_providers.deepseek]`——
 * 只扫 MCP 段落会漏掉它。带上段落名，报表才能写出
 * `model_providers.deepseek.experimental_bearer_token` 这种"直接去改哪个变量"的定位。
 *
 * 只认双引号标量：嵌套表与多行字符串宁可不认，也不猜错配对。
 */
export function parseTomlKeyValues(text: string): Array<{ section: string; key: string; value: string }> {
  const out: Array<{ section: string; key: string; value: string }> = [];
  const unescape = (raw: string): string => raw.replace(/\\(.)/g, '$1');
  let section = '';
  for (const line of text.split('\n')) {
    const trimmed = line.trim();
    const header = trimmed.match(/^\[(?:"([^"]+)"|([^\]]+))\]\s*(?:#.*)?$/);
    if (header) {
      section = (header[1] ?? header[2] ?? '').trim();
      continue;
    }
    const kv = trimmed.match(/^"?([A-Za-z_][A-Za-z0-9_-]*)"?\s*=\s*(.+)$/);
    if (!kv) continue;
    const key = kv[1] ?? '';
    const rest = (kv[2] ?? '').trim();
    const scalar = rest.match(/^"((?:[^"\\]|\\.)*)"\s*(?:#.*)?$/);
    if (scalar) {
      out.push({ section, key, value: unescape(scalar[1] ?? '') });
      continue;
    }
    // 行内表：env = { "KEY" = "value", ... } —— 键用 `env.KEY` 前缀，保留层级信息
    const inline = rest.match(/^\{([\s\S]*)\}\s*(?:#.*)?$/);
    if (!inline) continue;
    for (const pair of (inline[1] ?? '').matchAll(/"?([A-Za-z_][A-Za-z0-9_-]*)"?\s*=\s*"((?:[^"\\]|\\.)*)"/g)) {
      out.push({ section, key: `${key}.${pair[1] ?? ''}`, value: unescape(pair[2] ?? '') });
    }
  }
  return out;
}

/** 通用 JSON 钩子：{ hooks: [{ event, command }] } 或 [{ event, command }] */
export function parseGenericHooks(text: string): Array<{ event: string; command: string }> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return [];
  }
  const list = Array.isArray(parsed)
    ? parsed
    : Array.isArray((parsed as { hooks?: unknown })?.hooks)
      ? ((parsed as { hooks: unknown[] }).hooks)
      : [];
  const out: Array<{ event: string; command: string }> = [];
  for (const item of list) {
    const event = (item as { event?: unknown })?.event;
    const command = (item as { command?: unknown })?.command;
    if (typeof command === 'string' && command.trim()) {
      out.push({ event: typeof event === 'string' ? event : 'hook', command: command.trim() });
    }
  }
  return out;
}

export function expandProbePaths(paths: string[], home: string): string[] {
  return paths.map((p) => expandHome(p, home));
}
