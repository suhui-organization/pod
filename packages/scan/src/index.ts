/**
 * pod scan — 只读风险扫描器（获客楔子，D5）。
 *
 * 三类扫描（threat-model.md）：
 *   T6 影子 agent：发现本机已安装的 agent 平台与 MCP server 清单
 *   T4 MCP 供应链：npm 包是否锁定版本（@latest / 无版本 = 风险）
 *   T2 密钥暴露：agent 配置文件中的明文密钥（只报告掩码，不打印原文）
 *
 * 纯函数、只读；不修改任何文件、不联网。
 */
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { t } from '@podsec/i18n';

// ---------- 类型 ----------

export interface McpServerInfo {
  name: string;
  command: string;
  args: string[];
  /** 从 npx/npmx 拉取的包信息（来源风险） */
  npxPackage?: { name: string; version: string | null };
  risks: string[];
}

export interface SecretFinding {
  file: string;
  key: string;
  category: string;
  /** 掩码显示（如 ghp_ab12…cd34），不暴露原文 */
  masked: string;
}

export interface Finding {
  severity: 'high' | 'medium' | 'low';
  message: string;
}

export interface ScanResult {
  agents: Array<{ platform: string; found: boolean; detail?: string }>;
  mcpServers: McpServerInfo[];
  secrets: SecretFinding[];
  findings: Finding[];
}

export interface ScanOptions {
  home: string;
}

// ---------- 密钥模式（T2） ----------

export const SECRET_PATTERNS: Array<{ category: string; re: RegExp }> = [
  { category: 'github-pat', re: /ghp_[A-Za-z0-9]{36}/ },
  { category: 'github-fine-grained', re: /github_pat_[A-Za-z0-9_]{22,}/ },
  { category: 'github-oauth', re: /gho_[A-Za-z0-9]{36}/ },
  { category: 'openai', re: /\bsk-(?:proj-)?[A-Za-z0-9]{20,}/ },
  { category: 'anthropic', re: /\bsk-ant-[A-Za-z0-9-]{20,}/ },
  { category: 'aws-access-key', re: /AKIA[0-9A-Z]{16}/ },
  { category: 'slack-token', re: /xox[baprs]-[A-Za-z0-9-]{10,}/ },
  { category: 'google-api-key', re: /AIza[0-9A-Za-z_-]{35}/ },
  { category: 'gitlab-pat', re: /glpat-[A-Za-z0-9_-]{20,}/ },
];

export function maskSecret(secret: string): string {
  if (secret.length <= 8) return '***';
  return `${secret.slice(0, 4)}…${secret.slice(-2)}`;
}

/** 在文本中扫描密钥，返回 (key, category, masked) 列表；同一文本去重 */
export function scanSecretsInText(text: string, fileLabel: string): SecretFinding[] {
  const out: SecretFinding[] = [];
  const seen = new Set<string>();
  for (const { category, re } of SECRET_PATTERNS) {
    const m = text.match(re);
    if (!m) continue;
    const key = m[0];
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({ file: fileLabel, key: key.slice(0, 8), category, masked: maskSecret(key) });
  }
  return out;
}

// ---------- MCP 供应链（T4） ----------

/** 解析 npx 命令行里的包名与版本；返回 null 表示不是 npx 来源 */
export function parseNpxPackage(args: string[]): { name: string; version: string | null } | null {
  const idx = args.findIndex((a) => a === 'npx' || a === 'npx.cmd' || a === 'npmx');
  if (idx === -1) return null;
  for (let i = idx + 1; i < args.length; i++) {
    const a = args[i]!;
    if (a === '-y' || a === '--yes' || a === '-p' || a === '--package' || a === '--') continue;
    if (a.startsWith('-')) continue;
    // 包名：@scope/name@ver | name@ver | @scope/name | name
    const m = a.match(/^(@[^/@]+\/[^/@]+|[^/@]+)(?:@([^/]+))?$/);
    if (!m) return null;
    return { name: m[1]!, version: m[2] ?? null };
  }
  return null;
}

export function inspectMcpServer(input: { name: string; command: string; args: string[] }): McpServerInfo {
  const risks: string[] = [];
  // npx 可能出现在 command 字段（真实 mcp-manager 格式）或 args 里
  const pkg = parseNpxPackage([input.command, ...input.args]);
  if (pkg) {
    if (pkg.version === null) risks.push(t('npm 包 {pkg} 未锁定版本（供应链风险，见 T4）', { pkg: pkg.name }));
    else if (pkg.version === 'latest') risks.push(t('npm 包 {pkg} 使用 @latest 未锁定版本（供应链风险，见 T4）', { pkg: pkg.name }));
  }
  return { ...input, npxPackage: pkg ?? undefined, risks };
}

// ---------- 文件读取（只读、限大小） ----------

const MAX_FILE_BYTES = 1_000_000;

function readTextIfExists(path: string): string | null {
  if (!existsSync(path)) return null;
  try {
    const stat = readFileSync(path);
    if (stat.byteLength > MAX_FILE_BYTES) return null;
    return stat.toString('utf8');
  } catch {
    return null;
  }
}

// ---------- 主扫描 ----------

function agentProbes(home: string): Array<{ platform: string; probe: string; detail?: string }> {
  return [
    { platform: 'DeepSeek Harness (DSH)', probe: join(home, '.dsh/mcp-manager.json'), detail: 'dsh-mcp-manager' },
    { platform: 'OpenClaw', probe: join(home, '.openclaw') },
    { platform: 'Claude Code', probe: join(home, '.claude.json') },
    { platform: 'Cursor', probe: join(home, '.cursor') },
    { platform: 'Codex', probe: join(home, '.codex') },
    { platform: 'OpenCode', probe: join(home, '.config/opencode') },
  ];
}

export function scanMachine(opts: ScanOptions): ScanResult {
  const { home } = opts;
  const findings: Finding[] = [];
  const secrets: SecretFinding[] = [];
  const mcpServers: McpServerInfo[] = [];

  // 1) agent 发现（T6）
  const agents = agentProbes(home).map(({ platform, probe, detail }) => ({
    platform,
    found: existsSync(probe),
    detail,
  }));
  const foundCount = agents.filter((a) => a.found).length;
  if (foundCount > 3) {
    findings.push({
      severity: 'medium',
      message: t('发现 {count} 个 agent 平台（影子 agent 风险，见 T6）：{list}', {
          count: foundCount,
          list: agents.filter((a) => a.found).map((a) => a.platform).join('、'),
        }),
    });
  }

  // 2) MCP server 清单（DSH 的 mcp-manager.json；其他平台 v0 先不解析格式）
  const managerFile = join(home, '.dsh/mcp-manager.json');
  const managerText = readTextIfExists(managerFile);
  if (managerText) {
    try {
      const manager = JSON.parse(managerText) as {
        servers?: Array<{ name?: string; command?: string; args?: string[] }>;
      };
      for (const s of manager.servers ?? []) {
        if (!s.name || !s.command) continue;
        const info = inspectMcpServer({ name: s.name, command: s.command, args: s.args ?? [] });
        mcpServers.push(info);
      }
    } catch {
      findings.push({ severity: 'high', message: t('{file} 不是合法 JSON，无法盘点 MCP server', { file: managerFile }) });
    }
  }
  for (const s of mcpServers) {
    for (const risk of s.risks) {
      findings.push({ severity: 'medium', message: t('MCP server "{server}": {risk}', { server: s.name, risk }) });
    }
  }

  // 3) 密钥暴露（T2）：agent 配置文件（只读）
  const secretFiles: Array<{ path: string; label: string }> = [
    { path: managerFile, label: '~/.dsh/mcp-manager.json' },
    { path: join(home, '.claude.json'), label: '~/.claude.json' },
    { path: join(home, '.codex/config.toml'), label: '~/.codex/config.toml' },
    { path: join(home, '.cursor/mcp.json'), label: '~/.cursor/mcp.json' },
    { path: join(home, '.config/opencode/opencode.json'), label: '~/.config/opencode/opencode.json' },
  ];
  for (const { path, label } of secretFiles) {
    const text = readTextIfExists(path);
    if (text === null) continue;
    // mcp-manager.json 结构化优先：env 值的变量名作为 key
    if (path === managerFile) {
      try {
        const manager = JSON.parse(text) as { servers?: Array<{ name?: string; env?: Record<string, string> }> };
        for (const s of manager.servers ?? []) {
          for (const [key, value] of Object.entries(s.env ?? {})) {
            if (!value) continue;
            const hits = scanSecretsInText(value, `${label} → server "${s.name ?? '?'}"`);
            for (const h of hits) {
              secrets.push({ ...h, key });
            }
          }
        }
      } catch {
        // 交给全文扫描兜底
      }
    }
    secrets.push(...scanSecretsInText(text, label));
  }
  for (const s of secrets) {
    findings.push({
      severity: 'high',
      message: t('{file} 中发现明文 {category}（{masked}）', { file: s.file, category: s.category, masked: s.masked }),
    });
  }

  return { agents, mcpServers, secrets, findings };
}

// ---------- 报表渲染 ----------

export function renderMarkdown(result: ScanResult): string {
  const lines: string[] = [t('# pod scan 报表 — 你 Agent 的信任基线'), ''];
  lines.push(t('> 第一步：看清风险面。第二步：装闸门。第三步：每一步都有不可篡改的证据。'));
  lines.push('');
  lines.push(t('扫描时间：{ts}', { ts: new Date().toISOString() }));
  lines.push('');
  lines.push(t('## 1. Agent 清单（影子 agent，T6）'));
  lines.push('');
  lines.push(t('| 平台 | 已安装 |'));
  lines.push('|------|--------|');
  for (const a of result.agents) {
    lines.push(`| ${a.platform} | ${a.found ? '✅' : '—'} |`);
  }
  lines.push('');

  lines.push(t('## 2. MCP server（{count} 个）', { count: result.mcpServers.length }));
  lines.push('');
  if (result.mcpServers.length === 0) {
    lines.push(t('未发现（DSH mcp-manager.json 不存在或为空）。'));
  } else {
    lines.push(t('| server | 来源 | 版本锁定 | 风险 |'));
    lines.push('|--------|------|----------|------|');
    for (const s of result.mcpServers) {
      const src = s.npxPackage ? `npx ${s.npxPackage.name}` : t('本地 bin');
      const pinned = s.npxPackage ? (s.npxPackage.version && s.npxPackage.version !== 'latest' ? '✅' : '❌') : 'n/a';
      lines.push(`| ${s.name} | ${src} | ${pinned} | ${s.risks.join('；') || '—'} |`);
    }
  }
  lines.push('');

  lines.push(t('## 3. 密钥暴露（{count} 处）', { count: result.secrets.length }));
  lines.push('');
  if (result.secrets.length === 0) {
    lines.push(t('✅ 未在 agent 配置中发现明文密钥。'));
  } else {
    lines.push(t('| 位置 | 变量 | 类型 | 掩码 |'));
    lines.push('|------|------|------|------|');
    for (const s of result.secrets) {
      lines.push(`| ${s.file} | ${s.key} | ${s.category} | ${s.masked} |`);
    }
    lines.push('');
    lines.push(t('> 掩码仅显示前后几位。密钥管理建议：迁移到系统钥匙串 / secret 管理器后从配置中移除。'));
  }
  lines.push('');

  lines.push(t('## 4. 风险汇总'));
  lines.push('');
  if (result.findings.length === 0) {
    lines.push(t('✅ 未发现风险。'));
  } else {
    for (const f of result.findings) {
      const tag = f.severity === 'high' ? '🔴' : f.severity === 'medium' ? '🟠' : '🟡';
      lines.push(`- ${tag} **[${f.severity.toUpperCase()}]** ${f.message}`);
    }
  }
  lines.push('');
  lines.push('---');
  lines.push(t('pod scan 只读、不联网、不上传任何数据。'));
  lines.push('');
  lines.push(t('**下一步**：`pod init --template baseline` 装上闸门，'));
  lines.push(t('每次工具调用写入 SHA-256 哈希链——从今天起，你的 Agent 每一步都有不可篡改的证据。'));
  lines.push('');
  // 漏斗：scan 是 6 类平台的快速体检，guard 覆盖 16 类并给出"先做这三件事"，
  // harden 把结论变成可交付的报告。三条命令都只读或本地落盘，不制造压力。
  lines.push(t('**想把 16 类 harness 都过一遍**：`pod guard scan`（只读，输出「先做这三件事」与逐条处置命令）。'));
  lines.push(t('**要交给客户或审计方**：`pod harden --out ~/pod-audit-<日期>`（可交付、对方能用 `pod harden --verify` 自己验的报告目录）。'));
  return lines.join('\n');
}

// ---------- 防绕过检查（P1，信任边界完整性） ----------

export interface BypassFinding {
  /** 配置文件路径 */
  file: string;
  server: string;
  command: string;
}

/**
 * 扫描常见 agent 配置，找出"未经过 pod 网关"的 MCP server。
 * 这些 server 可被 agent 直连，绕过网关的策略/审计（T 边界完整性）。
 * v0 覆盖：~/.claude.json（Claude Code）、~/.dsh/mcp-manager.json（DSH）。
 */
export function checkBypass(home: string): BypassFinding[] {
  const out: BypassFinding[] = [];
  const managerFile = join(home, '.dsh/mcp-manager.json');
  const managerText = readTextIfExists(managerFile);
  if (managerText) {
    try {
      const manager = JSON.parse(managerText) as {
        servers?: Array<{ name?: string; command?: string; args?: string[] }>;
      };
      for (const s of manager.servers ?? []) {
        if (!s.name || !s.command) continue;
        if (!isPodCommand(s.command, s.args ?? [])) {
          out.push({ file: '~/.dsh/mcp-manager.json', server: s.name, command: s.command });
        }
      }
    } catch {
      // 忽略解析失败
    }
  }
  const claudeFile = join(home, '.claude.json');
  const claudeText = readTextIfExists(claudeFile);
  if (claudeText) {
    try {
      const claude = JSON.parse(claudeText) as {
        mcpServers?: Record<string, { command?: string; args?: string[] }>;
      };
      for (const [name, cfg] of Object.entries(claude.mcpServers ?? {})) {
        if (!cfg.command) continue;
        if (!isPodCommand(cfg.command, cfg.args ?? [])) {
          out.push({ file: '~/.claude.json', server: name, command: cfg.command });
        }
      }
    } catch {
      // 忽略解析失败
    }
  }
  return out;
}

function isPodCommand(command: string, args: string[]): boolean {
  const joined = [command, ...args].join(' ');
  return joined.includes('pod ') || joined.endsWith('pod') || joined.includes('/pod');
}
