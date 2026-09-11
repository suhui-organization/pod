/**
 * Agent 资产聚合：把 ~/.pod 下已落盘的产物读成一个页面能直接渲染的结构。
 *
 * 数据来源（全部只读，控制台不改写任何状态）：
 * - ~/.pod/policies/*.json   → 策略：agent 身份、server / 工具、三态规则
 * - ~/.pod/audit/*.jsonl     → 审计：真实调用、决策、拒绝原因
 * - ~/.pod/graph/paths.json  → 毒性链（`pod graph toxic` 的产物）
 * - 本机 agent 平台发现（复用 @podsec/scan）
 *
 * 原则（PRODUCT.md「说清楚不夸大」）：缺什么就把缺口写进 notes，
 * 不用空数字假装"一切正常"。
 */
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { scanMachine } from '@podsec/scan';
import type { Policy } from '@podsec/policy';
import type { ToxicPath } from '@podsec/graph';
import type {
  AgentActivity,
  AgentAsset,
  AgentAssetsPayload,
  AgentDecisionSummary,
  AgentPermissions,
  AgentPolicyRef,
  AgentRisk,
  DecisionState,
  DiscoveredPlatform,
  RiskSeverity,
} from './types.js';

const DAY_MS = 86_400_000;
/** 单文件读取上限（防御异常大的日志） */
const MAX_BYTES = 8 * 1024 * 1024;

export interface AggregateOptions {
  /** 用户主目录 */
  home: string;
  /** 默认 <home>/.pod */
  podHome?: string;
  /** 注入"现在"，便于测试 */
  now?: Date;
}

interface AuditRow {
  ts: string;
  agent: string;
  server: string;
  tool: string;
  decision: DecisionState;
  reason: string | null;
  enforced: boolean;
}

const SEVERITY_ORDER: Record<RiskSeverity, number> = { high: 0, medium: 1, low: 2 };

// ---------- 读取 ----------

function readJsonFile<T>(path: string): { ok: true; value: T } | { ok: false; error: string } {
  try {
    const raw = readFileSync(path);
    if (raw.byteLength > MAX_BYTES) return { ok: false, error: `文件超过 ${MAX_BYTES} 字节，已跳过` };
    return { ok: true, value: JSON.parse(raw.toString('utf8')) as T };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : String(err) };
  }
}

function readDirectory(dir: string): string[] | null {
  if (!existsSync(dir)) return null;
  try {
    return readdirSync(dir).sort();
  } catch {
    return null;
  }
}

interface PolicyEntry {
  file: string;
  policy: Policy;
}

function readPolicies(dir: string, notes: string[]): Map<string, PolicyEntry> {
  const out = new Map<string, PolicyEntry>();
  const files = readDirectory(dir);
  if (!files) {
    notes.push(`未找到策略目录 ${dir}：还没有登记任何 agent 策略（先跑 pod policy draft）`);
    return out;
  }
  for (const file of files.filter((f) => f.endsWith('.json'))) {
    const path = join(dir, file);
    const res = readJsonFile<Policy>(path);
    if (!res.ok) {
      notes.push(`策略文件 ${file} 无法解析，已跳过（${res.error}）`);
      continue;
    }
    const policy = res.value;
    if (typeof policy?.agent !== 'string' || policy.agent.length === 0) {
      notes.push(`策略文件 ${file} 缺少 agent 字段，已跳过`);
      continue;
    }
    const existing = out.get(policy.agent);
    if (existing) {
      notes.push(`agent "${policy.agent}" 有多份策略（${existing.file}、${file}），按后者展示`);
    }
    out.set(policy.agent, { file, policy });
  }
  return out;
}

function readAudit(dir: string, notes: string[]): { rows: AuditRow[]; files: number; skipped: number } {
  const rows: AuditRow[] = [];
  let skipped = 0;
  const files = readDirectory(dir);
  if (!files) {
    notes.push(`未找到审计目录 ${dir}：还没有记录到真实调用（pod record / pod serve 会写入）`);
    return { rows, files: 0, skipped };
  }
  const jsonl = files.filter((f) => f.endsWith('.jsonl'));
  for (const file of jsonl) {
    let text: string;
    try {
      const raw = readFileSync(join(dir, file));
      if (raw.byteLength > MAX_BYTES) {
        notes.push(`审计文件 ${file} 超过 ${MAX_BYTES} 字节，已跳过（后续可做分页读取）`);
        continue;
      }
      text = raw.toString('utf8');
    } catch (err) {
      notes.push(`审计文件 ${file} 读取失败，已跳过（${err instanceof Error ? err.message : String(err)}）`);
      continue;
    }
    for (const line of text.split('\n')) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      let raw: unknown;
      try {
        raw = JSON.parse(trimmed);
      } catch {
        skipped++;
        continue;
      }
      const row = raw as Partial<AuditRow>;
      if (
        typeof row?.ts !== 'string' ||
        typeof row.agent !== 'string' ||
        typeof row.server !== 'string' ||
        typeof row.tool !== 'string' ||
        (row.decision !== 'allow' && row.decision !== 'approve' && row.decision !== 'deny')
      ) {
        skipped++;
        continue;
      }
      rows.push({
        ts: row.ts,
        agent: row.agent,
        server: row.server,
        tool: row.tool,
        decision: row.decision,
        reason: typeof row.reason === 'string' ? row.reason : null,
        enforced: row.enforced !== false,
      });
    }
  }
  if (skipped > 0) {
    notes.push(`审计文件中有 ${skipped} 行无法解析，已跳过（哈希链可用 pod verify-audit 校验）`);
  }
  return { rows, files: jsonl.length, skipped };
}

function readToxicPaths(dir: string, notes: string[]): ToxicPath[] {
  const path = join(dir, 'paths.json');
  if (!existsSync(path)) {
    notes.push(`未找到 ${path}：毒性链列需要先跑 pod graph toxic（能力图分析）`);
    return [];
  }
  const res = readJsonFile<ToxicPath[]>(path);
  if (!res.ok || !Array.isArray(res.value)) {
    notes.push(`${path} 无法解析为毒性链列表，已跳过`);
    return [];
  }
  return res.value;
}

// ---------- 计算 ----------

function localDayKey(date: Date): string {
  const m = `${date.getMonth() + 1}`.padStart(2, '0');
  const d = `${date.getDate()}`.padStart(2, '0');
  return `${date.getFullYear()}-${m}-${d}`;
}

/** 近 7 天的日期键，从最早到最新（含今天） */
function last7DayKeys(now: Date): string[] {
  const keys: string[] = [];
  for (let i = 6; i >= 0; i--) {
    keys.push(localDayKey(new Date(now.getTime() - i * DAY_MS)));
  }
  return keys;
}

function summarizePolicy(policy: Policy): AgentPermissions {
  const servers = Object.values(policy.servers ?? {});
  const tools = new Set<string>();
  let allow = 0;
  let approve = 0;
  let deny = 0;
  for (const server of servers) {
    const a = server.allow ?? [];
    const p = server.approve ?? [];
    const d = server.deny ?? [];
    allow += a.length;
    approve += p.length;
    deny += d.length;
    for (const t of [...a, ...p, ...d]) tools.add(t);
  }
  return { servers: servers.length, tools: tools.size, allow, approve, deny };
}

function buildActivity(rows: AuditRow[], now: Date): AgentActivity {
  const dayKeys = last7DayKeys(now);
  const perDay = new Map<string, number>(dayKeys.map((k) => [k, 0]));
  let calls7dTotal = 0;
  let deny7d = 0;
  let approve7d = 0;

  let lastCallAt: string | null = null;
  let lastDecision: AgentDecisionSummary | null = null;

  for (const row of rows) {
    const tsMs = Date.parse(row.ts);
    if (!Number.isNaN(tsMs)) {
      const key = localDayKey(new Date(tsMs));
      if (perDay.has(key)) {
        perDay.set(key, (perDay.get(key) ?? 0) + 1);
        calls7dTotal++;
        if (row.decision === 'deny') deny7d++;
        if (row.decision === 'approve') approve7d++;
      }
      if (lastCallAt === null || tsMs > Date.parse(lastCallAt)) lastCallAt = row.ts;
      if (lastDecision === null || tsMs > Date.parse(lastDecision.at)) {
        lastDecision = {
          decision: row.decision,
          server: row.server,
          tool: row.tool,
          at: row.ts,
          enforced: row.enforced,
          reason: row.reason,
        };
      }
    }
  }

  return {
    entries: rows.length,
    lastCallAt,
    calls7d: dayKeys.map((k) => perDay.get(k) ?? 0),
    calls7dTotal,
    deny7d,
    approve7d,
    lastDecision,
  };
}

function normalizeId(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]/g, '');
}

function platformFor(agentId: string, platforms: DiscoveredPlatform[]): string | null {
  const target = normalizeId(agentId);
  if (target.length === 0) return null;
  const hit = platforms.find((p) => {
    const candidate = normalizeId(p.platform);
    return candidate === target || candidate.includes(target) || target.includes(candidate);
  });
  return hit ? hit.platform : null;
}

function buildRisks(input: {
  agentId: string;
  hasPolicy: boolean;
  policyServerNames: string[];
  rows: AuditRow[];
  toxic: ToxicPath[];
  unpinnedServers: string[];
}): AgentRisk[] {
  const risks: AgentRisk[] = [];
  const { agentId, hasPolicy, rows, toxic } = input;

  const owned = toxic.filter((p) => p.source.agent === agentId || p.sink.agent === agentId);
  if (owned.length > 0) {
    const worst = owned.reduce<RiskSeverity>(
      (acc, p) => (SEVERITY_ORDER[p.severity] < SEVERITY_ORDER[acc] ? p.severity : acc),
      'low',
    );
    const sample = owned[0];
    risks.push({
      kind: 'toxic-path',
      severity: worst,
      label: '存在毒性链',
      detail: sample ? `${sample.rule}：${sample.explain}` : '来自 capability graph 的毒性链分析',
      count: owned.length,
    });
  }

  const unpinned = input.unpinnedServers.filter((name) => input.policyServerNames.includes(name));
  if (unpinned.length > 0) {
    risks.push({
      kind: 'unpinned-package',
      severity: 'medium',
      label: 'MCP server 未锁定版本',
      detail: unpinned.join('、'),
      count: unpinned.length,
    });
  }

  const sensitive = rows.filter(
    (r) => r.decision === 'deny' && (r.reason ?? '').includes('sensitive path pattern'),
  );
  if (sensitive.length > 0) {
    const paths = new Set(
      sensitive.map((r) => (r.reason ?? '').replace(/^.*pattern\s*/, '').replace(/\s*\(.*$/, '')),
    );
    risks.push({
      kind: 'sensitive-path',
      severity: 'high',
      label: '触发敏感路径拒绝',
      detail: [...paths].slice(0, 3).join('、') || '审计中存在敏感路径拒绝',
      count: sensitive.length,
    });
  }

  if (!hasPolicy && rows.length > 0) {
    risks.push({
      kind: 'unregistered',
      severity: 'high',
      label: '未登记策略',
      detail: '有真实调用记录，但 ~/.pod/policies 下没有它的策略——权限不受约束',
      count: rows.length,
    });
  }

  if (hasPolicy && rows.length === 0) {
    risks.push({
      kind: 'no-activity',
      severity: 'low',
      label: '未观测到调用',
      detail: '策略已登记，但审计里没有它的调用记录（策略从行为编译，未观测 = 依据不足）',
      count: 0,
    });
  }

  return risks.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
}

// ---------- 主入口 ----------

export function aggregateAgents(opts: AggregateOptions): AgentAssetsPayload {
  const podHome = opts.podHome ?? join(opts.home, '.pod');
  const policyDir = join(podHome, 'policies');
  const auditDir = join(podHome, 'audit');
  const graphDir = join(podHome, 'graph');
  const now = opts.now ?? new Date();
  const notes: string[] = [];

  const policies = readPolicies(policyDir, notes);
  const audit = readAudit(auditDir, notes);
  const toxic = readToxicPaths(graphDir, notes);
  const scan = scanMachine({ home: opts.home });

  const platforms: DiscoveredPlatform[] = scan.agents
    .filter((a) => a.found)
    .map((a) => ({ platform: a.platform, detail: a.detail ?? null }));
  const unpinnedServers = scan.mcpServers.filter((s) => s.risks.length > 0).map((s) => s.name);

  const rowsByAgent = new Map<string, AuditRow[]>();
  for (const row of audit.rows) {
    const list = rowsByAgent.get(row.agent);
    if (list) list.push(row);
    else rowsByAgent.set(row.agent, [row]);
  }

  const agentIds = [...new Set([...policies.keys(), ...rowsByAgent.keys()])].sort();

  const agents: AgentAsset[] = agentIds.map((id) => {
    const entry = policies.get(id);
    const rows = rowsByAgent.get(id) ?? [];
    const activity = buildActivity(rows, now);

    const policyRef: AgentPolicyRef | null = entry
      ? {
          file: entry.file,
          version: entry.policy.version,
          defaultDecision: entry.policy.defaultDecision ?? 'deny',
        }
      : null;

    const permissions: AgentPermissions = entry
      ? summarizePolicy(entry.policy)
      : { servers: 0, tools: 0, allow: 0, approve: 0, deny: 0 };

    const policyServerNames = entry ? Object.keys(entry.policy.servers ?? {}) : [];

    const risks = buildRisks({
      agentId: id,
      hasPolicy: entry !== undefined,
      policyServerNames,
      rows,
      toxic,
      unpinnedServers,
    });

    const status: AgentAsset['status'] = !entry ? 'unobserved' : activity.calls7dTotal > 0 ? 'active' : 'idle';

    return {
      id,
      label: id,
      platform: platformFor(id, platforms),
      status,
      policy: policyRef,
      permissions,
      risks,
      activity,
    };
  });

  const registeredPlatforms = new Set(
    agents.map((a) => (a.platform ? normalizeId(a.platform) : '')).filter((v) => v.length > 0),
  );
  const discovered = platforms.filter((p) => !registeredPlatforms.has(normalizeId(p.platform)));
  if (discovered.length > 0) {
    notes.push(
      `本机发现 ${discovered.length} 个 agent 平台尚未出现在策略或审计里：` +
        discovered.map((p) => p.platform).join('、'),
    );
  }
  if (scan.secrets.length > 0) {
    notes.push(
      `agent 配置里有 ${scan.secrets.length} 处明文密钥（${[...new Set(scan.secrets.map((s) => s.category))].join('、')}），运行 pod scan 查看掩码报告`,
    );
  }

  const serverUnion = new Set<string>();
  const toolUnion = new Set<string>();
  for (const [, entry] of policies) {
    for (const [serverName, server] of Object.entries(entry.policy.servers ?? {})) {
      serverUnion.add(serverName);
      for (const t of [...(server.allow ?? []), ...(server.approve ?? []), ...(server.deny ?? [])]) {
        toolUnion.add(`${serverName}.${t}`);
      }
    }
  }

  return {
    generatedAt: now.toISOString(),
    podHome,
    dirs: { policies: policyDir, audit: auditDir, graph: graphDir },
    agents,
    totals: {
      agents: agents.length,
      servers: serverUnion.size,
      tools: toolUnion.size,
      calls7d: agents.reduce((sum, a) => sum + a.activity.calls7dTotal, 0),
      deny7d: agents.reduce((sum, a) => sum + a.activity.deny7d, 0),
      agentsWithRisks: agents.filter((a) => a.risks.length > 0).length,
    },
    discovered,
    notes,
  };
}
