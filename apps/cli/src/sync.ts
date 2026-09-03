/**
 * pod sync — 把本地审计（哈希链）增量推送到 Pod Cloud。
 *
 * 语义：
 *   - 每个 (server) 一条独立哈希链，与本地审计文件一一对应；
 *   - 同步游标 ~/.pod/sync-state/<agentId>.json 按 server 记录 last_hash，
 *     断点续传、幂等（无新事件则跳过）；
 *   - 服务端按 (agent, server) 校验 prev_hash 连续性，断链返回 409；
 *   - 只传哈希与元数据，不传参数/输出原文（隐私最小化）。
 */
import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { AuditLog } from '@podsec/audit';

export interface CloudAgentBinding {
  /** 本地审计文件的 agent 字段（"*" = 全部） */
  local_agent: string;
  agent_id: number;
  sync_token: string;
}

export interface CloudConfig {
  api_url: string;
  /** 旧格式：单 agent（agent_id/sync_token） */
  agent_id?: number;
  sync_token?: string;
  /** 新格式：多 agent 绑定（优先） */
  agents?: CloudAgentBinding[];
}

export interface SyncResult {
  agent_id: number;
  servers: Array<{ server: string; synced: number; skipped: number }>;
  total_synced: number;
  /** 每个绑定本次推送数（多 agent 时用于正确标注归属，不再笼统显示首个绑定） */
  bindings: Array<{ agent_id: number; synced: number }>;
}

export function loadCloudConfig(configPath?: string): CloudConfig {
  const path = configPath ?? join(homedir(), '.pod', 'cloud.json');
  if (!existsSync(path)) {
    throw new Error(`未找到云配置 ${path}（先 pod cloud-setup 或手工写入 api_url/agent_id/sync_token）`);
  }
  const raw = JSON.parse(readFileSync(path, 'utf8')) as Partial<CloudConfig>;
  if (!raw.api_url) {
    throw new Error(`云配置 ${path} 缺少 api_url`);
  }
  if (raw.agents && raw.agents.length > 0) {
    for (const b of raw.agents) {
      if (!b.local_agent || !b.agent_id || !b.sync_token) {
        throw new Error(`云配置 ${path} 的 agents 条目缺少 local_agent/agent_id/sync_token`);
      }
    }
    return { api_url: raw.api_url.replace(/\/+$/, ''), agents: raw.agents };
  }
  if (!raw.agent_id || !raw.sync_token) {
    throw new Error(`云配置 ${path} 缺少 agent_id/sync_token（或 agents 数组）`);
  }
  return { api_url: raw.api_url.replace(/\/+$/, ''), agent_id: raw.agent_id, sync_token: raw.sync_token };
}

export function loadSyncState(agentId: number): Record<string, string> {
  const path = join(homedir(), '.pod', 'sync-state', `${agentId}.json`);
  if (!existsSync(path)) return {};
  try {
    return JSON.parse(readFileSync(path, 'utf8')) as Record<string, string>;
  } catch {
    return {};
  }
}

export function saveSyncState(agentId: number, state: Record<string, string>): void {
  const path = join(homedir(), '.pod', 'sync-state', `${agentId}.json`);
  mkdirSync(join(homedir(), '.pod', 'sync-state'), { recursive: true });
  writeFileSync(path, JSON.stringify(state, null, 2), 'utf8');
}

interface ServerEvents {
  server: string;
  events: Array<Record<string, unknown>>;
}

/** 读取审计目录，按 server 分组并过滤掉已同步（游标之后）的事件；localAgent='*' 不过滤 */
export function collectPendingEvents(
  auditDir: string,
  cursor: Record<string, string>,
  localAgent: string = '*',
): ServerEvents[] {
  const out: ServerEvents[] = [];
  // 顶层 *.jsonl（旧布局）+ 子目录 <agent>/*.jsonl（多网关布局）
  const files: Array<{ dir: string; file: string }> = [];
  if (existsSync(auditDir)) {
    for (const f of readdirSync(auditDir).sort()) {
      if (f.endsWith('.jsonl')) files.push({ dir: auditDir, file: f });
      else if (!f.endsWith('.legacy')) {
        const sub = join(auditDir, f);
        if (existsSync(sub) && !existsSync(join(sub, '.skip'))) {
          for (const sf of readdirSync(sub).filter((x) => x.endsWith('.jsonl')).sort()) {
            files.push({ dir: sub, file: sf });
          }
        }
      }
    }
  }
  for (const { dir, file } of files) {
    const server = file.replace(/\.jsonl$/, '');
    const log = AuditLog.fromJSONL(readFileSync(join(dir, file), 'utf8'), '');
    if (log.entries.length === 0) continue;
    const lastHash = cursor[server];
    let events = log.entries
      .filter((e) => localAgent === '*' || e.agent === localAgent)
      .map((e) => ({
      seq: e.seq,
      ts: e.ts,
      server: e.server,
      tool: e.tool,
      args_hash: e.argsHash,
      decision: e.decision,
      outcome: e.outcome,
      approver: e.approver ?? '',
      reason: e.reason ?? '',
      policy_version: e.policyVersion,
      enforced: e.enforced ?? true,
      prev_hash: e.prevHash,
      hash: e.hash,
    }));
    if (lastHash) {
      const idx = events.findIndex((e) => e.hash === lastHash);
      if (idx === -1) {
        // 游标不在本地链中：从链首重推（服务端按 prev_hash 连续性校验，重复会 409）
        // 保守策略：仍从链首推，服务端已有数据时以 409 反馈，由用户决定重置游标
        events = events;
      } else {
        events = events.slice(idx + 1);
      }
    }
    if (events.length > 0) out.push({ server, events });
  }
  return out;
}

export async function pushBatch(
  cfg: { api_url: string; sync_token: string },
  server: string,
  events: Array<Record<string, unknown>>,
): Promise<{ synced: number }> {
  const url = `${cfg.api_url}/api/v1/sync/events`;
  const resp = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Sync-Token': cfg.sync_token },
    body: JSON.stringify({ events }),
  });
  if (resp.status === 409) {
    const body = (await resp.json().catch(() => ({}))) as { detail?: string };
    throw new Error(`服务端拒绝（哈希链断裂，server=${server}）：${body.detail ?? '409'}`);
  }
  if (!resp.ok) {
    const body = (await resp.json().catch(() => ({}))) as { detail?: string };
    throw new Error(`同步失败 HTTP ${resp.status}：${body.detail ?? ''}`);
  }
  const data = (await resp.json()) as { synced: number };
  return { synced: data.synced };
}

export interface PulledPolicy {
  id: number;
  name: string;
  agent_id: number | null;
  policy_json: string;
  version: string;
}

export interface PullPoliciesResult {
  agent_id: number;
  policies: Array<PulledPolicy & { path: string }>;
}

/**
 * 拉取云端策略（本 agent 绑定 + 租户模板），写入 ~/.pod/policies/。
 * 返回清单；调用方负责提示 pod serve --policy 加载。
 */
export async function pullPolicies(opts: {
  config?: string;
  apiUrl?: string;
  agentId?: number;
  syncToken?: string;
  outDir: string;
}): Promise<PullPoliciesResult> {
  const needFile = opts.config !== undefined || !(opts.apiUrl && opts.agentId && opts.syncToken);
  const loaded = needFile ? loadCloudConfig(opts.config) : ({} as CloudConfig);
  // agents 数组格式：按 agentId（或首条）解析出扁平 token，否则直接取扁平字段
  let syncToken = opts.syncToken;
  let agentId = opts.agentId;
  if (!syncToken && loaded.agents && loaded.agents.length > 0) {
    const target = loaded.agents.find((b) => b.agent_id === agentId) ?? loaded.agents[0];
    if (target) {
      syncToken = target.sync_token;
      agentId = target.agent_id;
    }
  }
  const cfg = {
    api_url: (opts.apiUrl ?? loaded.api_url ?? '').replace(/\/+$/, ''),
    agent_id: agentId,
    sync_token: syncToken,
  } as CloudConfig;

  const url = `${cfg.api_url}/api/v1/sync/policies`;
  const resp = await fetch(url, { headers: { 'X-Sync-Token': cfg.sync_token ?? '' } });
  if (!resp.ok) {
    const body = (await resp.json().catch(() => ({}))) as { detail?: string };
    throw new Error(`拉取策略失败 HTTP ${resp.status}：${body.detail ?? ''}`);
  }
  const data = (await resp.json()) as { agent_id: number; policies: PulledPolicy[] };

  mkdirSync(opts.outDir, { recursive: true });
  const out: PullPoliciesResult['policies'] = [];
  for (const p of data.policies) {
    // 校验云端策略是合法 JSON
    JSON.parse(p.policy_json);
    const safeName = p.name.replace(/[^a-zA-Z0-9_-]/g, '-');
    const path = join(opts.outDir, `${p.id}-${safeName}.json`);
    writeFileSync(path, p.policy_json.endsWith('\n') ? p.policy_json : p.policy_json + '\n', 'utf8');
    out.push({ ...p, path });
  }
  return { agent_id: data.agent_id, policies: out };
}

/** 执行一次同步；返回各 server 推送统计。 */
export async function runSync(opts: {
  config?: string;
  auditDir: string;
  apiUrl?: string;
  agentId?: number;
  syncToken?: string;
}): Promise<SyncResult> {
  // 三个字段全部显式提供时无需 cloud.json；否则必须能从文件读到
  const needFile = opts.config !== undefined || !(opts.apiUrl && opts.agentId && opts.syncToken);
  const cfg = {
    ...(needFile ? loadCloudConfig(opts.config) : {}),
    ...(opts.apiUrl ? { api_url: opts.apiUrl } : {}),
    ...(opts.agentId ? { agent_id: opts.agentId } : {}),
    ...(opts.syncToken ? { sync_token: opts.syncToken } : {}),
  } as CloudConfig;

  // 多 agent：每个 binding 用独立游标与令牌推送；旧格式视为单个 '*' binding
  const bindings: CloudAgentBinding[] = cfg.agents ?? [
    { local_agent: '*', agent_id: cfg.agent_id!, sync_token: cfg.sync_token! },
  ];

  const servers: SyncResult['servers'] = [];
  const perBinding: Array<{ agent_id: number; synced: number }> = [];
  let total = 0;
  for (const b of bindings) {
    const cursor = loadSyncState(b.agent_id);
    const pending = collectPendingEvents(opts.auditDir, cursor, b.local_agent);
    const newCursor = { ...cursor };
    let boundTotal = 0;
    for (const { server, events } of pending) {
      let synced = 0;
      for (let i = 0; i < events.length; i += 500) {
        const batch = events.slice(i, i + 500);
        const res = await pushBatch(
          { api_url: cfg.api_url, sync_token: b.sync_token },
          server,
          batch,
        );
        synced += res.synced;
      }
      newCursor[server] = events[events.length - 1]!.hash as string;
      total += synced;
      boundTotal += synced;
      servers.push({ server, synced, skipped: 0 });
    }
    saveSyncState(b.agent_id, newCursor);
    perBinding.push({ agent_id: b.agent_id, synced: boundTotal });
  }
  return { agent_id: bindings[0]!.agent_id, servers, total_synced: total, bindings: perBinding };
}
