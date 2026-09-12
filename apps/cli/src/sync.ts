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
import { dirname, join } from 'node:path';
import { AuditLog } from '@podsec/audit';
import type { Policy } from '@podsec/policy';
import { verifyPolicy } from './policy-sign.js';
import { t } from '@podsec/i18n';
import { quarantineAdd, quarantineRemove, readQuarantineFile } from './control-plane.js';

export interface CloudAgentBinding {
  /** 本地审计文件的 agent 字段（"*" = 全部） */
  local_agent: string;
  agent_id: number;
  sync_token: string;
}

export interface CloudConfig {
  api_url: string;
  /** 策略签名公钥（Ed25519 PEM）；配置后 pod pull-policy 会验签 */
  policy_public_key?: string;
  /**
   * 规则包签名公钥（Ed25519 PEM）；`pod rules pull --from-cloud` 用它验签。
   *
   * 为什么必须放在这个文件里、而不是从云端响应里拿：验签的公钥不能和包走同一条通道。
   * 如果公钥也从云端取，中间人换包时把公钥一起换掉，验签就成了摆设。
   * （没配时回落 policy_public_key——同一把签发密钥，通常没必要分开。）
   */
  rules_public_key?: string;
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
  /**
   * 本次失败项（空数组 = 全部成功）。
   *
   * 逐项失败不再中断其余绑定/链：一条死 token 或一条断链不该让整台机器
   * 停止上云。失败的链**不推进游标**，修好后重跑会从原处重试。
   */
  failures: Array<{ agent_id: number; server?: string; message: string }>;
  /**
   * 每个绑定本次从云端收敛的熔断状态。
   *
   * 放在 sync 里而不是单独一条命令：`pod sync` 本来就挂在定时任务上，
   * 熔断下发才谈得上"出事时不用等人 SSH 上去"。默认不配定时任务时它也不会自己跑——
   * 这一点写进了文档，不假装是实时的。
   */
  quarantine: Array<{ agent_id: number } & QuarantineSyncResult>;
}

export function loadCloudConfig(configPath?: string): CloudConfig {
  const path = configPath ?? join(homedir(), '.pod', 'cloud.json');
  if (!existsSync(path)) {
    throw new Error(
      t('未找到云配置 {path}（先 pod cloud-setup 或手工写入 api_url/agent_id/sync_token）', { path }),
    );
  }
  const raw = JSON.parse(readFileSync(path, 'utf8')) as Partial<CloudConfig>;
  if (!raw.api_url) {
    throw new Error(t('云配置 {path} 缺少 api_url', { path }));
  }
  if (raw.agents && raw.agents.length > 0) {
    for (const b of raw.agents) {
      if (!b.local_agent || !b.agent_id || !b.sync_token) {
        throw new Error(t('云配置 {path} 的 agents 条目缺少 local_agent/agent_id/sync_token', { path }));
      }
    }
    return {
      api_url: raw.api_url.replace(/\/+$/, ''),
      agents: raw.agents,
      policy_public_key: raw.policy_public_key,
      rules_public_key: raw.rules_public_key,
    };
  }
  if (!raw.agent_id || !raw.sync_token) {
    throw new Error(t('云配置 {path} 缺少 agent_id/sync_token（或 agents 数组）', { path }));
  }
  return {
    api_url: raw.api_url.replace(/\/+$/, ''),
    agent_id: raw.agent_id,
    sync_token: raw.sync_token,
    policy_public_key: raw.policy_public_key,
    rules_public_key: raw.rules_public_key,
  };
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
      // 事件类型必须转发：服务端据此把控制平面事件（hook/config-change/…）
      // 分流进 pod_control_events。漏掉这个字段不会报错，但控制平面事件会被
      // 当成工具调用落进数据平面表，云端"控制平面"页永远是空的。
      // 历史数据没有该字段，缺省 tool-call。
      kind: e.kind ?? 'tool-call',
      server: e.server,
      tool: e.tool,
      args_hash: e.argsHash,
      decision: e.decision,
      outcome: e.outcome,
      approver: e.approver ?? '',
      reason: e.reason ?? '',
      policy_version: e.policyVersion,
      enforced: e.enforced ?? true,
      snapshot: e.snapshot ?? '',
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
    throw new Error(
      t('服务端拒绝（哈希链断裂，server={server}）：{detail}', { server, detail: body.detail ?? '409' }),
    );
  }
  if (!resp.ok) {
    const body = (await resp.json().catch(() => ({}))) as { detail?: string };
    throw new Error(t('同步失败 HTTP {status}：{detail}', { status: resp.status, detail: body.detail ?? '' }));
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
  signature?: string;
}

export interface PullPoliciesResult {
  agent_id: number;
  policies: Array<PulledPolicy & { path: string; verified: boolean }>;
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
  policyPublicKey?: string;
  requireSignature?: boolean;
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
    throw new Error(t('拉取策略失败 HTTP {status}：{detail}', { status: resp.status, detail: body.detail ?? '' }));
  }
  const data = (await resp.json()) as { agent_id: number; policies: PulledPolicy[] };
  const publicKey = opts.policyPublicKey ?? loaded.policy_public_key;

  mkdirSync(opts.outDir, { recursive: true });
  const out: PullPoliciesResult['policies'] = [];
  for (const p of data.policies) {
    // 校验云端策略是合法 JSON
    const policy = JSON.parse(p.policy_json) as Policy;
    let verified = false;
    if (p.signature) {
      if (publicKey) {
        if (!verifyPolicy(policy, p.signature, publicKey)) {
          throw new Error(t('策略 "{name}" 签名无效（可能被篡改），已拒绝写入', { name: p.name }));
        }
        verified = true;
      } else if (opts.requireSignature) {
          throw new Error(t('策略 "{name}" 带签名但未配置 policy_public_key，无法验签', { name: p.name }));
      }
    } else if (opts.requireSignature) {
      throw new Error(t('策略 "{name}" 缺少签名（--require-signature）', { name: p.name }));
    }
    const safeName = p.name.replace(/[^a-zA-Z0-9_-]/g, '-');
    const path = join(opts.outDir, `${p.id}-${safeName}.json`);
    writeFileSync(path, p.policy_json.endsWith('\n') ? p.policy_json : p.policy_json + '\n', 'utf8');
    out.push({ ...p, path, verified });
  }
  return { agent_id: data.agent_id, policies: out };
}

/** 执行一次同步；返回各 server 推送统计。 */
/** 按 500 条一批推完一条链，返回实际写入条数 */
async function pushAll(
  cfg: { api_url?: string },
  syncToken: string,
  server: string,
  events: Array<Record<string, unknown>>,
): Promise<number> {
  let synced = 0;
  for (let i = 0; i < events.length; i += 500) {
    const res = await pushBatch(
      { api_url: cfg.api_url ?? '', sync_token: syncToken },
      server,
      events.slice(i, i + 500),
    );
    synced += res.synced;
  }
  return synced;
}

/** 云端下发的熔断条目用这个标记来源：同步只清理自己下的，人工下的解不掉 */
export const QUARANTINE_BY_CLOUD = 'cloud';

export interface HardenUploadPayload {
  generated_at: string;
  rules_version: string;
  high: number;
  medium: number;
  low: number;
  mcp_servers: number;
  exposed_secrets: number;
  broken_chains: number;
  /** 报告正文（交付物，已脱敏） */
  report_md: string;
  /** 机器可读发现（交付物，已脱敏；密钥只留掩码） */
  findings_json: string;
}

/**
 * 把 `pod harden` 的交付物上传到云端。
 *
 * **只传交付物**：report.md 与 findings.json 客户本来就要给人看；
 * evidence.json（原始审计链）不传——它是"本地优先"承诺的核心。
 * 调用方负责决定"要不要传"（`pod harden --upload` 是显式动作）。
 */
export async function uploadHardenReport(
  cfg: { api_url: string; sync_token: string },
  payload: HardenUploadPayload,
): Promise<{ id: number }> {
  const resp = await fetch(`${cfg.api_url}/api/v1/harden/reports`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Sync-Token': cfg.sync_token },
    body: JSON.stringify(payload),
  });
  if (!resp.ok) {
    const detail = await resp.text().catch(() => '');
    throw new Error(`上传加固报告失败：HTTP ${resp.status} ${detail.slice(0, 300)}`);
  }
  const body = (await resp.json()) as { report?: { id?: number } };
  return { id: body.report?.id ?? 0 };
}

export interface QuarantineSyncResult {
  /** 云端期望状态；undefined = 没拉到（**不能**当成"未熔断"） */
  desired?: boolean;
  applied: string[];
  released: string[];
  /** 拉取失败：什么都没动。失败是"保持现状"，不是"解除" */
  error?: string;
}

/** 列出本机的本地 agent 名（审计目录的顶层 *.jsonl 与子目录名） */
export function listLocalAgents(auditDir: string): string[] {
  if (!existsSync(auditDir)) return [];
  const out = new Set<string>();
  for (const entry of readdirSync(auditDir)) {
    if (entry.endsWith('.jsonl')) out.add(entry.replace(/\.jsonl$/, ''));
    else if (!entry.startsWith('.')) out.add(entry);
  }
  for (const name of Object.keys(readQuarantineFileSafe(quarantinePathOf(auditDir)))) out.add(name);
  return [...out].sort();
}

/** quarantine.json 的默认位置与审计目录同级（~/.pod/quarantine.json） */
function quarantinePathOf(auditDir: string): string {
  return join(dirname(auditDir), 'quarantine.json');
}

function readQuarantineFileSafe(file: string): Record<string, unknown> {
  try {
    return readQuarantineFile(file).agents;
  } catch {
    return {};
  }
}

/**
 * 把云端期望的熔断状态收敛到本地 `quarantine.json`。
 *
 * 三条安全规则，缺一不可：
 * 1. **拉取失败什么都不做**。网络问题不能等于"解除熔断"——那是 fail-open，
 *    攻击者只要断掉机器的出网就能解除云端下的熔断。
 * 2. **不接管本地条目**。人工在机器上手工加的熔断（by=cli-user）不会被云端覆盖成自己的，
 *    因此也就不会被后续的云端解除顺手删掉。
 * 3. **只解除自己下的**。desired=false 时只清理 by=cloud 的条目。
 *
 * 收敛（而不是执行一次性命令）是因为机器可能离线：期望状态幂等，上线后一次拉取即对齐。
 */
export async function syncQuarantine(opts: {
  api_url: string;
  sync_token: string;
  /** cloud.json 里这条绑定的 local_agent；'*' = 这台机器上的所有本地 agent */
  local_agent: string;
  auditDir: string;
  quarantineFile?: string;
  now?: Date;
}): Promise<QuarantineSyncResult> {
  const file = opts.quarantineFile ?? quarantinePathOf(opts.auditDir);
  let body: { quarantined?: boolean; reason?: string };
  try {
    const resp = await fetch(`${opts.api_url}/api/v1/sync/quarantine`, {
      headers: { 'X-Sync-Token': opts.sync_token },
    });
    if (!resp.ok) {
      return { applied: [], released: [], error: `拉取熔断状态失败：HTTP ${resp.status}` };
    }
    body = (await resp.json()) as typeof body;
  } catch (err) {
    return {
      applied: [],
      released: [],
      error: `拉取熔断状态失败：${err instanceof Error ? err.message : String(err)}（保持本地现状）`,
    };
  }

  const desired = body.quarantined === true;
  const reason = (body.reason ?? '').trim() || '云端下发熔断';
  const state = readQuarantineFile(file);
  const applied: string[] = [];
  const released: string[] = [];

  if (desired) {
    const targets = opts.local_agent === '*' ? listLocalAgents(opts.auditDir) : [opts.local_agent];
    for (const agent of targets) {
      // 规则 2：已经有人（人工或其他来源）下了熔断就不动它，避免接管所有权
      if (state.agents[agent]) continue;
      quarantineAdd({ file, agent, reason, by: QUARANTINE_BY_CLOUD, auditDir: opts.auditDir, ...(opts.now ? { now: opts.now } : {}) });
      applied.push(agent);
    }
  } else {
    for (const [agent, entry] of Object.entries(state.agents)) {
      // 规则 3：只解除云端自己下的
      if (entry?.by !== QUARANTINE_BY_CLOUD) continue;
      quarantineRemove({ file, agent, by: QUARANTINE_BY_CLOUD, auditDir: opts.auditDir, ...(opts.now ? { now: opts.now } : {}) });
      released.push(agent);
    }
  }
  return { desired, applied, released };
}

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
  const failures: SyncResult['failures'] = [];
  const quarantine: SyncResult['quarantine'] = [];
  let total = 0;
  for (const b of bindings) {
    const cursor = loadSyncState(b.agent_id);
    const pending = collectPendingEvents(opts.auditDir, cursor, b.local_agent);
    const newCursor = { ...cursor };
    let boundTotal = 0;
    for (const { server, events } of pending) {
      try {
        const synced = await pushAll(cfg, b.sync_token, server, events);
        newCursor[server] = events[events.length - 1]!.hash as string;
        total += synced;
        boundTotal += synced;
        servers.push({ server, synced, skipped: 0 });
      } catch (err: unknown) {
        // 只记这一条链的失败，继续跑其它链。关键：**不推进游标**——
        // 推进了就等于把没传上去的事件永久跳过，而用户以为已经同步过了。
        let message = err instanceof Error ? err.message : String(err);
        // 自愈：409 且本地有这条链的游标，多半是服务端这条链其实是空的——
        // 本机游标指向被重建过的旧库（agent_id 会被复用，游标文件却留在本地），
        // 于是只发了游标之后的事件，服务端从空链开始校验自然对不上。
        // 从链首重推一次：服务端若真有一条不同的链，会照样 409，重推不会损坏任何数据。
        if (message.includes('哈希链断裂') && cursor[server]) {
          const full = collectPendingEvents(opts.auditDir, {}, b.local_agent).find((p) => p.server === server);
          if (full) {
            try {
              const synced = await pushAll(cfg, b.sync_token, server, full.events);
              newCursor[server] = full.events[full.events.length - 1]!.hash as string;
              total += synced;
              boundTotal += synced;
              servers.push({ server, synced, skipped: 0 });
              continue;
            } catch (retryErr: unknown) {
              message += t('；从链首重推仍未通过：{error}', {
                error: retryErr instanceof Error ? retryErr.message : String(retryErr),
              });
            }
          }
        }
        failures.push({ agent_id: b.agent_id, server, message });
      }
    }
    saveSyncState(b.agent_id, newCursor);
    // 心跳:即使 0 条新事件也刷新在线状态(规模化后 agent 在线不依赖新审计)
    // 401 = token 失效(轮换过 / agent 被删过),同样只记这一项,不拖垮其它绑定。
    const ping = await fetch(`${cfg.api_url}/api/v1/sync/ping`, {
      method: 'POST',
      headers: { 'X-Sync-Token': b.sync_token },
    }).catch(() => null);
    if (ping && ping.status === 401) {
      failures.push({ agent_id: b.agent_id, message: t('sync token 无效（HTTP 401）') });
    }
    // 收敛云端下发的熔断：拉取失败时 syncQuarantine 自己保证"什么都不动"
    const q = await syncQuarantine({
      api_url: cfg.api_url ?? '',
      sync_token: b.sync_token,
      local_agent: b.local_agent,
      auditDir: opts.auditDir,
    });
    quarantine.push({ agent_id: b.agent_id, ...q });
    // 刻意**不算作同步失败**：老版本服务端没有 /sync/quarantine 这个端点，
    // 把它算进 failures 会让新客户端对着旧服务端每次都退出码 1。
    // 拉取失败会保留在 quarantine[] 里，由 CLI 打警告——不静默，也不误报同步失败。
    perBinding.push({ agent_id: b.agent_id, synced: boundTotal });
  }
  return {
    agent_id: bindings[0]!.agent_id,
    servers,
    total_synced: total,
    bindings: perBinding,
    failures,
    quarantine,
  };
}
