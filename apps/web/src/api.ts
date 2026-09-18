/**
 * 数据访问：只读。token 从 URL 取一次后放进 sessionStorage，
 * 并把 URL 里的 token 抹掉（避免留在浏览器历史 / 截图 / Referer）。
 */
import type { AgentAssetsPayload, HarnessCandidate } from '@podsec/console/types';
import type { TakeoverPlan, TakeoverResult, TakeoverRevertResult } from '@podsec/console/types';
import type { EnforcePlan, EnforceResult } from '@podsec/console/types';

const TOKEN_KEY = 'pod.console.token';

export function captureTokenFromUrl(): void {
  const url = new URL(window.location.href);
  const token = url.searchParams.get('token');
  if (!token) return;
  try {
    window.sessionStorage.setItem(TOKEN_KEY, token);
  } catch {
    // 隐私模式下 sessionStorage 可能不可用：仍保留当前 URL 的 token 供本次会话使用
    return;
  }
  url.searchParams.delete('token');
  window.history.replaceState({}, '', `${url.pathname}${url.search}${url.hash}`);
}

function currentToken(): string | null {
  const fromUrl = new URL(window.location.href).searchParams.get('token');
  if (fromUrl) return fromUrl;
  try {
    return window.sessionStorage.getItem(TOKEN_KEY);
  } catch {
    return null;
  }
}

export class ConsoleApiError extends Error {
  readonly status: number;
  constructor(message: string, status: number) {
    super(message);
    this.name = 'ConsoleApiError';
    this.status = status;
  }
}

async function request(path: string, init?: RequestInit): Promise<unknown> {
  const token = currentToken();
  let response: Response;
  try {
    response = await fetch(path, {
      ...init,
      headers: {
        ...(init?.headers ?? {}),
        ...(token ? { 'x-pod-token': token } : {}),
      },
      cache: 'no-store',
    });
  } catch (err) {
    throw new ConsoleApiError(
      `无法连接本地服务：${err instanceof Error ? err.message : String(err)}`,
      0,
    );
  }
  if (!response.ok) {
    let detail = `HTTP ${response.status}`;
    try {
      const body = (await response.json()) as { error?: string };
      if (body.error) detail = body.error;
    } catch {
      // 保持默认文案
    }
    throw new ConsoleApiError(detail, response.status);
  }
  return response.json();
}

async function getJson(path: string): Promise<unknown> {
  return request(path);
}

/**
 * 写请求。**必须**带 `Content-Type: application/json`：控制台服务端用它做
 * CSRF 防线的一部分（跨站表单发不出这个类型），去掉这一行按钮就会 415。
 */
async function postJson(path: string, body: unknown): Promise<unknown> {
  return request(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
}

/** 实时数据：由 `pod ui` 的 /api/agents 提供 */
export async function fetchAgents(): Promise<AgentAssetsPayload> {
  return (await getJson('/api/agents')) as AgentAssetsPayload;
}

/** 示例数据：随前端一起发布，用于没有真实语料时预览界面 */
export async function fetchSample(): Promise<AgentAssetsPayload> {
  const response = await fetch('/fixtures/agents.json', { cache: 'no-store' });
  if (!response.ok) {
    throw new ConsoleApiError(`示例数据不可用（HTTP ${response.status}）`, response.status);
  }
  return (await response.json()) as AgentAssetsPayload;
}

// ---------- 本机 harness 扫描与纳管（写操作） ----------

export interface HarnessScanPayload {
  generatedAt: string;
  podHome: string;
  harnesses: HarnessCandidate[];
  capabilities: { writes: boolean };
}

export interface EnrollResult {
  agent: string;
  harness: string;
  alreadyManaged: boolean;
  changed: { identity: boolean; policy: boolean; auditDir: boolean };
  identityFingerprint: string | null;
  policyFile: string | null;
  notes: string[];
  nextSteps: string[];
}

export interface ForgetResult {
  agent: string;
  found: boolean;
  removed: { policy: boolean; identity: boolean };
  notes: string[];
}

/**
 * 扫描本机装了哪些 harness。
 *
 * 只读，所以走 GET：它是幂等的，重复点不会改变任何状态——按钮的"扫描"语义
 * 由前端表达，不需要用 POST 假装它是一次变更。
 */
export async function scanHarnesses(): Promise<HarnessScanPayload> {
  return (await getJson('/api/harnesses')) as HarnessScanPayload;
}

/** 纳管：建身份 + 零权限策略 + 审计目录 + 入链（服务端唯一写路径） */
export async function enrollHarness(input: {
  harness: string;
  agent: string;
}): Promise<{ result: EnrollResult; payload: AgentAssetsPayload }> {
  return (await postJson('/api/agents/enroll', input)) as {
    result: EnrollResult;
    payload: AgentAssetsPayload;
  };
}

/** 移除纳管：删掉纳管时创建的策略；身份默认保留 */
export async function forgetHarness(input: {
  agent: string;
  purgeIdentity?: boolean;
}): Promise<{ result: ForgetResult; payload: AgentAssetsPayload }> {
  return (await postJson('/api/agents/forget', input)) as {
    result: ForgetResult;
    payload: AgentAssetsPayload;
  };
}

/**
 * 接管计划：把"改前 / 改后 / 备份路径"摊开给用户看。
 *
 * 只读（只解析配置），所以走 GET；按钮点开确认框时取一次。
 */
export async function fetchTakeoverPlan(
  harness: string,
  agent?: string,
): Promise<{ plan: TakeoverPlan; writes: boolean }> {
  const query = new URLSearchParams({ harness });
  if (agent) query.set('agent', agent);
  return (await getJson(`/api/agents/takeover-plan?${query.toString()}`)) as {
    plan: TakeoverPlan;
    writes: boolean;
  };
}

/** 执行接管：备份 + 改写 harness 配置 + 写包装策略（会动用户的配置文件） */
export async function applyTakeover(input: {
  harness: string;
  agent?: string;
}): Promise<{ result: TakeoverResult; payload: AgentAssetsPayload }> {
  return (await postJson('/api/agents/takeover', input)) as {
    result: TakeoverResult;
    payload: AgentAssetsPayload;
  };
}

/** 还原接管：从最近的备份恢复被改写的配置 */
export async function revertTakeover(input: {
  agent: string;
}): Promise<{ result: TakeoverRevertResult; payload: AgentAssetsPayload }> {
  return (await postJson('/api/agents/revert', input)) as {
    result: TakeoverRevertResult;
    payload: AgentAssetsPayload;
  };
}

export type EnforcementMode = 'record-only' | 'enforce';

/**
 * 切执法 / 回到只录不拦的计划（只读）。
 *
 * 计划里带着前置检查的结果：没有可执行的策略时返回 blockedReason，
 * 前端把它原样显示出来——包括"先跑哪条命令"。这比一个灰按钮有用。
 */
export async function fetchEnforcePlan(
  harness: string,
  mode: EnforcementMode,
  agent?: string,
): Promise<{ plan: EnforcePlan; writes: boolean }> {
  const query = new URLSearchParams({ harness, mode });
  if (agent) query.set('agent', agent);
  return (await getJson(`/api/agents/enforce-plan?${query.toString()}`)) as {
    plan: EnforcePlan;
    writes: boolean;
  };
}

/** 执行模式切换：只动包装命令里的 --record-only / --policy */
export async function applyEnforcement(input: {
  harness: string;
  mode: EnforcementMode;
  agent?: string;
}): Promise<{ result: EnforceResult; payload: AgentAssetsPayload }> {
  return (await postJson('/api/agents/enforce', input)) as {
    result: EnforceResult;
    payload: AgentAssetsPayload;
  };
}
