/**
 * 数据访问：只读。token 从 URL 取一次后放进 sessionStorage，
 * 并把 URL 里的 token 抹掉（避免留在浏览器历史 / 截图 / Referer）。
 */
import type { AgentAssetsPayload } from '@podsec/console/types';

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

async function getJson(path: string): Promise<unknown> {
  const token = currentToken();
  let response: Response;
  try {
    response = await fetch(path, {
      headers: token ? { 'x-pod-token': token } : undefined,
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
