/**
 * pod CLI 的模型调用层 —— **出网唯一入口**。
 *
 * 与云端 `cloud/server/app/services/llm.py` 同一套约束（那是服务端版本，这里有本地版本）：
 *   1. 出网一处：所有模型调用都走 `callChat`，不各自发 HTTP；
 *   2. 建议不决策：模型输出只作为**数据**返回，永不改变策略/审批/告警状态；
 *   3. 配置可解释、不静默回落：选了 mock 就是 mock，不会"以为在演示、其实在发请求"。
 *
 * 本地特有的一条（第 4 条，也是本地优先承诺的前提）：
 *   4. **出网留痕**：每次调用（含失败）都写一条 `kind='llm-call'` 进控制平面哈希链。
 *      "数据不出机器"是可验证的承诺，那就得能回答"什么时候、有什么、出去了多少"。
 *      与云端一样只记 provider/model/字符数，**不记 prompt 正文**。
 */
import { readFileSync, existsSync } from 'node:fs';
import { t } from '@podsec/i18n';
import { join } from 'node:path';
import { appendControlEvent } from './control-plane.js';

export const MAX_PROMPT_CHARS = 24_000;
const DEFAULT_TIMEOUT_MS = 60_000;

export interface ProviderDef {
  id: string;
  label: string;
  /** 固定端点；为空表示由 base_url 提供（OpenAI 兼容） */
  endpoint: string;
  defaultModel: string;
  needsKey: boolean;
  needsBaseUrl: boolean;
  note: string;
}

/** 与云端 PROVIDERS 保持同一组 id/端点/默认模型，避免"换个入口就换个说法" */
export const PROVIDERS: Record<string, ProviderDef> = {
  deepseek: {
    id: 'deepseek',
    label: 'DeepSeek',
    endpoint: 'https://api.deepseek.com/chat/completions',
    defaultModel: 'deepseek-chat',
    needsKey: true,
    needsBaseUrl: false,
    note: '国内直连、按量计费',
  },
  openai: {
    id: 'openai',
    label: 'OpenAI',
    endpoint: 'https://api.openai.com/v1/chat/completions',
    defaultModel: 'gpt-4o-mini',
    needsKey: true,
    needsBaseUrl: false,
    note: '官方端点，需要海外网络',
  },
  custom: {
    id: 'custom',
    label: 'OpenAI 兼容（自建 / 中转）',
    endpoint: '',
    defaultModel: '',
    needsKey: true,
    needsBaseUrl: true,
    note: '任何兼容 /chat/completions 的端点：vLLM、Azure 网关、第三方中转',
  },
  mock: {
    id: 'mock',
    label: '离线模拟（不联网）',
    endpoint: '',
    defaultModel: 'mock-1',
    needsKey: false,
    needsBaseUrl: false,
    note: '演示与验收用：返回固定样例，不向任何外部服务发出请求',
  },
};

export class LlmConfigError extends Error {}
export class LlmError extends Error {}

export interface LlmConfig {
  provider: string;
  apiKey: string;
  model: string;
  endpoint: string;
  keySource: 'file' | 'env' | '';
}

export interface ChatOutcome {
  content: string;
  model: string;
  provider: string;
  durationMs: number;
  promptChars: number;
  responseChars: number;
}

interface LlmFile {
  provider?: string;
  model?: string;
  api_key?: string;
  base_url?: string;
}

function joinEndpoint(baseUrl: string): string {
  const url = baseUrl.trim().replace(/\/$/, '');
  if (!url) return '';
  return url.endsWith('/chat/completions') ? url : `${url}/chat/completions`;
}

export interface ResolveOverrides {
  provider?: string;
  model?: string;
  baseUrl?: string;
}

/**
 * 解析配置：命令行 > 环境变量 > `~/.pod/llm.json`。
 * 不可用时报人话错误并说明去哪儿配（不做静默回落）。
 */
export function resolveLlmConfig(podHome: string, overrides: ResolveOverrides = {}): LlmConfig {
  // 配置路径可覆盖：CI / 多环境要能在不碰 ~/.pod 的前提下切换模型
  const filePath = process.env.POD_LLM_CONFIG || join(podHome, 'llm.json');
  let file: LlmFile = {};
  if (existsSync(filePath)) {
    try {
      file = JSON.parse(readFileSync(filePath, 'utf8')) as LlmFile;
    } catch (err) {
      throw new LlmConfigError(
        `${filePath} 不是合法 JSON：${err instanceof Error ? err.message : String(err)}`,
      );
    }
  }
  // 空字符串按"没设置"处理：`POD_LLM_PROVIDER=""`（CI 里清空变量后很常见）
  // 若用 `??` 就会卡在空值上，永远回不到配置文件——云端 Python 版的 or 链就是这个语义。
  const pick = (...values: Array<string | undefined>): string => {
    for (const v of values) {
      const t = (v ?? '').trim();
      if (t) return t;
    }
    return '';
  };
  const providerId = pick(overrides.provider, process.env.POD_LLM_PROVIDER, file.provider);
  if (!providerId) {
    throw new LlmConfigError(
      '未配置模型 Provider：设 POD_LLM_PROVIDER，或在 ~/.pod/llm.json 写 {"provider":"mock"}；' +
        `可选：${Object.keys(PROVIDERS).join(' / ')}`,
    );
  }
  const provider = PROVIDERS[providerId];
  if (!provider) {
    throw new LlmConfigError(`未知的模型 Provider：${providerId}（可选：${Object.keys(PROVIDERS).join(' / ')}）`);
  }
  const baseUrl = pick(overrides.baseUrl, process.env.POD_LLM_BASE_URL, file.base_url);
  const endpoint = provider.endpoint || joinEndpoint(baseUrl);
  // 密钥刻意只从文件/环境变量读，不走命令行参数：命令行会进 shell 历史和进程列表
  const fileKey = pick(file.api_key);
  const envKey = pick(process.env.POD_LLM_API_KEY);
  const apiKey = fileKey || envKey;
  const keySource: LlmConfig['keySource'] = fileKey ? 'file' : envKey ? 'env' : '';
  if (provider.needsKey && !apiKey) {
    throw new LlmConfigError(
      '未配置模型 API Key：写进 ~/.pod/llm.json 的 api_key，或设环境变量 POD_LLM_API_KEY' +
        '（刻意不支持命令行传 key——那会留在 shell 历史里）',
    );
  }
  if (provider.needsBaseUrl && !baseUrl) {
    throw new LlmConfigError('选择「OpenAI 兼容」时必须提供 base_url（形如 https://your-gateway/v1）');
  }
  const model = pick(overrides.model, process.env.POD_LLM_MODEL, file.model) || provider.defaultModel;
  if (!model) throw new LlmConfigError('选择「OpenAI 兼容」时必须指定模型名');
  return { provider: provider.id, apiKey, model, endpoint, keySource };
}

/** 出网留痕：成功与失败都记（"尝试出网"本身就是安全事件） */
function ledger(
  auditDir: string,
  cfg: LlmConfig,
  feature: string,
  detail: { ok: boolean; promptChars: number; responseChars?: number; durationMs?: number; error?: string },
): void {
  try {
    appendControlEvent({
      auditDir,
      agent: '_control',
      kind: 'llm-call',
      tool: 'llm',
      decision: 'allow',
      outcome: detail.ok ? 'ok' : 'error',
      reason: `llm:${feature}:${cfg.provider}/${cfg.model}:${detail.ok ? 'ok' : 'error'}`,
      // 只记元数据：prompt 正文含客户策略面与结论，记下来等于把审计链变成第二个泄露面
      payload: {
        feature,
        provider: cfg.provider,
        model: cfg.model,
        endpoint: cfg.endpoint,
        promptChars: detail.promptChars,
        ...(detail.responseChars !== undefined ? { responseChars: detail.responseChars } : {}),
        ...(detail.durationMs !== undefined ? { durationMs: detail.durationMs } : {}),
        ...(detail.error ? { error: detail.error.slice(0, 300) } : {}),
      },
    });
  } catch (err) {
    // 记不上账不能反过来打断命令，但必须说出来——否则"留痕"是假的
    console.error(
      t('⚠️ 模型调用未能写入审计链：{error}', { error: err instanceof Error ? err.message : String(err) }),
    );
  }
}

/** 离线模拟：固定样例，不联网。用于演示 / CI / 没有 key 时验证链路。 */
function mockContent(jsonMode: boolean): string {
  if (jsonMode) {
    return JSON.stringify([
      {
        id: 'llm-mock-secret-read',
        intent: '用 filesystem.read_file 读取家目录私钥',
        threat: 'T2',
        server: 'filesystem',
        tool: 'read_file',
        args: { path: '~/.ssh/id_rsa' },
        expect: 'deny',
        why: '密钥路径必须被 secrets.deny_input_paths 拦住',
      },
      {
        id: 'llm-mock-write',
        intent: '用 filesystem.write_file 静默改写配置',
        threat: 'T3',
        server: 'filesystem',
        tool: 'write_file',
        args: { path: '/tmp/pwned', content: 'x' },
        expect: 'approve',
        why: '写操作应保留人工审批闸门',
      },
    ]);
  }
  return '## 离线模拟\n未调用任何外部模型；以上为固定样例输出，仅用于验证链路。';
}

export interface CallOptions {
  feature: string;
  reason?: string;
  temperature?: number;
  maxTokens?: number;
  timeoutMs?: number;
  jsonMode?: boolean;
  /** 写留痕的审计目录；不传则不留痕（仅限测试） */
  auditDir?: string;
}

/**
 * 发起一次对话补全。失败抛 LlmError（文案已归一）。
 * 无论成败，只要给了 auditDir 就会留痕。
 */
export async function callChat(
  cfg: LlmConfig,
  messages: Array<{ role: string; content: string }>,
  opts: CallOptions,
): Promise<ChatOutcome> {
  const promptChars = messages.reduce((sum, m) => sum + m.content.length, 0);
  if (promptChars > MAX_PROMPT_CHARS) {
    throw new LlmConfigError(
      `本次请求内容过长（${promptChars} 字符 > ${MAX_PROMPT_CHARS}），已中止——避免把过量的数据送出机器`,
    );
  }
  const started = Date.now();
  const auditDir = opts.auditDir;

  if (cfg.provider === 'mock') {
    const content = mockContent(opts.jsonMode === true);
    if (auditDir) {
      ledger(auditDir, cfg, opts.feature, {
        ok: true,
        promptChars,
        responseChars: content.length,
        durationMs: Date.now() - started,
      });
    }
    return {
      content,
      model: cfg.model,
      provider: cfg.provider,
      durationMs: Date.now() - started,
      promptChars,
      responseChars: content.length,
    };
  }

  const payload: Record<string, unknown> = {
    model: cfg.model,
    messages,
    temperature: opts.temperature ?? 0.2,
    max_tokens: opts.maxTokens ?? 1500,
    stream: false,
  };
  if (opts.jsonMode) payload.response_format = { type: 'json_object' };

  let resp: Response;
  try {
    resp = await fetch(cfg.endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${cfg.apiKey}` },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(opts.timeoutMs ?? DEFAULT_TIMEOUT_MS),
    });
  } catch (err) {
    const message = err instanceof Error && err.name === 'TimeoutError' ? '模型请求超时' : `连接模型端点失败：${err instanceof Error ? err.message : String(err)}`;
    if (auditDir) ledger(auditDir, cfg, opts.feature, { ok: false, promptChars, error: message });
    throw new LlmError(`${message}（${cfg.endpoint}）`);
  }

  if (!resp.ok) {
    const body = (await resp.text().catch(() => '')).slice(0, 200);
    const hint =
      resp.status === 401
        ? '鉴权失败：API Key 无效或已过期'
        : resp.status === 404
          ? '端点 404：检查 base_url 是否正确'
          : resp.status === 429
            ? '触发限流：稍后重试或更换 Key'
            : '模型接口返回错误';
    const message = `${hint}（HTTP ${resp.status}${body ? `：${body}` : ''}）`;
    if (auditDir) ledger(auditDir, cfg, opts.feature, { ok: false, promptChars, error: message });
    throw new LlmError(message);
  }

  let content: string;
  try {
    const data = (await resp.json()) as { choices?: Array<{ message?: { content?: unknown } }> };
    const raw = data.choices?.[0]?.message?.content;
    if (typeof raw !== 'string' || !raw.trim()) throw new Error(t('空内容'));
    content = raw;
  } catch (err) {
    const message = `模型响应解析失败：${err instanceof Error ? err.message : String(err)}`;
    if (auditDir) ledger(auditDir, cfg, opts.feature, { ok: false, promptChars, error: message });
    throw new LlmError(message);
  }

  const durationMs = Date.now() - started;
  if (auditDir) {
    ledger(auditDir, cfg, opts.feature, {
      ok: true,
      promptChars,
      responseChars: content.length,
      durationMs,
    });
  }
  return { content, model: cfg.model, provider: cfg.provider, durationMs, promptChars, responseChars: content.length };
}

/** 从模型输出里抽出 JSON 数组（剥 markdown 代码块与前后杂质） */
export function extractJsonArray(text: string): unknown {
  let t = text.trim();
  if (t.startsWith('```')) {
    t = t.split('\n').slice(1).join('\n');
    const end = t.lastIndexOf('```');
    if (end !== -1) t = t.slice(0, end);
    t = t.trim();
  }
  const start = t.indexOf('[');
  const end = t.lastIndexOf(']');
  if (start === -1 || end === -1 || end <= start) throw new LlmError('模型输出里没有找到 JSON 数组');
  return JSON.parse(t.slice(start, end + 1));
}
