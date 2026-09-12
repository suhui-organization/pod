"""Pod Cloud：模型调用层（AI 功能的唯一出网点）。

三条约束，改这个文件前先读：

1. **出网一处**：策略生成 / 告警摘要 / AI 日报都走 `call_chat`，不各自发 HTTP。
   分散发请求的下场是超时、错误语义、留痕各自漂移（重构前就是两份复制的 httpx 调用）。
2. **建议不决策**：模型输出只作为"建议"返回展示，永不改变策略 / 审批 / 告警状态；
   调用失败只报错，不影响主流程。
3. **配置可解释**：选了什么 provider、key 从哪来、为什么不可用，都给人话错误，
   **不做静默回落**。历史 bug：`mock` 不在 ENDPOINTS 里，被静默当成 deepseek 发出去，
   报错文案完全指错方向。

配置优先级：租户设置（设置页）→ 环境变量（部署期兜底）→ 报错。
"""

from __future__ import annotations

import json
import logging
import os
from app.i18n import DEFAULT_LOCALE, t
import time
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

import httpx

logger = logging.getLogger("podcloud.llm")

# 超时：模型是最慢的一环，但也不能挂死请求
DEFAULT_TIMEOUT = 60.0
# 单次调用最多带多少字符出去（防止把整库审计塞进 prompt）
MAX_PROMPT_CHARS = 24000


@dataclass(frozen=True)
class Provider:
    """一个可选的模型来源。`needs_base_url` 为真时 endpoint 由租户填写。"""

    id: str
    label: str
    endpoint: str
    default_model: str
    needs_key: bool
    needs_base_url: bool
    note: str


PROVIDERS: dict[str, Provider] = {
    "deepseek": Provider(
        id="deepseek",
        label="DeepSeek",
        endpoint="https://api.deepseek.com/chat/completions",
        default_model="deepseek-chat",
        needs_key=True,
        needs_base_url=False,
        note="国内直连、按量计费；默认模型 deepseek-chat",
    ),
    "openai": Provider(
        id="openai",
        label="OpenAI",
        endpoint="https://api.openai.com/v1/chat/completions",
        default_model="gpt-4o-mini",
        needs_key=True,
        needs_base_url=False,
        note="官方端点，需要海外网络；默认模型 gpt-4o-mini",
    ),
    "custom": Provider(
        id="custom",
        label="OpenAI 兼容（自建 / 中转）",
        endpoint="",
        default_model="",
        needs_key=True,
        needs_base_url=True,
        note="任何兼容 /chat/completions 的端点：自建 vLLM、Azure 网关、第三方中转",
    ),
    "mock": Provider(
        id="mock",
        label="离线模拟（不联网）",
        endpoint="",
        default_model="mock-1",
        needs_key=False,
        needs_base_url=False,
        note="演示与验收用：返回固定样例，不向任何外部服务发出请求",
    ),
}

# 界面上"哪些功能依赖这套配置"——由后端给，避免前端各写一份
AI_FEATURES: list[dict[str, str]] = [
    {
        "id": "policies.generate",
        "name": "AI 生成策略",
        "where": "策略中心",
        "degraded": "按钮保留但提示先配置模型；策略的保存/应用不受影响，仍可手写 JSON",
    },
    {
        "id": "alerts.summary",
        "name": "AI 告警摘要",
        "where": "告警页",
        "degraded": "摘要不可用；告警列表、状态与处置按钮全部照常",
    },
    {
        "id": "alerts.digest",
        "name": "AI 日报",
        "where": "设置 · AI 日报",
        "degraded": "无告警时只推一句「无告警」文本，有告警时跳过本次推送",
    },
]

# 出网字段白名单：每条记录只允许带这些键
OUTBOUND_KEYS: dict[str, tuple[str, ...]] = {
    "alert": ("ts", "agent", "severity", "kind", "message"),
}
# 单条自由文本出网上限（message 是摘要质量的主要来源，也是最可能夹带路径/参数的地方）
MAX_FREETEXT_CHARS = 240


def providers_public(locale: str = DEFAULT_LOCALE) -> list[dict[str, Any]]:
    """给设置页的 Provider 清单（不含任何密钥信息）。

    label/note 是给人看的说明，按请求语言输出；模型 id 与端点保持原样。
    """
    return [
        {
            "id": p.id,
            "label": t(p.label, locale),
            "default_model": p.default_model,
            "needs_key": p.needs_key,
            "needs_base_url": p.needs_base_url,
            "note": t(p.note, locale),
        }
        for p in PROVIDERS.values()
    ]


class LlmConfigError(Exception):
    """配置不可用（没填、填错、缺项）。文案直接给用户看，所以要写成人话。"""


class LlmError(Exception):
    """调用失败（网络、鉴权、限流、响应格式）。"""

    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


@dataclass
class LlmConfig:
    provider: str
    api_key: str
    model: str
    base_url: str
    endpoint: str
    provider_label: str = ""
    key_source: str = ""  # tenant | env

    @property
    def key_hint(self) -> str:
        """给界面用的脱敏提示：不回显 key，只说明来源与尾号。"""
        if not self.api_key:
            return ""
        return f"…{self.api_key[-4:]}" if len(self.api_key) > 8 else "已配置"


@dataclass
class ChatOutcome:
    content: str
    model: str
    provider: str
    duration_ms: int
    prompt_chars: int
    response_chars: int
    usage: dict[str, Any] = field(default_factory=dict)


def _join_endpoint(base_url: str) -> str:
    """把租户填的 base_url 补成 chat/completions 端点。

    容错三种常见写法：`https://x/v1`、`https://x/v1/`、`https://x/v1/chat/completions`。
    """
    url = base_url.strip().rstrip("/")
    if not url:
        return ""
    if url.endswith("/chat/completions"):
        return url
    return f"{url}/chat/completions"


def resolve_config(row: Any = None) -> LlmConfig:
    """解析出一次调用需要的全部配置；不可用时抛 LlmConfigError（文案给用户看）。

    `row` 是租户设置行（可为 None，表示只看环境变量）。
    """
    raw = (getattr(row, "provider", "") or "").strip() or "auto"
    if raw in ("", "auto"):
        raw = (os.environ.get("PODCLOUD_PROVIDER", "") or "").strip() or "auto"
    if raw in ("", "auto"):
        # auto 的语义：配了 key 就按 deepseek 直连（国内默认），不再是"猜一个 provider"
        raw = "deepseek"
    provider = PROVIDERS.get(raw)
    if provider is None:
        options = " / ".join(PROVIDERS)
        raise LlmConfigError(f"未知的模型 Provider：{raw}（可选：{options}）")

    base_url = (getattr(row, "base_url", "") or "").strip() or (
        os.environ.get("PODCLOUD_LLM_BASE_URL", "") or ""
    ).strip()
    endpoint = provider.endpoint or _join_endpoint(base_url)

    api_key = (getattr(row, "api_key", "") or "").strip()
    key_source = "tenant"
    if not api_key:
        api_key = (os.environ.get("PODCLOUD_LLM_API_KEY", "") or "").strip()
        key_source = "env"
    if provider.needs_key and not api_key:
        raise LlmConfigError(
            "未配置模型 API Key：在「设置 → AI 模型」里填写，"
            "或为服务进程设置环境变量 PODCLOUD_LLM_API_KEY"
        )
    if provider.needs_base_url and not base_url:
        raise LlmConfigError(
            "选择「OpenAI 兼容」时必须填写 Base URL（形如 https://your-gateway/v1）"
        )

    model = (getattr(row, "model", "") or "").strip() or (
        os.environ.get("PODCLOUD_LLM_MODEL", "") or ""
    ).strip()
    if not model:
        model = provider.default_model
    if not model:
        raise LlmConfigError("选择「OpenAI 兼容」时必须填写模型名（如 qwen-max / gpt-4o-mini）")

    return LlmConfig(
        provider=provider.id,
        api_key=api_key,
        model=model,
        base_url=base_url,
        endpoint=endpoint,
        provider_label=provider.label,
        key_source=key_source if api_key else "",
    )


def shape_alert(alert: Mapping[str, Any]) -> dict[str, Any]:
    """把一条告警裁剪成"可以出网"的样子。

    这里是**产品决策点**，不是实现细节：带得少，摘要质量差；带得多，数据出网面大。
    当前口径是能跑的安全底线 —— 只留白名单字段，自由文本截断。

    TODO(walden): 这 5–10 行留给你。下面这版有个已知代价：`message` 原样出网，
    而 message 往往夹带文件路径、工具参数、甚至密钥片段（恰恰是它最有信息量）。
    你可以选的几条路：
      · 路径脱敏：把 /Users/xxx/... 之类替换成 <path>，保留结构信息；
      · 只留 kind + severity，丢掉 message（最安全，摘要会变空泛）；
      · 命中密钥模式（参考 policies.SECRET_PATTERNS）的整条丢弃。
    改完请顺手在 tests/test_llm_settings.py 里留一条断言。
    """
    allowed = OUTBOUND_KEYS.get("alert", ())
    shaped: dict[str, Any] = {}
    for key in allowed:
        value = alert.get(key)
        if value is None:
            continue
        if key == "message":
            text = str(value)
            if len(text) > MAX_FREETEXT_CHARS:
                text = text[:MAX_FREETEXT_CHARS] + "…"
            shaped[key] = text
        else:
            shaped[key] = value
    return shaped


def _mock_content(messages: Iterable[dict[str, str]], json_mode: bool) -> str:
    """离线模拟：不联网，返回结构合法的固定样例（演示 / CI 用）。"""
    if json_mode:
        return json.dumps(
            {
                "version": "0.1.0",
                "defaultDecision": "deny",
                "servers": {
                    "filesystem": {
                        "allow": ["read_file", "list_directory"],
                        "approve": ["write_file"],
                        "deny": ["delete_file"],
                    }
                },
                "secrets": {"deny_input_paths": [".env", ".ssh"], "deny_output_matching": []},
                "explanation": "离线模拟输出：读放行、写审批、删除拒绝。未调用任何外部模型。",
            },
            ensure_ascii=False,
        )
    return (
        "## 总体情况\n离线模拟模式：未调用任何外部模型，以下为固定样例输出。\n\n"
        "## 关键发现\n本次调用命中的是 mock provider，仅用于验证链路是否打通。\n\n"
        "## 建议行动\n在「设置 → AI 模型」里换成真实 Provider 后重新生成。"
    )


def call_chat(
    cfg: LlmConfig,
    messages: list[dict[str, str]],
    *,
    feature: str,
    temperature: float = 0.2,
    max_tokens: int = 1000,
    timeout: float = DEFAULT_TIMEOUT,
    json_mode: bool = False,
) -> ChatOutcome:
    """发起一次对话补全。失败抛 LlmError（文案已归一，调用方直接展示）。"""
    prompt_chars = sum(len(m.get("content", "")) for m in messages)
    if prompt_chars > MAX_PROMPT_CHARS:
        raise LlmConfigError(
            f"本次请求内容过长（{prompt_chars} 字符 > {MAX_PROMPT_CHARS}），已中止，避免超量把数据送出"
        )

    started = time.monotonic()
    if cfg.provider == "mock":
        content = _mock_content(messages, json_mode)
        return ChatOutcome(
            content=content,
            model=cfg.model,
            provider=cfg.provider,
            duration_ms=int((time.monotonic() - started) * 1000),
            prompt_chars=prompt_chars,
            response_chars=len(content),
            usage={"mock": True},
        )

    payload: dict[str, Any] = {
        "model": cfg.model,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
        "stream": False,
    }
    if json_mode:
        # 兼容端点未必认 response_format，所以只作为提示，不押注它生效
        payload["response_format"] = {"type": "json_object"}

    try:
        resp = httpx.post(
            cfg.endpoint,
            json=payload,
            headers={"Authorization": f"Bearer {cfg.api_key}", "Content-Type": "application/json"},
            timeout=timeout,
        )
    except httpx.TimeoutException as e:
        raise LlmError(f"模型请求超时（{timeout:.0f}s）：{cfg.endpoint}") from e
    except httpx.HTTPError as e:
        raise LlmError(f"连接模型端点失败：{e}") from e

    duration_ms = int((time.monotonic() - started) * 1000)
    if resp.status_code == 401:
        raise LlmError("模型鉴权失败（401）：API Key 无效或已过期", status_code=401)
    if resp.status_code == 404:
        raise LlmError(
            f"模型端点返回 404：请检查 Base URL 是否正确（当前 {cfg.endpoint}）", status_code=404
        )
    if resp.status_code == 429:
        raise LlmError("模型触发限流（429）：稍后重试或更换 Key", status_code=429)
    if resp.status_code != 200:
        raise LlmError(
            f"模型接口返回 {resp.status_code}：{resp.text[:200]}", status_code=resp.status_code
        )

    try:
        data = resp.json()
        content = data["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError, ValueError) as e:
        raise LlmError(f"模型响应解析失败：{resp.text[:200]}") from e
    if not isinstance(content, str) or not content.strip():
        raise LlmError("模型返回了空内容")

    return ChatOutcome(
        content=content,
        model=str(data.get("model") or cfg.model),
        provider=cfg.provider,
        duration_ms=duration_ms,
        prompt_chars=prompt_chars,
        response_chars=len(content),
        usage=data.get("usage") if isinstance(data.get("usage"), dict) else {},
    )


def record_call(
    db: Any,
    *,
    tenant_id: int,
    user_id: int | None,
    feature: str,
    cfg: LlmConfig,
    outcome: ChatOutcome | None = None,
    error: Exception | None = None,
) -> None:
    """记录一次模型调用（action=llm.call）。

    这是安全产品的**出网留痕**：记谁在什么时候、用哪个模型、发了多少字符、成没成。
    **不记 prompt 与响应正文** —— 那些含租户审计明细，记下来等于把控制台变成第二个泄露面。
    无 user_id（定时任务）时跳过，不写 user_id=0 的假记录。
    """
    if user_id is None:
        return
    from app.services.audit import record_audit

    detail: dict[str, Any] = {
        "feature": feature,
        "provider": cfg.provider,
        "model": cfg.model,
        "endpoint": cfg.endpoint,
        "ok": error is None,
    }
    if outcome is not None:
        detail.update(
            {
                "duration_ms": outcome.duration_ms,
                "prompt_chars": outcome.prompt_chars,
                "response_chars": outcome.response_chars,
            }
        )
        if outcome.usage:
            detail["usage"] = {
                k: v for k, v in outcome.usage.items() if k in ("prompt_tokens", "completion_tokens", "total_tokens")
            }
    if error is not None:
        detail["error"] = str(error)[:300]
    try:
        record_audit(db, tenant_id=tenant_id, user_id=user_id, action="llm.call", detail=detail)
    except Exception as e:  # noqa: BLE001 留痕失败不能反过来打断业务
        logger.warning("记录模型调用失败 tenant=%s feature=%s: %s", tenant_id, feature, e)


def test_connection(cfg: LlmConfig) -> dict[str, Any]:
    """连通性自检：发一个最小请求，回模型 / 耗时 / 真实错误原文。

    没有这个按钮，API Key 输入框就是个不可信的黑盒 —— 用户只能"存下来再看功能好不好使"。
    """
    started = time.monotonic()
    try:
        outcome = call_chat(
            cfg,
            [
                {"role": "system", "content": "你是连通性自检端点，只回复 OK。"},
                {"role": "user", "content": "ping"},
            ],
            feature="settings.llm_test",
            temperature=0.0,
            max_tokens=16,
            timeout=20.0,
        )
    except (LlmError, LlmConfigError) as e:
        return {
            "ok": False,
            "provider": cfg.provider,
            "model": cfg.model,
            "endpoint": cfg.endpoint,
            "latency_ms": int((time.monotonic() - started) * 1000),
            "error": str(e),
            "sample": "",
        }
    return {
        "ok": True,
        "provider": cfg.provider,
        "model": outcome.model,
        "endpoint": cfg.endpoint,
        "latency_ms": outcome.duration_ms,
        "error": "",
        "sample": outcome.content.strip()[:120],
    }
