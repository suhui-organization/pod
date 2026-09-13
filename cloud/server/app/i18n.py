"""服务端 i18n：把"服务端生成、给人看"的文本按请求语言输出。

设计取舍
--------
1. **中文原文即词条键**（与前端同一套约定）：`t("邮箱已注册", locale)`。
   好处是路由里继续写中文，可读性不降；没翻译的字符串原样输出中文，
   不会变成 key 名或空白，所以可以逐处补齐。

2. **只在统一异常处理里翻译一次**，不改 60+ 个 `raise HTTPException(detail=...)`。
   路由保持原样，出口收口——这也是这个项目一贯的做法（网关、审计、同步
   都是在出口统一处理）。

3. **不翻译入库的审计/告警原文**。那些文本是本机 `pod` 生成后同步上来的
   证据，原文进过哈希链；按语言改写展示会篡改证据（详见 docs/threat-model.md
   的 T7）。它们在界面上保持原样，需要翻译应该在**产生端**（CLI）做。

4. 语言来源：`Accept-Language` 请求头（前端 axios 会带上当前界面语言），
   其次 `?lang=` 查询参数，最后回落到 zh-CN。
"""

from __future__ import annotations

from typing import Any
import re

SUPPORTED_LOCALES = ("zh-CN", "en-US")
DEFAULT_LOCALE = "zh-CN"


def resolve_locale(accept_language: str | None, query_lang: str | None = None) -> str:
    """从 Accept-Language / ?lang= 里选出我们支持的语言。

    只做最小可用解析：取第一个带 q 值的语言标签，按前缀匹配。
    不做权重排序——界面只有中英两种，排序带来的复杂度不值当。
    """
    raw = (query_lang or accept_language or "").strip()
    if not raw:
        return DEFAULT_LOCALE
    first = raw.split(",")[0].split(";")[0].strip().lower()
    if first.startswith("en"):
        return "en-US"
    if first.startswith("zh"):
        return "zh-CN"
    # 不认识的语言：英文优先（开源项目面向英文用户），但只对显式声明了语言的请求生效
    return "en-US" if first else DEFAULT_LOCALE


# 英文词表：key = 中文原文。占位符用 {name}，与 str.format 一致。
EN: dict[str, str] = {
    # ── 认证 / 账号 ──
    "邮箱已注册": "This email is already registered",
    "邮箱或密码错误": "Wrong email or password",
    "账号已停用": "This account has been disabled",
    "账号未关联任何租户": "This account is not linked to any tenant",
    "用户不存在": "User not found",
    "当前密码不正确": "Current password is incorrect",
    "私有化实例不开放 Web 自助注册": "Self-service sign-up is disabled on this instance",
    "重置链接无效或已过期,请重新申请": "This reset link is invalid or expired — request a new one",
    "缺少登录凭证": "Missing credentials",
    "登录凭证无效或已过期": "Your session is invalid or expired — sign in again",

    # ── AI 模型配置（设置页）──────────────────────────────────────────────
    # 为什么这几条要单独列：provider 清单与"哪些功能依赖模型"是**结构化 payload**，
    # 不走 translate_detail（那只处理异常 detail），字段必须自己过词表。
    "未配置模型 API Key：在「设置 → AI 模型」里填写，或为服务进程设置环境变量 PODCLOUD_LLM_API_KEY":
        "No model API key configured: fill it in under Settings → AI model, or set PODCLOUD_LLM_API_KEY for the server process",
    "离线模拟（不联网）": "Offline mock (no network)",
    "演示与验收用：返回固定样例，不向任何外部服务发出请求":
        "For demos and acceptance runs: returns fixed samples and never calls any external service",
    "选择「OpenAI 兼容」时必须填写 Base URL（形如 https://your-gateway/v1）":
        "Base URL is required when you pick “OpenAI-compatible” (e.g. https://your-gateway/v1)",
    "AI 生成策略": "Generate policy with AI",
    "策略中心": "Policies",
    "按钮保留但提示先配置模型；策略的保存/应用不受影响，仍可手写 JSON":
        "The button stays but asks you to configure a model first; saving and applying policies is unaffected — you can still hand-write the JSON",
    "AI 告警摘要": "AI alert summary",
    "告警页": "Alerts",
    "摘要不可用；告警列表、状态与处置按钮全部照常":
        "Summaries are unavailable; the alert list, statuses and action buttons all keep working",
    "AI 日报": "AI daily digest",
    "设置 · AI 日报": "Settings · AI digest",
    "无告警时只推一句「无告警」文本，有告警时跳过本次推送":
        "With no alerts it sends a single “no alerts” line; with alerts it skips that push",
    # ── 成员 / 租户 ──
    "仅租户管理员可管理成员": "Only tenant admins can manage members",
    "成员不存在": "Member not found",
    "只有管理员可以执行该操作": "Only admins can perform this action",
    # ── agent ──
    "agent 不存在": "Agent not found",
    "当前计划最多 {limit} 个 agent（已用 {cnt}）；升级计划后再注册":
        "Your plan allows up to {limit} agents (currently {cnt}); upgrade to add more",
    "sync token 无效": "Invalid sync token",
    "缺少 X-Sync-Token": "Missing X-Sync-Token",
    # ── 同步 ──
    "同一批次不能混合数据平面与控制平面事件（每批应来自同一个审计文件）":
        "A batch cannot mix data-plane and control-plane events (each batch must come from one audit file)",
    "哈希链断裂：期望 prev_hash={expected}…，收到 {actual}…（seq={seq}）":
        "Hash chain broken: expected prev_hash={expected}…, got {actual}… (seq={seq})",
    # ── 策略 ──
    "策略不存在": "Policy not found",
    "未知模板: {template}": "Unknown template: {template}",
    # ── 告警 ──
    "告警不存在": "Alert not found",
    "state 需为 {states} 之一": "state must be one of {states}",
    "AI 摘要生成失败: {error}": "AI summary failed: {error}",
    "日报生成失败: {error}": "Digest generation failed: {error}",
    # ── 计费 ──
    "本部署未启用计费（自托管模式）：所有功能可用且不限 agent 数，无需订阅":
        "Billing is disabled on this deployment (self-hosted): every feature is available, agents are unlimited, and no subscription is needed",
    "支付通道未开通：请联系我们开通后升级（当前套餐能力不受影响）":
        "The payment channel is not enabled: contact us to upgrade (your current capabilities are unaffected)",
    "支付平台暂时不可用，请稍后重试": "The payment provider is temporarily unavailable — try again later",
    # ── 通用 ──
    "参数校验失败": "Request validation failed",
    "服务器内部错误": "Internal server error",
    # ── 模型供应商（设置页展示）──
    "OpenAI 兼容（自建 / 中转）": "OpenAI-compatible (self-hosted / proxy)",
    "国内直连、按量计费；默认模型 deepseek-chat":
        "Direct from mainland China, pay-as-you-go; default model deepseek-chat",
    "官方端点，需要海外网络；默认模型 gpt-4o-mini":
        "Official endpoint, requires overseas network access; default model gpt-4o-mini",
    "任何兼容 /chat/completions 的端点：自建 vLLM、Azure 网关、第三方中转":
        "Any endpoint compatible with /chat/completions: self-hosted vLLM, Azure gateway, third-party proxy",
    # ── 接入脚本（用户终端直接看到）──
    "本地审计里只有「%s」，已自动把绑定名从「%s」对齐到它。":
        "Only “%s” exists in the local audit trail — the binding name was aligned from “%s”.",
    "⚠️  绑定名「%s」在本机审计里找不到，这些事件不会被同步。":
        "⚠️  Binding name “%s” was not found in the local audit trail; those events will not sync.",
    "   本机审计里现有的 agent：%s": "   Agents present in the local audit trail: %s",
    "   解决：用对应的名字重跑一次这条命令，例如":
        "   Fix: re-run this command with the matching name, for example",
    "本地还没有审计数据（pod serve 跑起来之后才会有），先绑定名称「%s」。":
        "No local audit data yet (it appears once pod serve runs) — binding the name “%s” for now.",
    "已清理 %d 条失效绑定(%s)：它们的 token 已不被服务端承认。":
        "Removed %d stale bindings (%s): the server no longer accepts their tokens.",
    "  这些是删过或换过库的 agent 残留；不清掉会让每次 pod sync 直接中止。":
        "  These are leftovers from deleted or rebuilt agents; leaving them makes every pod sync abort.",
    "已写入": "Wrote",
    "✅ 已接入：agent #${AID}（__NAME__）在线，云端现有 ${EVENTS} 条审计。":
        "✅ Connected: agent #${AID} (__NAME__) is online; the cloud now holds ${EVENTS} audit entries.",
    "❌ 未接入：这个 sync token 属于 agent #${GOT}，不是本次要接入的 #${AID}。":
        "❌ Not connected: this sync token belongs to agent #${GOT}, not #${AID}.",
    "❌ 未接入：服务端拒绝了这个 sync token（401）。":
        "❌ Not connected: the server rejected this sync token (401).",
    "❌ 未接入：连不上 ${API}":
        "❌ Not connected: cannot reach ${API}",
    "❌ 未接入：服务端返回 HTTP ${CODE}（配置已写好，稍后可重跑 pod sync）":
        "❌ Not connected: the server returned HTTP ${CODE} (config is written; re-run pod sync later)",
}


def t(message: str, locale: str = DEFAULT_LOCALE, **kwargs: Any) -> str:
    """翻译一条服务端文案。

    - locale 不是 en-US 时直接返回原文（中文原文即结果）
    - 词表里没有时返回原文（未翻译不等于错误）
    - 占位符用 kwargs 填充；原文有占位符但调用方没给时，退回原文而不是抛错
      （错误文案本身不该因为格式化失败再制造一个错误）
    """
    if locale != "en-US":
        return message
    template = EN.get(message)
    if template is None:
        return message
    if not kwargs:
        return template
    try:
        return template.format(**kwargs)
    except (KeyError, IndexError):
        return template


# 带动态数值的文案：路由已经在 f-string 里插好了值，这里按模式认领后重排。
# 只覆盖少数几条——把它当成"例外清单"，而不是鼓励把文案写散。
_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(r"^当前计划最多 (\d+) 个 agent（已用 (\d+)）"),
        "Your plan allows up to {0} agents (currently {1}); upgrade to add more",
    ),
    (
        re.compile(r"^哈希链断裂：期望 prev_hash=(\S+)…，收到 (\S+)…（seq=(\d+)）"),
        "Hash chain broken: expected prev_hash={0}…, got {1}… (seq={2})",
    ),
    (re.compile(r"^未知模板: (.+)$"), "Unknown template: {0}"),
    (re.compile(r"^state 需为 (.+) 之一$"), "state must be one of {0}"),
    (re.compile(r"^AI 摘要生成失败: (.+)$"), "AI summary failed: {0}"),
    (re.compile(r"^日报生成失败: (.+)$"), "Digest generation failed: {0}"),
    (re.compile(r"^只有管理员可以执行该操作$"), "Only admins can perform this action"),
    (
        re.compile(r"^未知 Provider：(\S+)（可选 (.+)）$"),
        "Unknown provider: {0} (choose one of {1})",
    ),
]


def t_dynamic(message: str, locale: str) -> str:
    """先精确匹配词表，再按模式匹配带数值的文案；都不中则原样返回。"""
    if locale != "en-US":
        return message
    if message in EN:
        return EN[message]
    for pattern, template in _PATTERNS:
        m = pattern.match(message)
        if m:
            return template.format(*m.groups())
    return message


def translate_detail(detail: Any, locale: str) -> Any:
    """翻译 HTTPException 的 detail。

    detail 可能是字符串（我们自己的文案），也可能是 list/dict（FastAPI 的
    结构化校验详情）。只动字符串；结构化的原样返回，避免破坏调用方契约。
    """
    if isinstance(detail, str):
        return t_dynamic(detail, locale)
    return detail
