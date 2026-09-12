"""Pod Cloud：AI 功能层（prompt + 输出解析），发送统一走 `services/llm.py`。

分工：
- `llm.py` 管**怎么调**——provider/端点/key 解析、超时、错误语义、出网裁剪、调用留痕；
- 本文件管**调什么**——提示词、上下文压缩、把模型输出解析成结构化结果。

铁律：LLM 输出只作为"建议"返回展示，永不改变策略/审批/告警状态；
调用失败只返回错误，不影响主流程。
"""

import json
import logging
from typing import Any

from app.services import llm

logger = logging.getLogger("podcloud.ai_summary")


SYSTEM_PROMPT = (
    "你是 AI Agent 安全舱（Pod Cloud）的安全分析师。用户会给你一批最近的告警记录"
    "（Agent 的工具行为被策略拦截/批准的审计信号）。请输出一份中文分析摘要："
    "① 总体情况（告警数量、涉及 Agent、主要类型）；"
    "② 关键发现（最高危的 1-3 件事，说明为什么值得关注）；"
    "③ 建议行动（按优先级列出可执行的排查/处置建议）。"
    "要求：基于给定数据，不要编造未出现的事实；简洁，总长度不超过 400 字；"
    "用 markdown 输出（## 开头的小节）。"
)


def build_context(alerts: list[dict]) -> str:
    """把告警列表压成紧凑文本（近 24h，最多 50 条）。

    字段裁剪在 `llm.shape_alert`——那是决定"什么数据可以出网"的地方。
    """
    lines = []
    for a in alerts[:50]:
        item = llm.shape_alert(a)
        ts = str(item.get("ts") or "")[:16]
        lines.append(
            f"- [{ts}] agent={item.get('agent')} {item.get('severity')} "
            f"{item.get('kind')}: {item.get('message')}"
        )
    return "近 24h 告警记录：\n" + "\n".join(lines) if lines else "近 24h 无告警记录。"


def summarize(
    cfg: llm.LlmConfig,
    alerts: list[dict],
    *,
    db: Any = None,
    tenant_id: int | None = None,
    user_id: int | None = None,
    feature: str = "alerts.summary",
) -> dict:
    """调用 LLM 生成告警摘要。返回 {summary, model}；失败抛 llm.LlmError 由调用方转 502。"""
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": build_context(alerts)},
    ]
    try:
        outcome = llm.call_chat(
            cfg, messages, feature=feature, temperature=0.3, max_tokens=800, timeout=40.0
        )
    except Exception as e:  # noqa: BLE001 失败也要留痕（出网尝试本身是安全事件）
        if db is not None and tenant_id is not None:
            llm.record_call(db, tenant_id=tenant_id, user_id=user_id, feature=feature, cfg=cfg, error=e)
        raise
    if db is not None and tenant_id is not None:
        llm.record_call(
            db, tenant_id=tenant_id, user_id=user_id, feature=feature, cfg=cfg, outcome=outcome
        )
    return {"summary": outcome.content.strip(), "model": outcome.model}


# ---- 策略自然语言生成（生成辅助 + 人工确认，生成结果不落库） ----

POLICY_SCHEMA_HINT = """策略 JSON 结构（与 pod 网关同构，deny > approve > allow，未授权工具 fail-closed）:
{
  "version": "0.1.0",
  "defaultDecision": "deny",
  "servers": {
    "filesystem": {
      "allow": ["read_file", "list_directory", "search_files"],
      "approve": ["write_file", "edit_file"],
      "deny": ["delete_file"],
      "source": {"command": "mcp-server-filesystem"}
    }
  },
  "secrets": {
    "deny_input_paths": ["~/.ssh", ".env", "credentials", "id_rsa", "id_ed25519", ".aws", ".git-credentials", "known_hosts"],
    "deny_output_matching": ["ghp_[A-Za-z0-9]{36}", "sk-[A-Za-z0-9]{20,}"]
  }
}
工具参考: read_file/list_directory/search_files(读), write_file/edit_file(写), delete_file(删除)"""

POLICY_GEN_SYSTEM = (
    "你是 Pod Cloud（AI Agent 安全舱）的策略生成器。根据用户的中文安全需求，输出一份"
    "pod 网关策略 JSON。要求：① 只输出一个 JSON 对象，不要任何额外文字或 markdown 代码块标记；"
    "② 结构必须符合给定 schema；③ 需求冲突时以更严格的安全为准（fail-closed）；"
    "④ 涉及敏感内容时补全 secrets.deny_input_paths / deny_output_matching；"
    "⑤ 在 JSON 对象末尾附加一个 explanation 字符串字段（非空）：用中文解释这份策略的关键决策——"
    "哪些操作被放行/审批/拒绝及原因、敏感路径如何补全、为什么这样满足用户需求（80-200 字）。"
    "示例结尾：\"explanation\": \"读取放行以便日常开发，写入需审批以留人工判断，删除一律拒绝防止误删；"
    "密钥路径全部拦截防止泄露；生产配置目录同样禁止访问。\"\n\n" + POLICY_SCHEMA_HINT
)


def extract_json(text: str) -> str:
    """从 LLM 输出中提取 JSON 正文（剥 markdown 代码块与前后杂质）。"""
    text = text.strip()
    if text.startswith("```"):
        text = text.split("\n", 1)[-1]
        text = text.rsplit("```", 1)[0].strip()
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        raise ValueError("输出中未找到 JSON 对象")
    return text[start : end + 1]


def generate_policy(
    cfg: llm.LlmConfig,
    description: str,
    *,
    db: Any = None,
    tenant_id: int | None = None,
    user_id: int | None = None,
) -> dict:
    """自然语言 → 策略 JSON（不落库；由调用方交人工确认后保存）。"""
    messages = [
        {"role": "system", "content": POLICY_GEN_SYSTEM},
        {"role": "user", "content": f"请生成策略 JSON。需求：{description}"},
    ]
    feature = "policies.generate"
    try:
        outcome = llm.call_chat(
            cfg,
            messages,
            feature=feature,
            temperature=0.1,
            max_tokens=1500,
            timeout=60.0,
            json_mode=True,
        )
    except Exception as e:  # noqa: BLE001 失败也要留痕（出网尝试本身是安全事件）
        if db is not None and tenant_id is not None:
            llm.record_call(db, tenant_id=tenant_id, user_id=user_id, feature=feature, cfg=cfg, error=e)
        raise
    if db is not None and tenant_id is not None:
        llm.record_call(
            db, tenant_id=tenant_id, user_id=user_id, feature=feature, cfg=cfg, outcome=outcome
        )

    raw = extract_json(outcome.content)
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as e:
        raise llm.LlmError(f"模型输出的 JSON 无法解析：{e}") from e
    if not isinstance(parsed, dict):
        raise llm.LlmError("模型输出不是 JSON 对象")
    # explanation 字段单独提取，不进入策略本体
    explanation = str(parsed.pop("explanation", "") or "").strip()
    policy = parsed
    # 归一：确保必要键存在
    policy.setdefault("version", "0.1.0")
    policy.setdefault("defaultDecision", "deny")
    policy.setdefault("servers", {})
    policy.setdefault("secrets", {"deny_input_paths": [], "deny_output_matching": []})
    return {"policy": policy, "model": outcome.model, "explanation": explanation}
