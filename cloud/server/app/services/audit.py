"""审计与用量记录(统一入口,业务路由调用)。"""

import hashlib
import json

from sqlalchemy.orm import Session

from app.models import AuditLog


def record_audit(db: Session, tenant_id: int, user_id: int, action: str, detail: dict | None = None) -> None:
    """只 add + flush,不 commit —— 事务由调用方路由统一提交(I8)。"""
    db.add(AuditLog(tenant_id=tenant_id, user_id=user_id, action=action, detail_json=json.dumps(detail or {}, ensure_ascii=False)))
    db.flush()



def _clip(text, n: int) -> str:
    return str(text or "")[:n]


def _sha256(text) -> str:
    return hashlib.sha256(str(text or "").encode("utf-8", errors="replace")).hexdigest()


def record_flow_run(
    db: Session,
    tenant_id: int,
    user_id: int,
    *,
    flow_id: str,
    flow_name: str = "",
    entry: str = "chat",
    status: str = "ok",
    input_text: str = "",
    output_text: str = "",
    error: str | None = None,
    approval_id: int | None = None,
    conversation_id: int | None = None,
    session_id: str | None = None,
    tool_calls: list | None = None,
    duration_ms: int | None = None,
    extra: dict | None = None,
) -> None:
    """流程级审计快照(action=flow_run):每次 Fluvia/Langflow 流程运行一条。

    用途(企业尽调可验证的流程可审计性):
    - flow_id / flow_name / entry:跑了哪条流程、从哪个入口进来
      (entry ∈ chat | approval | agent_tool | schedule)
    - status / error:运行结果(成功或失败原因)
    - input / output:截断预览;全量内容留在 conversation_messages / 审批记录,
      审计表不落全量业务数据(敏感数据最小化)
    - output_sha256:输出指纹;事后校验输出是否被改动
    - tool_calls:触发本次运行的本地工具调用 [{name, args_summary}]
    - approval_id / conversation_id / session_id:审批链路与会话关联

    只 add + flush,不 commit —— 事务由调用方统一提交(与 record_audit 一致)。
    """
    detail = {
        "flow_id": str(flow_id or ""),
        "flow_name": _clip(flow_name, 128),
        "entry": entry,
        "status": status,
        "input": _clip(input_text, 1000),
        "output": _clip(output_text, 2000),
        "output_sha256": _sha256(output_text),
        "error": _clip(error, 1000),
        "approval_id": approval_id,
        "conversation_id": conversation_id,
        "session_id": session_id,
        "tool_calls": (tool_calls or [])[:10],
        "duration_ms": duration_ms,
    }
    if extra:
        detail.update(extra)
    db.add(AuditLog(
        tenant_id=tenant_id,
        user_id=user_id,
        action="flow_run",
        detail_json=json.dumps(detail, ensure_ascii=False),
    ))
    db.flush()
