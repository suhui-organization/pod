"""控制平面事件 API：与 /timeline（数据平面：agent 做了什么）并列的第二视图。"""

# 回答的问题是"agent 的运行环境被谁改过"——本地 pod 的 pod posture /
# pod quarantine / pod delegate 等命令产生的事件，经 pod sync 上云后在这里聚合。
# 敏感内容与数据平面一致：只存哈希（args_hash），原文不出本地。

from datetime import datetime, timedelta

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Agent, PodControlEvent
from app.security import get_current_tenant_id

router = APIRouter(prefix="/control-events", tags=["control-events"])

# 展示用严重级别的推导口径（服务端不存 severity：pod 侧事件只带 kind/decision）。
# 响应里带 severity_source=derived，前端据此提示"级别是推导的"，不假装是原始事实。
_HIGH_RISK_KINDS = {"quarantine", "delegation", "identity", "grant"}
_MEDIUM_RISK_KINDS = {"hook", "config-change", "memory", "package"}


def derive_severity(kind: str, decision: str, outcome: str) -> str:
    # 阻断类（deny / outcome=blocked）与熔断、委托越权、身份变更 → high；
    # 钩子、配置漂移、记忆、包来源 → medium；其余（metadata/anomaly）→ low。
    if decision == "deny" or outcome == "blocked" or kind in _HIGH_RISK_KINDS:
        return "high"
    if kind in _MEDIUM_RISK_KINDS:
        return "medium"
    return "low"


@router.get("")
def list_control_events(
    limit: int = 100,
    minutes: int = 0,
    kind: str | None = None,
    agent_id: int | None = None,
    db: Session = Depends(get_db),
    tenant_id: int = Depends(get_current_tenant_id),
):
    # 租户级控制平面事件（新→旧）。minutes=0 表示全部。
    q = (
        db.query(PodControlEvent, Agent.name)
        .join(Agent, PodControlEvent.agent_id == Agent.id)
        .filter(PodControlEvent.tenant_id == tenant_id)
    )
    if minutes > 0:
        since = datetime.utcnow() - timedelta(minutes=minutes)
        q = q.filter(PodControlEvent.synced_at >= since)
    if kind:
        q = q.filter(PodControlEvent.kind == kind)
    if agent_id:
        q = q.filter(PodControlEvent.agent_id == agent_id)
    rows = (
        q.order_by(PodControlEvent.ts.desc(), PodControlEvent.id.desc())
        .limit(min(max(limit, 1), 1000))
        .all()
    )
    return {
        "events": [
            {
                "id": ev.id,
                "agent": name,
                "agent_id": ev.agent_id,
                "kind": ev.kind,
                "category": ev.category or "",
                "severity": derive_severity(ev.kind, ev.decision, ev.outcome),
                "ts": ev.ts,
                "seq": ev.seq,
                "decision": ev.decision,
                "outcome": ev.outcome or "",
                "reason": ev.reason or "",
                "args_hash": ev.args_hash,
                "chain": ev.chain,
                "prev_hash": ev.prev_hash,
                "hash": ev.hash,
            }
            for ev, name in rows
        ],
        "severity_source": "derived",
    }


@router.get("/summary")
def control_event_summary(
    minutes: int = 0,
    db: Session = Depends(get_db),
    tenant_id: int = Depends(get_current_tenant_id),
):
    # 按 kind / severity 聚合计数（展示用）。minutes=0 表示全部。
    q = db.query(PodControlEvent).filter(PodControlEvent.tenant_id == tenant_id)
    if minutes > 0:
        since = datetime.utcnow() - timedelta(minutes=minutes)
        q = q.filter(PodControlEvent.synced_at >= since)
    rows = q.all()
    by_kind: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    for ev in rows:
        by_kind[ev.kind] = by_kind.get(ev.kind, 0) + 1
        sev = derive_severity(ev.kind, ev.decision, ev.outcome)
        by_severity[sev] = by_severity.get(sev, 0) + 1
    return {"total": len(rows), "by_kind": by_kind, "by_severity": by_severity}
