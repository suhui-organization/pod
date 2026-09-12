"""Pod Cloud：取证时间线（P1，Agent 黑匣子云端视图）。

按事件时间（ts）排序的跨 Agent 时间线；与本地 pod timeline 同构。
"""

from datetime import datetime, timedelta

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Agent, SyncEvent
from app.security import get_current_tenant_id

router = APIRouter(prefix="/timeline", tags=["timeline"])


@router.get("")
def get_timeline(
    limit: int = 200,
    minutes: int = 0,
    server: str | None = None,
    tool: str | None = None,
    agent_id: int | None = None,
    db: Session = Depends(get_db),
    tenant_id: int = Depends(get_current_tenant_id),
):
    """租户级事件时间线（新→旧），含 Agent 名。minutes=0 表示全部。"""
    q = db.query(SyncEvent, Agent.name).join(Agent, SyncEvent.agent_id == Agent.id).filter(SyncEvent.tenant_id == tenant_id)
    if minutes > 0:
        since = datetime.utcnow() - timedelta(minutes=minutes)
        q = q.filter(SyncEvent.synced_at >= since)
    if server:
        q = q.filter(SyncEvent.server == server)
    if tool:
        q = q.filter(SyncEvent.tool == tool)
    if agent_id:
        q = q.filter(SyncEvent.agent_id == agent_id)
    rows = q.order_by(SyncEvent.ts.desc()).limit(min(max(limit, 1), 1000)).all()
    return {
        "events": [
            {
                "id": ev.id,
                "agent": name,
                "agent_id": ev.agent_id,
                "ts": ev.ts,
                "server": ev.server,
                "tool": ev.tool,
                "args_hash": ev.args_hash,
                "decision": ev.decision,
                "outcome": ev.outcome,
                "approver": ev.approver or "",
                "reason": ev.reason or "",
                "policy_version": ev.policy_version,
                "enforced": ev.enforced,
                "seq": ev.seq,
            }
            for ev, name in rows
        ]
    }
