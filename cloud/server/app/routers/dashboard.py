"""Pod Cloud：仪表盘聚合（跨 agent 审计视图，商业计划「实时行为监控」）。

v0 提供租户级摘要：agent 数、审计事件数、决策分布、近 7 天趋势。
"""

from datetime import datetime, timedelta

from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Agent, PodControlEvent, Subscription, SyncEvent
from app.security import get_current_tenant_id

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/summary")
def dashboard_summary(db: Session = Depends(get_db), tenant_id: int = Depends(get_current_tenant_id)):
    agent_count = db.query(func.count(Agent.id)).filter(Agent.tenant_id == tenant_id).scalar() or 0
    online_count = db.query(func.count(Agent.id)).filter(Agent.tenant_id == tenant_id, Agent.status == "online").scalar() or 0
    event_count = db.query(func.count(SyncEvent.id)).filter(SyncEvent.tenant_id == tenant_id).scalar() or 0

    decisions = dict(
        db.query(SyncEvent.decision, func.count(SyncEvent.id))
        .filter(SyncEvent.tenant_id == tenant_id)
        .group_by(SyncEvent.decision)
        .all()
    )
    outcomes = dict(
        db.query(SyncEvent.outcome, func.count(SyncEvent.id))
        .filter(SyncEvent.tenant_id == tenant_id)
        .group_by(SyncEvent.outcome)
        .all()
    )

    # 近 7 天按天聚合（按同步时间 synced_at）
    since = datetime.utcnow() - timedelta(days=7)
    rows = (
        db.query(func.date(SyncEvent.synced_at), func.count(SyncEvent.id))
        .filter(SyncEvent.tenant_id == tenant_id, SyncEvent.synced_at >= since)
        .group_by(func.date(SyncEvent.synced_at))
        .all()
    )
    trend = [{"date": str(d), "events": n} for d, n in rows]

    # ---- 仪表盘扩展（P2：数据可视化）----
    # 按 server 分布
    by_server = dict(
        db.query(SyncEvent.server, func.count(SyncEvent.id))
        .filter(SyncEvent.tenant_id == tenant_id)
        .group_by(SyncEvent.server)
        .all()
    )
    # 按工具 Top 10
    by_tool = [
        {"tool": t, "events": n}
        for t, n in (
            db.query(SyncEvent.tool, func.count(SyncEvent.id))
            .filter(SyncEvent.tenant_id == tenant_id)
            .group_by(SyncEvent.tool)
            .order_by(func.count(SyncEvent.id).desc())
            .limit(10)
            .all()
        )
    ]
    # 按 Agent 活跃度。两个口径必须都给出，否则这个图会误导人：
    #   - events / control 是**累计**值，只增不减，看起来永远不动；
    #   - events_recent / control_recent 是近 7 天，才是"活跃度"该有的含义。
    # 0 事件的新 agent 也要上榜（左连接语义），避免"统计里少了 agent"。
    # 控制平面事件（钩子/配置/身份/委托...）单独计数：它们是 agent 的活动，
    # 只是发生在另一张表（pod_control_events）。
    agents = db.query(Agent.id, Agent.name).filter(Agent.tenant_id == tenant_id).all()
    since_7d = datetime.utcnow() - timedelta(days=7)

    def count_by_agent(model, extra_filter=None):
        q = db.query(model.agent_id, func.count(model.id)).filter(model.tenant_id == tenant_id)
        if extra_filter is not None:
            q = q.filter(extra_filter)
        return dict(q.group_by(model.agent_id).all())

    tool_all = count_by_agent(SyncEvent)
    tool_recent = count_by_agent(SyncEvent, SyncEvent.synced_at >= since_7d)
    control_all = count_by_agent(PodControlEvent)
    control_recent = count_by_agent(PodControlEvent, PodControlEvent.synced_at >= since_7d)

    per_agent = [
        {
            "agent": name,
            "events": tool_all.get(agent_id, 0),
            "events_recent": tool_recent.get(agent_id, 0),
            "control": control_all.get(agent_id, 0),
            "control_recent": control_recent.get(agent_id, 0),
        }
        for agent_id, name in agents
    ]
    # 活跃度排序：近 7 天有动静的排前面，再按累计量，最后按名字稳定排序
    per_agent.sort(
        key=lambda r: (-(r["events_recent"] + r["control_recent"]), -r["events"], r["agent"])
    )

    # 近 7 天的控制平面事件按 kind 聚合（前端用于说明"这些活动都是什么"）
    control_by_kind = dict(
        db.query(PodControlEvent.kind, func.count(PodControlEvent.id))
        .filter(PodControlEvent.tenant_id == tenant_id, PodControlEvent.synced_at >= since_7d)
        .group_by(PodControlEvent.kind)
        .all()
    )
    control_total = db.query(func.count(PodControlEvent.id)).filter(
        PodControlEvent.tenant_id == tenant_id
    ).scalar() or 0
    # 近 24h 按小时分布
    since_h = datetime.utcnow() - timedelta(hours=24)
    hourly = [
        {"hour": h, "events": n}
        for h, n in (
            db.query(func.strftime("%H", SyncEvent.synced_at), func.count(SyncEvent.id))
            .filter(SyncEvent.tenant_id == tenant_id, SyncEvent.synced_at >= since_h)
            .group_by(func.strftime("%H", SyncEvent.synced_at))
            .all()
        )
    ]
    # 告警统计 + 最近 5 条
    from app.models import PodAlert

    alert_total = db.query(func.count(PodAlert.id)).filter(PodAlert.tenant_id == tenant_id).scalar() or 0
    alert_by_state = dict(
        db.query(PodAlert.state, func.count(PodAlert.id))
        .filter(PodAlert.tenant_id == tenant_id)
        .group_by(PodAlert.state)
        .all()
    )
    open_high = (
        db.query(func.count(PodAlert.id))
        .filter(PodAlert.tenant_id == tenant_id, PodAlert.state == "open", PodAlert.severity == "high")
        .scalar()
        or 0
    )
    alert_by_severity = dict(
        db.query(PodAlert.severity, func.count(PodAlert.id))
        .filter(PodAlert.tenant_id == tenant_id)
        .group_by(PodAlert.severity)
        .all()
    )
    # 告警按 kind 分布（全部时间）
    alert_by_kind = [
        {"kind": k, "count": n}
        for k, n in (
            db.query(PodAlert.kind, func.count(PodAlert.id))
            .filter(PodAlert.tenant_id == tenant_id)
            .group_by(PodAlert.kind)
            .order_by(func.count(PodAlert.id).desc())
            .all()
        )
    ]
    # 近 7 天告警趋势（按天）
    alert_trend_7d = [
        {"date": str(d), "count": n}
        for d, n in (
            db.query(func.date(PodAlert.created_at), func.count(PodAlert.id))
            .filter(PodAlert.tenant_id == tenant_id, PodAlert.created_at >= since)
            .group_by(func.date(PodAlert.created_at))
            .all()
        )
    ]
    alerts_recent = [
        {
            "id": a.id,
            "kind": a.kind,
            "severity": a.severity,
            "message": a.message,
            "created_at": a.created_at.isoformat(),
        }
        for a in (
            db.query(PodAlert)
            .filter(PodAlert.tenant_id == tenant_id)
            .order_by(PodAlert.id.desc())
            .limit(5)
            .all()
        )
    ]

    sub = db.query(Subscription).filter(Subscription.tenant_id == tenant_id).first()
    plan = sub.plan if sub else "free"
    # 计费关闭时显示不限量口径（与 /subscription 一致，避免两处口径打架）
    from app.services.billing import billing_enabled, effective_agent_limit

    agent_limit = effective_agent_limit(sub.agent_limit if sub else 3)

    return {
        "agents": {"total": agent_count, "online": online_count},
        "events": {
            "total": event_count,
            "by_decision": decisions,
            "by_outcome": outcomes,
            "by_server": by_server,
            "by_tool": by_tool,
            "per_agent": per_agent,
            "hourly_24h": hourly,
            "control_total": control_total,
            "control_by_kind_7d": control_by_kind,
        },
        "trend_7d": trend,
        "alerts": {
            "open": alert_by_state.get("open", 0),
            "acknowledged": alert_by_state.get("acknowledged", 0),
            "resolved": alert_by_state.get("resolved", 0),
            "open_high": open_high,
            "by_severity": alert_by_severity,
            "by_kind": alert_by_kind,
            "trend_7d": alert_trend_7d,
        },
        "alerts_recent": alerts_recent,
        "plan": plan,
        "agent_limit": agent_limit,
    }
