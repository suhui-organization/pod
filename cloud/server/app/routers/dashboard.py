"""Pod Cloud：仪表盘聚合（跨 agent 审计视图，商业计划「实时行为监控」）。

v0 提供租户级摘要：agent 数、审计事件数、决策分布、近 7 天趋势。
"""

from datetime import datetime, timedelta

from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import (
    Agent,
    PodAgentAsset,
    PodAgentFinding,
    PodControlEvent,
    Subscription,
    SyncEvent,
)
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

    # ---- ② 资产 / ③ 发现：这台租户下所有机器上报了什么 ----
    # 为什么放在 dashboard：podcloud 的职责是"展示机器干的活"，
    # 而"还有几个 server 绕过网关、扫出多少 high"才是运维每天要看的东西。
    asset_servers = (
        db.query(PodAgentAsset)
        .filter(PodAgentAsset.tenant_id == tenant_id, PodAgentAsset.kind == "server")
        .all()
    )
    asset_harnesses = (
        db.query(PodAgentAsset)
        .filter(PodAgentAsset.tenant_id == tenant_id, PodAgentAsset.kind == "harness")
        .all()
    )
    coverage_out = {
        "servers": len(asset_servers),
        "unmanaged": sum(1 for r in asset_servers if not r.behind_gateway),
        "harnesses": len(asset_harnesses),
        "harnesses_managed": sum(1 for r in asset_harnesses if r.managed),
        "agents_with_unmanaged": len({r.agent_id for r in asset_servers if not r.behind_gateway}),
    }

    finding_rows = (
        db.query(PodAgentFinding).filter(PodAgentFinding.tenant_id == tenant_id).all()
    )
    sev_rank = {"high": 0, "medium": 1, "low": 2}
    agg: dict[tuple[str, str, str], int] = {}
    findings_totals = {"high": 0, "medium": 0, "low": 0}
    for row in finding_rows:
        agg[(row.source, row.key, row.severity)] = agg.get((row.source, row.key, row.severity), 0) + row.count
        if row.severity in findings_totals:
            findings_totals[row.severity] += row.count
    findings_top = [
        {"source": s, "key": k, "severity": sev, "count": n}
        for (s, k, sev), n in sorted(
            agg.items(), key=lambda kv: (sev_rank.get(kv[0][2], 9), -kv[1])
        )[:10]
    ]
    findings_reported_agents = len({r.agent_id for r in finding_rows})

    # 近 7 天按天聚合。**按事件发生时间 ts 分组，不是按上传时间 synced_at**：
    # 离线几天的机器补传时，synced_at 会把历史事件全堆在"今天"，看图会以为今天爆发。
    # 入库延迟另有 hourly_24h（按 synced_at）可以看。
    since = datetime.utcnow() - timedelta(days=7)
    rows = (
        db.query(func.date(SyncEvent.ts), func.count(SyncEvent.id))
        .filter(
            SyncEvent.tenant_id == tenant_id,
            SyncEvent.synced_at >= since,
            func.date(SyncEvent.ts).isnot(None),
        )
        .group_by(func.date(SyncEvent.ts))
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
        # ---- ② 资产 / ③ 发现（机器上报，云端只聚合展示）----
        "assets": coverage_out,
        "findings": {
            "totals": findings_totals,
            "top": findings_top,
            "reported_agents": findings_reported_agents,
        },
    }
