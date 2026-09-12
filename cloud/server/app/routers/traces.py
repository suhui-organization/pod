"""Pod Cloud：调用链追踪（大模块）。

把散落的审计事件重组成「任务 → 工具调用链」的关系图谱数据：
- 任务 = 某 agent 连续活动的一段(相邻调用间隔 > SESSION_GAP_MIN 分钟切新任务)，
  任务源头即图中根节点；
- 每个调用 = 图中的一个节点，携带该点处理的内容线索：
  tool/server/decision/outcome/approver/reason/policy_version/args_hash(隐私最小化,
  只存哈希，UI 展示哈希而非明文参数);
- 按用户区分: 返回租户成员列表; 事件归属当前为租户内注册/管理员账号
  (agent 尚未绑定具体成员,归属账号 = 首个 admin,后续可加 agent-user 绑定)。

前端据此用关系图谱(echarts graph)渲染: 任务根 → 调用序列边。
"""

import os
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Agent, SyncEvent, TenantUser, User
from app.security import get_current_tenant_id

router = APIRouter(prefix="/traces", tags=["traces"])

SESSION_GAP_MIN = int(os.environ.get("PODCLOUD_TRACE_GAP_MIN", "15"))
DEFAULT_WINDOW_MIN = 24 * 60


def _event_time(ev: SyncEvent) -> datetime:
    """调用链时间口径：优先审计事件真实发生时间 ts，缺失/非法时退回同步时间 synced_at。

    历史 bug：此前用 synced_at 聚类与计时，导致一次同步推送的整批事件
    被算成同一时刻（任务耗时 0 秒、间隔 0 秒），且回填旧审计时时间错位。
    """
    if ev.ts:
        try:
            return datetime.fromisoformat(ev.ts.replace("Z", "+00:00")).replace(tzinfo=None)
        except (ValueError, TypeError):
            pass
    return ev.synced_at or datetime.utcnow()


@router.get("")
def list_traces(
    db: Session = Depends(get_db),
    tenant_id: int = Depends(get_current_tenant_id),
    minutes: int = DEFAULT_WINDOW_MIN,
    user_id: int | None = None,
    agent_id: int | None = None,
    task_limit: int = 40,
    calls_limit: int = 200,
):
    # ── 租户成员(按用户区分的筛选来源) ────────────────────────────────
    members = (
        db.query(TenantUser, User)
        .join(User, User.id == TenantUser.user_id)
        .filter(TenantUser.tenant_id == tenant_id)
        .order_by(TenantUser.id)
        .all()
    )
    users = [
        {
            "id": u.id,
            "email": u.email,
            "full_name": u.full_name,
            "role": tu.role,
        }
        for tu, u in members
    ]
    owner = next((u for tu, u in members if tu.role == "admin"), None) or (members[0][1] if members else None)

    agents = {
        a.id: a
        for a in db.query(Agent).filter(Agent.tenant_id == tenant_id).all()
    }

    since = datetime.utcnow() - timedelta(minutes=minutes)
    # ts 是 ISO-8601 UTC 字符串，字典序即时间序；窗口按"调用真实发生时间"过滤
    since_iso = since.isoformat(timespec="seconds")
    q = (
        db.query(SyncEvent)
        .filter(
            SyncEvent.tenant_id == tenant_id,
            SyncEvent.ts >= since_iso,
        )
        .order_by(SyncEvent.agent_id, SyncEvent.ts, SyncEvent.id)
    )
    if agent_id is not None:
        q = q.filter(SyncEvent.agent_id == agent_id)
    rows = q.all()

    # ── 会话聚类: 同 agent 相邻调用间隔超过 gap 即切新任务 ─────────────
    sessions: list[list[SyncEvent]] = []
    cur: list[SyncEvent] | None = None
    prev: SyncEvent | None = None
    for ev in rows:
        if cur is None or ev.agent_id != prev.agent_id:  # type: ignore[union-attr]
            cur = [ev]
            sessions.append(cur)
        else:
            t_ev = _event_time(ev)
            t_prev = _event_time(prev)  # type: ignore[arg-type]
            if (t_ev - t_prev).total_seconds() / 60 > SESSION_GAP_MIN:
                cur = [ev]
                sessions.append(cur)
            else:
                cur.append(ev)
        prev = ev

    tasks = []
    for sess in sessions:
        if not sess:
            continue
        a = agents.get(sess[0].agent_id)
        if a is None:
            continue
        t0 = _event_time(sess[0])
        t1 = _event_time(sess[-1])
        # 节点间隔(距上一调用)与任务耗时统计
        times = [_event_time(e) for e in sess]
        gaps = [(times[i] - times[i - 1]).total_seconds() for i in range(1, len(times))]
        duration_seconds = max(0, int((t1 - t0).total_seconds()))
        calls = [
            {
                "id": e.id,
                "seq": e.seq,
                "ts": e.ts,
                "tool": e.tool,
                "server": e.server,
                "decision": e.decision,
                "outcome": e.outcome,
                "approver": e.approver or "",
                "reason": e.reason or "",
                "args_hash": e.args_hash,
                "policy_version": e.policy_version or "",
                "inter_gap_seconds": int(gaps[i - 1]) if i > 0 else None,
            }
            for i, e in enumerate(sess[:calls_limit])
        ]
        decisions: dict[str, int] = {}
        for e in sess:
            decisions[e.decision] = decisions.get(e.decision, 0) + 1
        tasks.append(
            {
                "id": f"{sess[0].agent_id}-{t0.isoformat(timespec='seconds')}",
                "agent_id": sess[0].agent_id,
                "agent": a.name,
                "platform": a.platform,
                "owner_id": owner.id if owner else None,
                "owner_name": owner.full_name or owner.email if owner else "",
                "owner_email": owner.email if owner else "",
                "started_at": t0.isoformat(timespec="seconds") + "Z",
                "ended_at": t1.isoformat(timespec="seconds") + "Z",
                "duration_seconds": duration_seconds,
                "avg_gap_seconds": round(sum(gaps) / len(gaps)) if gaps else 0,
                "max_gap_seconds": round(max(gaps)) if gaps else 0,
                "call_count": len(sess),
                "decisions": decisions,
                "calls": calls,
            }
        )

    tasks.sort(key=lambda t: t["started_at"], reverse=True)
    if user_id is not None:
        tasks = [t for t in tasks if t["owner_id"] == user_id]
    tasks = tasks[:task_limit]

    return {"gap_minutes": SESSION_GAP_MIN, "users": users, "tasks": tasks}
