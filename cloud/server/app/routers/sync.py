"""Pod Cloud：本地网关审计同步端点（pod sync 命令调用）。

- 鉴权：X-Sync-Token 头（服务端存 sha256 哈希，不存明文）
- 完整性：批次内事件按 pod 本地哈希链顺序提交，prev_hash 必须连续，
  断裂即拒绝（409）——云端保留可验证的不可变审计
- 敏感内容：只收哈希（args_hash/output 不传输），隐私最小化
"""

from datetime import datetime

from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import CONTROL_CHAIN, Agent, PodAlert, PodControlEvent, PodPolicy, SyncEvent

router = APIRouter(prefix="/sync", tags=["sync"])


class SyncEventIn(BaseModel):
    seq: int = Field(ge=1)
    ts: str = Field(min_length=1, max_length=64)
    # 事件类型：缺省 tool-call（数据平面，历史客户端不发送该字段）。
    # 其余取值（hook/config-change/memory/package/identity/delegation/grant/
    # quarantine/anomaly/metadata）为控制平面事件，入 pod_control_events。
    kind: str = Field(default="tool-call", max_length=32)
    server: str = Field(min_length=1, max_length=64)
    tool: str = Field(min_length=1, max_length=128)
    args_hash: str = Field(min_length=64, max_length=64)
    decision: str = Field(min_length=1, max_length=16)
    outcome: str = Field(default="", max_length=16)
    approver: str = Field(default="", max_length=64)
    reason: str = Field(default="", max_length=2000)
    policy_version: str = Field(default="", max_length=32)
    enforced: bool = True
    prev_hash: str = Field(default="", max_length=64)
    hash: str = Field(min_length=64, max_length=64)


class SyncBatchRequest(BaseModel):
    events: list[SyncEventIn] = Field(max_length=500)


@router.post("/events")
def sync_events(
    body: SyncBatchRequest,
    db: Session = Depends(get_db),
    x_sync_token: str = Header(default=""),
):
    """推送一批审计事件；校验哈希链连续性后入库。"""
    if not x_sync_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="缺少 X-Sync-Token")
    from hashlib import sha256

    token_hash = sha256(x_sync_token.encode("utf-8")).hexdigest()
    agent = db.query(Agent).filter(Agent.sync_token_hash == token_hash).first()
    if agent is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="sync token 无效")

    # 每个 (agent, 链) 一条独立哈希链（本地每个审计文件一条链）：
    #   - tool-call → pod_sync_events，链键 = server（本地每 server 一个文件）
    #   - 控制平面事件 → pod_control_events，链键 = chain（pod 侧固定 'control'）
    # 一批事件必然来自同一个文件，因此不允许混链，混了就是客户端 bug。
    is_control = bool(body.events) and body.events[0].kind != "tool-call"
    if body.events and any((ev.kind != "tool-call") != is_control for ev in body.events):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="同一批次不能混合数据平面与控制平面事件（每批应来自同一个审计文件）",
        )

    if is_control:
        chain = CONTROL_CHAIN
        last = (
            db.query(PodControlEvent)
            .filter(
                PodControlEvent.agent_id == agent.id,
                PodControlEvent.tenant_id == agent.tenant_id,
                PodControlEvent.chain == chain,
            )
            .order_by(PodControlEvent.id.desc())
            .first()
        )
    else:
        chain = ""
        last = (
            db.query(SyncEvent)
            .filter(
                SyncEvent.agent_id == agent.id,
                SyncEvent.tenant_id == agent.tenant_id,
                SyncEvent.server == (body.events[0].server if body.events else ""),
            )
            .order_by(SyncEvent.id.desc())
            .first()
        )
    expected_prev = last.hash if last else ""
    now = datetime.utcnow()
    for ev in body.events:
        if ev.prev_hash != expected_prev:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"哈希链断裂：期望 prev_hash={expected_prev[:12]}…，收到 {ev.prev_hash[:12]}…（seq={ev.seq}）",
            )
        if is_control:
            db.add(
                PodControlEvent(
                    tenant_id=agent.tenant_id,
                    agent_id=agent.id,
                    chain=chain,
                    kind=ev.kind,
                    category=ev.tool,
                    seq=ev.seq,
                    ts=ev.ts,
                    decision=ev.decision,
                    outcome=ev.outcome,
                    reason=ev.reason,
                    args_hash=ev.args_hash,
                    policy_version=ev.policy_version,
                    prev_hash=ev.prev_hash,
                    hash=ev.hash,
                    synced_at=now,
                )
            )
        else:
            db.add(
                SyncEvent(
                    tenant_id=agent.tenant_id,
                    agent_id=agent.id,
                    seq=ev.seq,
                    ts=ev.ts,
                    server=ev.server,
                    tool=ev.tool,
                    args_hash=ev.args_hash,
                    decision=ev.decision,
                    outcome=ev.outcome,
                    approver=ev.approver,
                    reason=ev.reason,
                    policy_version=ev.policy_version,
                    enforced=ev.enforced,
                    prev_hash=ev.prev_hash,
                    hash=ev.hash,
                    synced_at=now,
                )
            )
        expected_prev = ev.hash
    agent.status = "online"
    agent.last_seen_at = now
    # 告警规则只针对数据平面事件：控制平面事件有自己的 kind，硬套工具调用规则
    # 会按 reason 文本误报（例如"疑似提示注入"这类子串匹配）。
    tool_events = [ev for ev in body.events if ev.kind == "tool-call"]
    new_alerts = _run_alert_rules(db, agent, tool_events) if tool_events else []
    db.commit()
    # 渠道通知（后台线程，仅通知达到阈值的新告警；不阻塞 sync）
    _notify_alerts(db, agent, new_alerts)
    return {"synced": len(body.events), "agent_id": agent.id}


@router.post("/ping")
def sync_ping(db: Session = Depends(get_db), x_sync_token: str = Header(default="")):
    """轻量心跳：即使 0 条新审计也刷新 last_seen/online。

    规模化后 agent 可能长时间无审计事件；在线判定不应依赖“有新事件”，
    而由定时 pod sync（含本心跳）维持，失联才由巡检切 offline。
    """
    if not x_sync_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="缺少 X-Sync-Token")
    from hashlib import sha256

    token_hash = sha256(x_sync_token.encode("utf-8")).hexdigest()
    agent = db.query(Agent).filter(Agent.sync_token_hash == token_hash).first()
    if agent is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="sync token 无效")
    now = datetime.utcnow()
    agent.status = "online"
    agent.last_seen_at = now
    # 带上已有事件数:接入脚本据此把"token 有效"和"真的有审计上云"区分开,
    # 否则用户看到 ✅ 却不知道数据到底进来没有。
    event_count = db.query(SyncEvent).filter(SyncEvent.agent_id == agent.id).count()
    db.commit()
    return {"pong": True, "agent_id": agent.id, "last_seen_at": now.isoformat(), "event_count": event_count}


def _notify_alerts(db: Session, agent: Agent, new_alerts: list) -> None:
    from datetime import datetime

    from app.models import TenantSettings
    from app.services.alert_notify import _severity_ok, load_webhook_cfg, notify_async

    if not new_alerts:
        return
    row = db.query(TenantSettings).filter(TenantSettings.tenant_id == agent.tenant_id).first()
    if row is None:
        return
    cfg = load_webhook_cfg(row.alert_webhook_json)
    if not cfg.get("enabled"):
        return
    min_sev = cfg.get("min_severity", "medium")
    now = datetime.utcnow()
    hits = [
        {"kind": a.kind, "severity": a.severity, "message": a.message, "agent": agent.name,
         "ts": a.created_at.isoformat() if a.created_at else now.isoformat()}
        for a in new_alerts
        if _severity_ok(min_sev, a.severity)
    ]
    if hits:
        notify_async(cfg, hits)
    # 邮件渠道（用户自设 SMTP）
    try:
        import json

        smtp = json.loads(row.alert_smtp_json or "{}")
        if isinstance(smtp, dict) and smtp.get("enabled"):
            from app.services.alert_notify import email_async

            email_async(smtp, hits)
    except json.JSONDecodeError:
        pass


@router.get("/quarantine")
def get_quarantine(db: Session = Depends(get_db), x_sync_token: str = Header(default="")):
    """分发面：机器 `pod sync` 拉取云端期望的熔断状态。

    返回的是**期望状态**而不是一次性命令：命令在机器离线时就永远丢了，
    期望状态是幂等的——离线一周的机器上线后一次拉取就收敛到正确状态。

    解除由机器侧执行，且只清理 `by=cloud` 的条目：人工在机器上手工加的熔断，
    云端（或拿到 token 的人）解不掉——那正是攻击者想要的能力。
    """
    if not x_sync_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="缺少 X-Sync-Token")
    from hashlib import sha256

    token_hash = sha256(x_sync_token.encode("utf-8")).hexdigest()
    agent = db.query(Agent).filter(Agent.sync_token_hash == token_hash).first()
    if agent is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="sync token 无效")
    return {
        "agent_id": agent.id,
        "quarantined": bool(agent.quarantined),
        "reason": agent.quarantine_reason or "",
        "since": agent.quarantined_at.isoformat() if agent.quarantined_at else "",
        "by": agent.quarantined_by or "",
    }


@router.get("/policies")
def get_agent_policies(
    db: Session = Depends(get_db),
    x_sync_token: str = Header(default=""),
):
    """Agent 鉴权拉取策略：本 agent 绑定策略 + 租户模板（agent_id 为空）。"""
    if not x_sync_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="缺少 X-Sync-Token")
    from hashlib import sha256

    token_hash = sha256(x_sync_token.encode("utf-8")).hexdigest()
    agent = db.query(Agent).filter(Agent.sync_token_hash == token_hash).first()
    if agent is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="sync token 无效")

    policies = (
        db.query(PodPolicy)
        .filter(
            PodPolicy.tenant_id == agent.tenant_id,
            or_(PodPolicy.agent_id == agent.id, PodPolicy.agent_id.is_(None)),
        )
        .order_by(PodPolicy.id)
        .all()
    )
    return {
        "agent_id": agent.id,
        "policies": [
            {
                "id": p.id,
                "name": p.name,
                "agent_id": p.agent_id,
                "policy_json": p.policy_json,
                "version": p.version,
                "created_at": p.created_at.isoformat(),
            }
            for p in policies
        ],
    }


# ---- 云端告警规则（与本地 pod alert 引擎同构，P2） ----

# 规则速查：
#   high:   secret_leak / sensitive_path / policy_mismatch / deny_burst / tool_spike
#   medium: injection_suspect / approval_timeout / unregistered_server / agent_silence
#   low:    manual_approval / tool_first_use

BURST_THRESHOLD = 5      # deny_burst: 窗口内 deny 次数
BURST_WINDOW = 60        # 秒
SPIKE_THRESHOLD = 30     # tool_spike: 窗口内总调用次数
SILENCE_HOURS = 24       # agent_silence: 未同步告警阈值（小时）


def _tenant_rules(db: Session, agent: Agent) -> dict:
    """读取租户自定义规则阈值（回落默认常量）。"""
    from app.models import TenantSettings

    row = db.query(TenantSettings).filter(TenantSettings.tenant_id == agent.tenant_id).first()
    rules = {}
    if row and row.alert_rules_json:
        import json

        try:
            parsed = json.loads(row.alert_rules_json)
            if isinstance(parsed, dict):
                rules = parsed
        except json.JSONDecodeError:
            pass
    return rules


def _window_count(db: Session, agent: Agent, now, window: int, **filters) -> int:
    from datetime import timedelta

    q = db.query(SyncEvent).filter(
        SyncEvent.agent_id == agent.id,
        SyncEvent.synced_at >= now - timedelta(seconds=window),
    )
    for k, v in filters.items():
        q = q.filter(getattr(SyncEvent, k) == v)
    return q.count()


def _recent_alert(db: Session, agent: Agent, kind: str, now, window: int) -> bool:
    from datetime import timedelta

    return (
        db.query(PodAlert)
        .filter(
            PodAlert.agent_id == agent.id,
            PodAlert.kind == kind,
            PodAlert.created_at >= now - timedelta(seconds=window),
        )
        .first()
        is not None
    )


def _add_alert(db: Session, agent: Agent, kind: str, severity: str, message: str, seq: int, now) -> None:
    db.add(PodAlert(
        tenant_id=agent.tenant_id, agent_id=agent.id, kind=kind, severity=severity,
        message=message, event_seq=seq, created_at=now,
    ))


def _run_alert_rules(db: Session, agent: Agent, events: list) -> list:
    """事件入库后重算告警规则，返回本批次新增告警（供渠道通知）。"""
    db.flush()  # autoflush=False：先把本批次事件写入事务，窗口计数才能看到
    from datetime import datetime, timedelta

    now = datetime.utcnow()
    new_alerts: list[PodAlert] = []
    seen_first_use: set = set()

    # 租户自定义阈值（回落默认）
    rules = _tenant_rules(db, agent)
    burst_threshold = int(rules.get("deny_burst_threshold", BURST_THRESHOLD))
    burst_window = int(rules.get("burst_window_seconds", BURST_WINDOW))
    spike_threshold = int(rules.get("spike_threshold", SPIKE_THRESHOLD))

    # 窗口计数（含本次批次）
    deny_count = _window_count(db, agent, now, burst_window, decision="deny")
    call_count = _window_count(db, agent, now, burst_window)
    # tool_first_use：本批次前 agent 未见过的工具（全量已知 - 本批次 = 历史已知）
    batch_tools = {e.tool for e in events}
    all_known = {t for (t,) in db.query(SyncEvent.tool).filter(SyncEvent.agent_id == agent.id).distinct()}
    first_use_tools = batch_tools - (all_known - batch_tools)

    for ev in events:
        reason = ev.reason or ""
        kind = None
        severity = "medium"
        message = ""

        if "secret_leak" in reason:
            kind, severity, message = "secret_leak", "high", f"工具输出被密钥拦截（{ev.server}.{ev.tool}）"
        elif "injection_suspect" in reason:
            kind, severity, message = "injection_suspect", "medium", f"检测到疑似提示注入（{ev.server}.{ev.tool}）"
        elif "hits sensitive path" in reason:
            kind, severity, message = "sensitive_path", "high", f"尝试访问敏感路径被拦截（{ev.server}.{ev.tool}）"
        elif "policy is bound to agent" in reason:
            kind, severity, message = "policy_mismatch", "high", f"策略与 agent 不匹配，调用被拒绝（{ev.server}.{ev.tool}）"
        elif "is not registered" in reason:
            kind, severity, message = "unregistered_server", "medium", f"调用了策略未声明的服务器（{ev.server}.{ev.tool}）"
        elif ev.decision == "approve" and "timed out" in reason:
            kind, severity, message = "approval_timeout", "medium", f"审批超时被拒绝（{ev.server}.{ev.tool}）"
        elif ev.decision == "approve" and "requires approval" in reason:
            kind, severity, message = "manual_approval", "low", f"风险操作经人工批准（{ev.server}.{ev.tool}）"

        if kind:
            _add_alert(db, agent, kind, severity, message, ev.seq, now)
            new_alerts.append(PodAlert(kind=kind, severity=severity, message=message))

        # 行为面信号独立判定（与主信号可并存）：agent 首次使用某工具（每工具一条）
        if ev.tool in first_use_tools and ev.tool not in seen_first_use:
            seen_first_use.add(ev.tool)
            _add_alert(db, agent, "tool_first_use", "low",
                       f"agent 首次使用工具（{ev.server}.{ev.tool}）", ev.seq, now)
            new_alerts.append(PodAlert(kind="tool_first_use", severity="low", message=""))

    # deny_burst：窗口内 deny 次数（窗口去重）
    if deny_count >= burst_threshold and not _recent_alert(db, agent, "deny_burst", now, burst_window):
        _add_alert(db, agent, "deny_burst", "high",
                   f"滑动窗口 {burst_window}s 内 deny 达到 {deny_count} 次（阈值 {burst_threshold}）",
                   events[-1].seq if events else 0, now)
        new_alerts.append(PodAlert(kind="deny_burst", severity="high", message=""))

    # tool_spike：窗口内调用总数激增（窗口去重）
    if call_count >= spike_threshold and not _recent_alert(db, agent, "tool_spike", now, burst_window):
        _add_alert(db, agent, "tool_spike", "high",
                   f"滑动窗口 {burst_window}s 内工具调用达 {call_count} 次（阈值 {spike_threshold}）——疑似失控循环",
                   events[-1].seq if events else 0, now)
        new_alerts.append(PodAlert(kind="tool_spike", severity="high", message=""))

    return new_alerts
