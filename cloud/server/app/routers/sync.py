"""Pod Cloud：本地网关审计同步端点（pod sync 命令调用）。

- 鉴权：X-Sync-Token 头（服务端存 sha256 哈希，不存明文）
- 完整性：批次内事件按 pod 本地哈希链顺序提交，prev_hash 必须连续，
  断裂即拒绝（409）——云端保留可验证的不可变审计
- 敏感内容：只收哈希（args_hash/output 不传输），隐私最小化
"""

import json
from datetime import datetime

from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import (
    CONTROL_CHAIN,
    Agent,
    PodAgentAsset,
    PodAgentFinding,
    PodAlert,
    PodControlEvent,
    PodPolicy,
    SyncEvent,
)
from app.protocol import MIN_CLIENT_PROTOCOL, SERVER_PROTOCOL

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


class AuditHealthIn(BaseModel):
    """审计链健康：条数 / 断裂数 / 最近一次工具调用时间。"""

    chains: int = Field(default=0, ge=0, le=1_000_000)
    broken: int = Field(default=0, ge=0, le=1_000_000)
    last_call_at: str | None = Field(default=None, max_length=64)


class CoverageHealthIn(BaseModel):
    """网关覆盖率：发现的 server 数 / 其中绕过网关的数量。"""

    servers: int = Field(default=0, ge=0, le=1_000_000)
    unmanaged: int = Field(default=0, ge=0, le=1_000_000)


class GuardHealthIn(BaseModel):
    """最近一次只读漏洞扫描的计数。"""

    high: int = Field(default=0, ge=0, le=1_000_000)
    medium: int = Field(default=0, ge=0, le=1_000_000)
    low: int = Field(default=0, ge=0, le=1_000_000)
    scanned_at: str = Field(default="", max_length=64)


class HealthIn(BaseModel):
    """本机健康摘要。

    字段显式列出（而不是收任意 dict）有两个原因：只存我们知道含义的东西，
    以及给存储一个上界——健康摘要是机器自报的，不能让它把库写爆。
    契约上**只允许计数、布尔与时间戳**：路径、主机名、配置原文一律不出本机。
    """

    audit: AuditHealthIn = Field(default_factory=AuditHealthIn)
    coverage: CoverageHealthIn = Field(default_factory=CoverageHealthIn)
    guard: GuardHealthIn | None = None
    errors: list[str] = Field(default_factory=list, max_length=20)


class PingIn(BaseModel):
    """心跳载荷。**全部可选**：v0.4.0 之前的客户端不带 body，心跳照常工作。"""

    protocol_version: int = Field(default=0, ge=0, le=10_000)
    pod_version: str = Field(default="", max_length=32)
    health: HealthIn | None = None


class InventoryHarnessIn(BaseModel):
    """本机装的一个 harness。"""

    id: str = Field(min_length=1, max_length=64)
    label: str = Field(default="", max_length=64)
    installed: bool = True
    managed: bool = False
    managed_by: list[str] = Field(default_factory=list, max_length=8)


class InventoryServerIn(BaseModel):
    """本机配置里的一个 MCP server。只收标识与状态，不收 args/paths/env 取值。"""

    name: str = Field(min_length=1, max_length=128)
    harness: str = Field(default="", max_length=64)
    transport: str = Field(default="", max_length=16)
    behind_gateway: bool = False
    record_only: bool = False
    scope: str = Field(default="", max_length=16)
    package: str = Field(default="", max_length=128)
    pinned: bool = False


class InventoryIn(BaseModel):
    """② 资产清单（机器级快照，每次上报整体替换）。"""

    pod_version: str = Field(default="", max_length=32)
    # 机器标识（伪匿名哈希）。同一台机器接多个绑定时靠它去重
    machine_id: str = Field(default="", max_length=32)
    rules_version: str = Field(default="", max_length=32)
    scanned_at: str = Field(default="", max_length=64)
    coverage: CoverageHealthIn = Field(default_factory=CoverageHealthIn)
    harnesses: list[InventoryHarnessIn] = Field(default_factory=list, max_length=64)
    servers: list[InventoryServerIn] = Field(default_factory=list, max_length=300)


class InventoryRequest(BaseModel):
    inventory: InventoryIn


class FindingIn(BaseModel):
    """③ 一条聚合发现：哪个威胁/类别、多严重、落在哪、几处。"""

    source: str = Field(min_length=1, max_length=16)
    key: str = Field(min_length=1, max_length=64)
    severity: str = Field(min_length=1, max_length=16)
    harness: str = Field(default="", max_length=64)
    count: int = Field(default=0, ge=0, le=1_000_000)


class FindingsTotalsIn(BaseModel):
    high: int = Field(default=0, ge=0, le=1_000_000)
    medium: int = Field(default=0, ge=0, le=1_000_000)
    low: int = Field(default=0, ge=0, le=1_000_000)


class FindingsPayloadIn(BaseModel):
    """③ 发现清单本体（每次上报整体替换）。"""

    scanned_at: str = Field(default="", max_length=64)
    totals: FindingsTotalsIn = Field(default_factory=FindingsTotalsIn)
    findings: list[FindingIn] = Field(default_factory=list, max_length=500)


class FindingsRequest(BaseModel):
    """线上升级形状：`{"findings": {...}}`——与客户端的 payload 一一对应。

    为什么不让顶层直接是那些字段：端 A 的两个上报都是"一个信封 + 一份快照"
    （`{"inventory": …}` / `{"findings": …}`），形状一致才不容易接错。
    """

    findings: FindingsPayloadIn


def _agent_from_token(db: Session, x_sync_token: str) -> Agent:
    """X-Sync-Token → Agent。三处上报端点共用，鉴权口径只有这一份。"""
    if not x_sync_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="缺少 X-Sync-Token")
    from hashlib import sha256

    token_hash = sha256(x_sync_token.encode("utf-8")).hexdigest()
    agent = db.query(Agent).filter(Agent.sync_token_hash == token_hash).first()
    if agent is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="sync token 无效")
    return agent


@router.post("/events")
def sync_events(
    body: SyncBatchRequest,
    db: Session = Depends(get_db),
    x_sync_token: str = Header(default=""),
    x_pod_protocol: str = Header(default=""),
    x_pod_version: str = Header(default=""),
):
    """推送一批审计事件；校验哈希链连续性后入库。"""
    if not x_sync_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="缺少 X-Sync-Token")
    from hashlib import sha256

    token_hash = sha256(x_sync_token.encode("utf-8")).hexdigest()
    agent = db.query(Agent).filter(Agent.sync_token_hash == token_hash).first()
    if agent is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="sync token 无效")
    # 顺手记下客户端版本：即使这台机器的心跳被防火墙挡掉、只有事件能上来，
    # 控制台也能回答"它装的是哪一版"。
    if x_pod_protocol.strip().isdigit():
        agent.protocol_version = int(x_pod_protocol.strip())
    if x_pod_version.strip():
        agent.pod_version = x_pod_version.strip()[:32]

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
def sync_ping(
    body: PingIn | None = None,
    db: Session = Depends(get_db),
    x_sync_token: str = Header(default=""),
    x_pod_protocol: str = Header(default=""),
    x_pod_version: str = Header(default=""),
):
    """轻量心跳：刷新 last_seen/online，并收下"这台机器现在什么状态"。

    规模化后 agent 可能长时间无审计事件；在线判定不应依赖“有新事件”，
    而由定时 pod sync（含本心跳）维持，失联才由巡检切 offline。

    **在线 ≠ 真的在保护**：网关可能没起、链可能断了、还有 server 绕过网关。
    这些只有机器自己能看见，所以随心跳上报一份只含计数的健康摘要；
    控制台据此把"部署了但没生效"和"正常"分开。
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

    # 版本：body 优先，header 兜底（老客户端只带 header 的话也能记上）
    client_protocol = 0
    if body is not None and body.protocol_version:
        client_protocol = body.protocol_version
    elif x_pod_protocol.strip().isdigit():
        client_protocol = int(x_pod_protocol.strip())
    agent.protocol_version = client_protocol
    if body is not None and body.pod_version:
        agent.pod_version = body.pod_version
    elif x_pod_version.strip():
        agent.pod_version = x_pod_version.strip()[:32]

    # 健康摘要：只存合规字段（Pydantic 已限定形状），过期数据不留着冒充现状
    if body is not None and body.health is not None:
        agent.health_json = json.dumps(body.health.model_dump(), ensure_ascii=False)
        agent.health_at = now

    # 带上已有事件数:接入脚本据此把"token 有效"和"真的有审计上云"区分开,
    # 否则用户看到 ✅ 却不知道数据到底进来没有。
    event_count = db.query(SyncEvent).filter(SyncEvent.agent_id == agent.id).count()
    db.commit()

    # 协议提示：告诉客户端"你是不是已经旧到少了一半能力"。
    # 老客户端会忽略这些字段，所以加它们不会破坏任何东西。
    client_outdated = client_protocol < MIN_CLIENT_PROTOCOL
    resp = {
        "pong": True,
        "agent_id": agent.id,
        "last_seen_at": now.isoformat(),
        "event_count": event_count,
        "server_protocol": SERVER_PROTOCOL,
        "min_client_protocol": MIN_CLIENT_PROTOCOL,
        "client_outdated": client_outdated,
    }
    if client_outdated:
        resp["message"] = (
            f"本机 pod 上报的协议版本为 {client_protocol}，云端要求至少 {MIN_CLIENT_PROTOCOL}"
            f"（云端协议 {SERVER_PROTOCOL}）。建议升级本机 pod：当前版本的部分能力不会被云端识别。"
        )
    return resp


@router.post("/inventory")
def sync_inventory(
    body: InventoryRequest,
    db: Session = Depends(get_db),
    x_sync_token: str = Header(default=""),
):
    """② 资产清单：这台机器上有什么（harness / MCP server / 覆盖率）。

    **整体替换**语义：资产是快照，不是流水——机器说"现在有这些"，云端就存这些，
    某台 server 被删掉时会自然消失，不需要靠 diff。

    隐私边界：只收标识与布尔（name / harness / behind_gateway / scope / 包名），
    不收路径、args、env 取值与配置原文（那些留在本机报告里）。
    """
    agent = _agent_from_token(db, x_sync_token)
    now = datetime.utcnow()
    inv = body.inventory
    db.query(PodAgentAsset).filter(PodAgentAsset.agent_id == agent.id).delete(synchronize_session=False)
    mid = inv.machine_id.strip()[:32]
    for h in inv.harnesses:
        db.add(
            PodAgentAsset(
                tenant_id=agent.tenant_id,
                agent_id=agent.id,
                kind="harness",
                machine_id=mid,
                key=h.id[:128],
                label=h.label[:64],
                installed=h.installed,
                managed=h.managed,
                managed_by_json=json.dumps(h.managed_by, ensure_ascii=False),
                updated_at=now,
            )
        )
    for s in inv.servers:
        db.add(
            PodAgentAsset(
                tenant_id=agent.tenant_id,
                agent_id=agent.id,
                kind="server",
                machine_id=mid,
                key=s.name[:128],
                installed=True,
                managed=s.behind_gateway,
                behind_gateway=s.behind_gateway,
                record_only=s.record_only,
                scope=s.scope[:16],
                package=s.package[:128],
                pinned=s.pinned,
                harness=s.harness[:64],
                updated_at=now,
            )
        )
    agent.inventory_at = now
    db.commit()
    return {
        "ok": True,
        "harnesses": len(inv.harnesses),
        "servers": len(inv.servers),
        "unmanaged": sum(1 for s in inv.servers if not s.behind_gateway),
    }


@router.post("/findings")
def sync_findings(
    body: FindingsRequest,
    db: Session = Depends(get_db),
    x_sync_token: str = Header(default=""),
    x_pod_machine: str = Header(default=""),
):
    """③ 发现：pod 干活时扫出来的问题（漏洞扫描 + 控制平面姿态）。

    同样是快照替换：修好之后下次上报就消失了，不会在云端永远留一条红。
    """
    agent = _agent_from_token(db, x_sync_token)
    now = datetime.utcnow()
    db.query(PodAgentFinding).filter(PodAgentFinding.agent_id == agent.id).delete(synchronize_session=False)
    mid = x_pod_machine.strip()[:32]
    for f in body.findings.findings:
        db.add(
            PodAgentFinding(
                tenant_id=agent.tenant_id,
                agent_id=agent.id,
                source=f.source[:16],
                machine_id=mid,
                key=f.key[:64],
                severity=f.severity[:16],
                harness=f.harness[:64],
                count=f.count,
                updated_at=now,
            )
        )
    agent.findings_at = now
    db.commit()
    return {"ok": True, "findings": len(body.findings.findings)}


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
