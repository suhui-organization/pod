"""Pod Cloud：告警聚合（P2 云端版，与本地告警规则同构）。"""

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Agent, PodAlert
from app.security import get_current_tenant_id, get_current_user

router = APIRouter(prefix="/alerts", tags=["alerts"])

VALID_STATES = {"open", "acknowledged", "resolved"}


class AlertStateIn(BaseModel):
    state: str = Field(min_length=1, max_length=16)


@router.get("")
def list_alerts(
    limit: int = 50,
    kind: str | None = None,
    severity: str | None = None,
    state: str | None = None,
    db: Session = Depends(get_db),
    tenant_id: int = Depends(get_current_tenant_id),
):
    """租户告警列表（新→旧），含 agent 名；可按 kind/severity/state 筛选。"""
    q = db.query(PodAlert, Agent.name).join(Agent, PodAlert.agent_id == Agent.id).filter(PodAlert.tenant_id == tenant_id)
    if kind:
        q = q.filter(PodAlert.kind == kind)
    if severity:
        q = q.filter(PodAlert.severity == severity)
    if state:
        q = q.filter(PodAlert.state == state)
    rows = q.order_by(PodAlert.id.desc()).limit(min(max(limit, 1), 200)).all()
    return {
        "alerts": [
            {
                "id": a.id,
                "agent": name,
                "agent_id": a.agent_id,
                "kind": a.kind,
                "severity": a.severity,
                "message": a.message,
                "event_seq": a.event_seq,
                "state": a.state,
                "created_at": a.created_at.isoformat(),
            }
            for a, name in rows
        ]
    }


@router.put("/{alert_id}/state")
def update_alert_state(
    alert_id: int,
    body: AlertStateIn,
    db: Session = Depends(get_db),
    tenant_id: int = Depends(get_current_tenant_id),
):
    """更新告警状态：open（未处理）/ acknowledged（已确认）/ resolved（已解决）。"""
    if body.state not in VALID_STATES:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"state 需为 {sorted(VALID_STATES)} 之一")
    alert = db.query(PodAlert).filter(PodAlert.id == alert_id, PodAlert.tenant_id == tenant_id).first()
    if alert is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="告警不存在")
    alert.state = body.state
    db.commit()
    return {"id": alert.id, "state": alert.state}


@router.post("/batch-state")
def batch_update_state(
    ids: list[int],
    state: str,
    db: Session = Depends(get_db),
    tenant_id: int = Depends(get_current_tenant_id),
):
    """批量更新告警状态（如「全部已解决」）。"""
    if state not in VALID_STATES:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"state 需为 {sorted(VALID_STATES)} 之一")
    updated = (
        db.query(PodAlert)
        .filter(PodAlert.tenant_id == tenant_id, PodAlert.id.in_(ids[:500]))
        .update({PodAlert.state: state}, synchronize_session=False)
    )
    db.commit()
    return {"updated": updated}


@router.post("/summarize")
def summarize_alerts(
    hours: int = 24,
    db: Session = Depends(get_db),
    tenant_id: int = Depends(get_current_tenant_id),
    user: dict = Depends(get_current_user),
):
    """AI 告警摘要（分析层，只返回文本，不改变任何告警状态）。

    模型配置取租户设置（设置 → AI 模型），未配置时回落环境变量
    PODCLOUD_LLM_API_KEY；仍无 key 返回 400 并说明去哪配。
    """
    from datetime import datetime, timedelta

    from app.models import TenantSettings
    from app.services import llm
    from app.services.ai_summary import summarize

    row = db.query(TenantSettings).filter(TenantSettings.tenant_id == tenant_id).first()
    try:
        cfg = llm.resolve_config(row)
    except llm.LlmConfigError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)) from e

    since = datetime.utcnow() - timedelta(hours=max(1, min(hours, 168)))
    rows = (
        db.query(PodAlert, Agent.name)
        .join(Agent, PodAlert.agent_id == Agent.id)
        .filter(PodAlert.tenant_id == tenant_id, PodAlert.created_at >= since)
        .order_by(PodAlert.id.desc())
        .limit(50)
        .all()
    )
    alerts = [
        {
            "agent": name,
            "severity": a.severity,
            "kind": a.kind,
            "message": a.message,
            "ts": a.created_at.isoformat(),
        }
        for a, name in rows
    ]
    try:
        result = summarize(cfg, alerts, db=db, tenant_id=tenant_id, user_id=user["id"])
        db.commit()  # 提交调用留痕；摘要本身不落库
    except Exception as e:  # noqa: BLE001 分析失败不影响告警主流程
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=f"AI 摘要生成失败: {e}") from e
    return {"summary": result["summary"], "model": result["model"], "alerts_count": len(alerts), "ai_generated": True}


@router.post("/digest-now")
def digest_now(
    db: Session = Depends(get_db),
    tenant_id: int = Depends(get_current_tenant_id),
    user: dict = Depends(get_current_user),
):
    """立即推送一份 AI 日报（手动触发，复用 webhook/邮件渠道）。"""
    from app.services.digest_scheduler import push_digest_now

    try:
        result = push_digest_now(db, tenant_id, user_id=user["id"])
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)) from e
    except Exception as e:  # noqa: BLE001 日报生成失败不影响主流程
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=f"日报生成失败: {e}") from e
    return result
