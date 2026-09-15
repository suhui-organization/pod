"""/api/v1/selfcheck：人工触发的一键自检 + 自修复，以及巡检历史。

检查项与判定逻辑在 `services/selfcheck.py` —— 后台每日巡检走同一份，
否则会出现"我点了没问题、巡检却说失败"。这里只管鉴权、落库、返回。

权限：仅租户管理员（会触发一次真实模型出网调用与审计写入）。
语言：与其余服务端文案一致，走 Accept-Language（见 app/i18n.py）。
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import require_admin
from app.i18n import resolve_locale
from app.models import SelfCheckRun
from app.schemas import SelfCheckIn
from app.security import get_current_tenant_id, get_current_user
from app.services import selfcheck as selfcheck_service
from app.services import selfcheck_scheduler
from app.services.audit import record_audit

router = APIRouter(prefix="/selfcheck", tags=["selfcheck"])


@router.post("/run")
def run_selfcheck(
    request: Request,
    body: SelfCheckIn | None = None,
    db: Session = Depends(get_db),
    user: dict = Depends(get_current_user),
    tenant_id: int = Depends(get_current_tenant_id),
):
    """跑一遍自检；repair=true 时先做安全自修复，再检查（结果反映修完的状态）。"""
    require_admin(db, tenant_id, user)
    locale = resolve_locale(request.headers.get("accept-language"), request.query_params.get("lang"))
    result = selfcheck_service.run_checks(
        db,
        tenant_id=tenant_id,
        user_id=user["id"],
        locale=locale,
        repair_first=bool(body and body.repair),
    )
    alerts = selfcheck_service.record_alerts(db, tenant_id, result)
    run = selfcheck_service.persist_run(db, tenant_id, "manual", result, alerts)
    record_audit(
        db,
        tenant_id=tenant_id,
        user_id=user["id"],
        action="selfcheck.run",
        detail={
            "repair": bool(body and body.repair),
            "summary": result["summary"],
            "repairs": result["repairs"],
            "alerts_created": alerts["created"],
            "alerts_auto_resolved": alerts["resolved"],
            "run_id": run.id,
        },
    )
    db.commit()
    return {
        "run_id": run.id,
        "started_at": result["started_at"].isoformat(timespec="seconds"),
        "finished_at": result["finished_at"].isoformat(timespec="seconds"),
        "locale": locale,
        "summary": result["summary"],
        "repairs": result["repairs"],
        # 这次顺手在告警列表里开了/关了哪些（页面可以据此提示"已自动关闭 N 条"）
        "alerts": alerts,
        "checks": result["checks"],
    }


@router.get("/history")
def selfcheck_history(
    limit: int = Query(10, ge=1, le=50),
    with_checks: bool = False,
    db: Session = Depends(get_db),
    user: dict = Depends(get_current_user),
    tenant_id: int = Depends(get_current_tenant_id),
):
    """巡检历史（新→旧）。默认只回摘要——列表只需要知道"哪天跑过、结果如何"。"""
    require_admin(db, tenant_id, user)
    rows = (
        db.query(SelfCheckRun)
        .filter(SelfCheckRun.tenant_id == tenant_id)
        .order_by(SelfCheckRun.id.desc())
        .limit(limit)
        .all()
    )
    runs = [selfcheck_service.serialize_run(r) for r in rows]
    if not with_checks:
        for r in runs:
            r.pop("checks", None)
    return {
        "runs": runs,
        # 把"自动巡检什么时候跑、失败会不会告警"一并告诉管理员（前端直接显示）
        "schedule": {
            "enabled": selfcheck_scheduler.enabled(),
            "hour": selfcheck_scheduler.settings.selfcheck_hour,
            "repair": selfcheck_scheduler._repair_enabled(),
            "notify": selfcheck_scheduler._notify_mode(),
        },
    }
