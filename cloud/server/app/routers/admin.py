"""成员管理(内网 SaaS 形态):admin 创建成员(加入本租户)、列成员、重置密码。

边界:仅租户 admin 可写(desktop 客户端豁免——单用户租户自己即 admin);
创建的用户加入当前租户,继承租户级模型/数据源配置。
"""

import json

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import AuditLog, TenantUser, User
from app.security import get_current_tenant_id, get_current_user, hash_password, set_password, validate_password_strength

router = APIRouter(prefix="/admin", tags=["admin"])


def _require_admin(db: Session, tenant_id: int, user: dict) -> None:
    if user.get("client") == "desktop":
        return
    membership = db.query(TenantUser).filter(TenantUser.tenant_id == tenant_id, TenantUser.user_id == user["id"]).first()
    if membership is None or membership.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="仅租户管理员可管理成员")


class CreateMemberRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=64)
    full_name: str = Field(default="", max_length=128)
    role: str = Field(default="member", pattern="^(member|admin)$")


class ResetPasswordRequest(BaseModel):
    password: str = Field(min_length=8, max_length=64)


@router.get("/users")
def list_members(db: Session = Depends(get_db), user: dict = Depends(get_current_user), tenant_id: int = Depends(get_current_tenant_id)):
    _require_admin(db, tenant_id, user)
    rows = db.query(TenantUser, User).join(User, User.id == TenantUser.user_id).filter(TenantUser.tenant_id == tenant_id).all()
    return [
        {"id": u.id, "email": u.email, "full_name": u.full_name, "role": tu.role, "is_active": u.is_active, "created_at": str(u.created_at)}
        for tu, u in rows
    ]


@router.post("/users")
def create_member(body: CreateMemberRequest, db: Session = Depends(get_db), user: dict = Depends(get_current_user), tenant_id: int = Depends(get_current_tenant_id)):
    _require_admin(db, tenant_id, user)
    weak = validate_password_strength(body.password)
    if weak:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=weak)
    exists = db.query(User).filter(User.email == body.email).first()
    if exists:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="邮箱已注册")
    new_user = User(email=str(body.email), password_hash=hash_password(body.password), full_name=body.full_name)
    db.add(new_user)
    db.flush()
    db.add(TenantUser(tenant_id=tenant_id, user_id=new_user.id, role=body.role))
    db.add(AuditLog(tenant_id=tenant_id, user_id=user["id"], action=f"create_member:{body.email}"))
    db.commit()
    return {"id": new_user.id, "email": new_user.email, "full_name": new_user.full_name, "role": body.role}


@router.post("/users/{member_id}/reset-password")
def reset_password(member_id: int, body: ResetPasswordRequest, db: Session = Depends(get_db), user: dict = Depends(get_current_user), tenant_id: int = Depends(get_current_tenant_id)):
    _require_admin(db, tenant_id, user)
    membership = db.query(TenantUser).filter(TenantUser.tenant_id == tenant_id, TenantUser.user_id == member_id).first()
    if membership is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="成员不存在")
    member = db.query(User).filter(User.id == member_id).first()
    weak = validate_password_strength(body.password)
    if weak:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=weak)
    # 重置密码同时吊销该成员所有既有会话:被盗号时这条是唯一能立刻止血的动作
    set_password(member, body.password)
    db.add(AuditLog(tenant_id=tenant_id, user_id=user["id"], action=f"reset_password:{member_id}"))
    db.commit()
    return {"id": member_id, "ok": True}


@router.get("/flow-audits")
def list_flow_audits(
    page: int = 1,
    page_size: int = 50,
    db: Session = Depends(get_db),
    user: dict = Depends(get_current_user),
    tenant_id: int = Depends(get_current_tenant_id),
):
    """流程级审计快照只读端点(企业尽调可验证):按页列出本租户 flow_run 审计。

    每条含:flow_id/flow_name/entry/status/输入输出预览/输出指纹(output_sha256)/
    审批链路(approval_id)/会话关联(conversation_id, session_id)/耗时/工具调用。

    分页:page 从 1 起;page_size 默认 50,上限 200。
    响应:{ total(全量计数), page, page_size, stats{ok, error, avg_duration_ms}, items }。
    stats 基于最近 1000 条聚合(status/duration_ms 在 detail_json 内,需 Python 侧聚合);
    total 为全部记录数,分页仅影响 items。
    """
    _require_admin(db, tenant_id, user)
    page = max(page, 1)
    page_size = min(max(page_size, 1), 200)
    base = db.query(AuditLog).filter(AuditLog.tenant_id == tenant_id, AuditLog.action == "flow_run")

    total = base.count()
    rows = (
        base.order_by(AuditLog.id.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    items = []
    for r in rows:
        try:
            detail = json.loads(r.detail_json or "{}")
        except json.JSONDecodeError:
            detail = {}
        items.append({"id": r.id, "user_id": r.user_id, "created_at": str(r.created_at), **detail})

    # 最近 1000 条聚合统计(OK/失败/平均耗时;耗时字段在 detail_json,无法 SQL 聚合)
    ok = err = 0
    durations: list[int] = []
    for rid, detail_json in (
        base.order_by(AuditLog.id.desc())
        .with_entities(AuditLog.id, AuditLog.detail_json)
        .limit(1000)
        .all()
    ):
        try:
            detail = json.loads(detail_json or "{}")
        except json.JSONDecodeError:
            detail = {}
        if detail.get("status") == "ok":
            ok += 1
        else:
            err += 1
        d = detail.get("duration_ms")
        if isinstance(d, (int, float)):
            durations.append(int(d))
    avg_duration_ms = round(sum(durations) / len(durations)) if durations else 0

    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "stats": {"ok": ok, "error": err, "avg_duration_ms": avg_duration_ms},
        "items": items,
    }
