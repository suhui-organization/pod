"""用户管理(租户 admin):创建/列表/更新/停用成员。"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import require_admin
from app.models import TenantUser, User
from app.schemas import UserCreateRequest, UserUpdateRequest
from app.security import get_current_tenant_id, get_current_user, hash_password, set_password, validate_password_strength
from app.services.audit import record_audit

router = APIRouter(prefix="/users", tags=["users"])

VALID_ROLES = {"admin", "member"}


def _user_out(db: Session, tenant_id: int, user_id: int) -> dict:
    row = db.query(User).filter(User.id == user_id).first()
    membership = db.query(TenantUser).filter(TenantUser.tenant_id == tenant_id, TenantUser.user_id == user_id).first()
    if row is None or membership is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="用户不存在")
    return {
        "id": row.id,
        "email": row.email,
        "full_name": row.full_name,
        "role": membership.role,
        "is_active": row.is_active,
        "created_at": row.created_at.isoformat(),
    }


@router.get("")
def list_users(db: Session = Depends(get_db), user: dict = Depends(get_current_user), tenant_id: int = Depends(get_current_tenant_id)):
    require_admin(db, tenant_id, user)
    memberships = db.query(TenantUser).filter(TenantUser.tenant_id == tenant_id).all()
    out = []
    for m in memberships:
        row = db.query(User).filter(User.id == m.user_id).first()
        if row is not None:
            out.append({"id": row.id, "email": row.email, "full_name": row.full_name, "role": m.role, "is_active": row.is_active, "created_at": row.created_at.isoformat()})
    return out


@router.post("")
def create_user(body: UserCreateRequest, db: Session = Depends(get_db), user: dict = Depends(get_current_user), tenant_id: int = Depends(get_current_tenant_id)):
    require_admin(db, tenant_id, user)
    if body.role not in VALID_ROLES:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="角色仅支持 admin 或 member")
    weak = validate_password_strength(body.password)
    if weak:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=weak)
    exists = db.query(User).filter(User.email == body.email).first()
    if exists is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="邮箱已被使用")
    row = User(email=body.email, password_hash=hash_password(body.password), full_name=body.full_name.strip())
    db.add(row)
    db.flush()
    db.add(TenantUser(tenant_id=tenant_id, user_id=row.id, role=body.role))
    record_audit(db, tenant_id=tenant_id, user_id=user["id"], action="user_create", detail={"email": body.email, "role": body.role})
    db.commit()
    return _user_out(db, tenant_id, row.id)


@router.patch("/{user_id}")
def update_user(user_id: int, body: UserUpdateRequest, db: Session = Depends(get_db), user: dict = Depends(get_current_user), tenant_id: int = Depends(get_current_tenant_id)):
    require_admin(db, tenant_id, user)
    row = db.query(User).filter(User.id == user_id).first()
    membership = db.query(TenantUser).filter(TenantUser.tenant_id == tenant_id, TenantUser.user_id == user_id).first()
    if row is None or membership is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="用户不存在")
    if body.role is not None:
        if body.role not in VALID_ROLES:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="角色仅支持 admin 或 member")
        if user_id == user["id"] and body.role != "admin":
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="不能取消自己的管理员角色")
        membership.role = body.role
    if body.is_active is not None:
        if user_id == user["id"] and not body.is_active:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="不能停用自己的账号")
        row.is_active = body.is_active
    if body.full_name is not None:
        row.full_name = body.full_name.strip()
    if body.password:
        weak = validate_password_strength(body.password)
        if weak:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=weak)
        # 管理员代改密码 = 一次重置:该成员所有既有会话立即失效,
        # 否则"重置了密码但旧会话还活着"会一直开着。
        set_password(row, body.password)
    record_audit(db, tenant_id=tenant_id, user_id=user["id"], action="user_update", detail={"user_id": user_id, "role": body.role, "is_active": body.is_active})
    db.commit()
    return _user_out(db, tenant_id, user_id)


@router.delete("/{user_id}")
def deactivate_user(user_id: int, db: Session = Depends(get_db), user: dict = Depends(get_current_user), tenant_id: int = Depends(get_current_tenant_id)):
    require_admin(db, tenant_id, user)
    if user_id == user["id"]:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="不能停用自己的账号")
    row = db.query(User).filter(User.id == user_id).first()
    membership = db.query(TenantUser).filter(TenantUser.tenant_id == tenant_id, TenantUser.user_id == user_id).first()
    if row is None or membership is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="用户不存在")
    row.is_active = False
    record_audit(db, tenant_id=tenant_id, user_id=user["id"], action="user_deactivate", detail={"user_id": user_id})
    db.commit()
    return {"ok": True}
