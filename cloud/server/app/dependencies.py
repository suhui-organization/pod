"""共享的权限依赖:租户管理员校验(能力中心/设置/用户管理统一使用)。"""

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.models import TenantUser


def require_admin(db: Session, tenant_id: int, user: dict) -> None:
    """仅当前租户 admin 可执行;不再按 client 类型豁免(角色才是权限边界)。"""
    membership = db.query(TenantUser).filter(TenantUser.tenant_id == tenant_id, TenantUser.user_id == user["id"]).first()
    if membership is None or membership.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="仅租户管理员可执行此操作")
