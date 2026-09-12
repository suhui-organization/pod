"""租户:当前租户信息、成员数、创建新租户(私有化实例禁用)。"""

from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.models import Tenant, TenantUser
from app.schemas import TenantOut
from app.security import get_current_tenant_id, get_current_user

router = APIRouter(prefix="/tenants", tags=["tenants"])


class CreateTenantRequest(BaseModel):
    name: str = Field(min_length=1, max_length=128)


@router.get("/me")
def tenants_me(db: Session = Depends(get_db), user: dict = Depends(get_current_user), tenant_id: int = Depends(get_current_tenant_id)):
    tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
    if not tenant:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="租户不存在")
    members = db.query(TenantUser).filter(TenantUser.tenant_id == tenant_id).count()
    my_role = db.query(TenantUser).filter(TenantUser.tenant_id == tenant_id, TenantUser.user_id == user["id"]).first()
    return {**TenantOut.model_validate(tenant).model_dump(), "members": members, "is_private": settings.is_private,
            "my_role": my_role.role if my_role else "member"}


@router.post("")
def create_tenant(body: CreateTenantRequest, db: Session = Depends(get_db), user: dict = Depends(get_current_user)):
    if settings.is_private:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="私有化实例不支持创建新租户")
    tenant = Tenant(name=body.name, slug=f"t-{body.name[:32]}-{uuid4().hex[:6]}", plan="trial")
    db.add(tenant)
    db.flush()
    db.add(TenantUser(tenant_id=tenant.id, user_id=user["id"], role="admin"))
    db.commit()
    return TenantOut.model_validate(tenant)
