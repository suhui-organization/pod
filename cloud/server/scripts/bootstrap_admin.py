"""私有化实例管理员初始化:python -m scripts.bootstrap_admin --email a@x.com --password xxx"""
import argparse
import os
import sys
from uuid import uuid4

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.database import Base, SessionLocal, engine  # noqa: E402
from app.models import Tenant, TenantUser, User  # noqa: E402
from app.security import hash_password  # noqa: E402


def bootstrap_admin(email: str, password: str, tenant_name: str = "默认租户") -> str:
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        existing = db.query(User).filter(User.email == email).first()
        if existing:
            # 幂等:账号已存在时提示其租户,便于排查"登错账号"类问题
            memberships = db.query(TenantUser).filter(TenantUser.user_id == existing.id).all()
            tids = [m.tenant_id for m in memberships]
            print(f"[bootstrap] 账号 {email} 已存在(user_id={existing.id},租户={tids}),跳过创建。")
            return f"already-exists:user={existing.id},tenants={tids}"
        if existing:
            return "用户已存在,跳过"
        # slug 需唯一:邮箱前缀 + 随机后缀(与 register 路由一致,避免同前缀邮箱冲突)
        tenant = Tenant(name=tenant_name, slug=f"private-{email.split('@')[0]}-{uuid4().hex[:6]}", plan="trial", is_private=True)
        db.add(tenant)
        db.flush()
        user = User(email=email, password_hash=hash_password(password), full_name="管理员")
        db.add(user)
        db.flush()
        db.add(TenantUser(tenant_id=tenant.id, user_id=user.id, role="admin"))
        db.commit()
        return "管理员创建完成"
    finally:
        db.close()


def main():
    parser = argparse.ArgumentParser(description="私有化实例管理员初始化")
    parser.add_argument("--email", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--tenant-name", default="默认租户")
    args = parser.parse_args()
    print(bootstrap_admin(args.email, args.password, args.tenant_name))


if __name__ == "__main__":
    main()
