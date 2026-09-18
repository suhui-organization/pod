"""认证:注册(建用户+默认租户)、登录、刷新、当前用户。"""

from datetime import datetime, timedelta, timezone
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.models import AuditLog, PasswordResetToken, Tenant, TenantUser, User, UserPreference
from app.schemas import (
    ChangePasswordRequest,
    ForgotPasswordRequest,
    LoginRequest,
    ProfileUpdateRequest,
    RefreshRequest,
    RegisterRequest,
    ResetPasswordRequest,
    TenantOut,
)
from app.security import (
    RESET_TOKEN_MINUTES,
    create_access_token,
    create_refresh_token,
    decode_refresh_token,
    ensure_session_not_revoked,
    get_current_user,
    hash_reset_token,
    hash_password,
    new_reset_token,
    set_password,
    validate_password_strength,
    verify_password,
)
from app.services.mailer import deliver_reset_link, mailer_configured
from app.services.billing import billing_enabled

router = APIRouter(prefix="/auth", tags=["auth"])


@router.get("/config")
def auth_config():
    """公开配置:前端据此决定是否展示 Web 自助注册(desktop 不受此开关影响)。"""
    return {
        "is_private": settings.is_private,
        # 本部署是否启用计费：前端据此隐藏订阅入口（自托管部署没有付费能力）
        "billing_enabled": billing_enabled(),
        "billing_provider": settings.billing_provider if billing_enabled() else "",
        # 找回密码的投递方式:email=已配系统 SMTP;log=链接写服务端日志。
        # 这是实例级属性,与"账号是否存在"无关,所以可以公开。
        "password_reset": "email" if mailer_configured() else "log",
        "password_reset_minutes": RESET_TOKEN_MINUTES,
        # 本次构建的标识（镜像 tag）：前端在侧栏显示"构建 xxx"，运维也可以直接
        # `curl /api/v1/auth/config` 判断"新版本滚上去了没有"——比拿端点 401/404
        # 猜要确定得多。这是实例级公开信息，与账号是否存在无关。
        "build": settings.build_tag,
    }


def _tokens(user: User, tenant_id: int, client: str = "web") -> dict:
    return {
        "access_token": create_access_token(user_id=user.id, tenant_id=tenant_id, client=client),
        "refresh_token": create_refresh_token(user_id=user.id, tenant_id=tenant_id, client=client),
        "expires_in_minutes": settings.jwt_expire_minutes,
    }


@router.post("/register")
def register(body: RegisterRequest, db: Session = Depends(get_db)):
    if settings.is_private and body.client != "desktop":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="私有化实例不开放 Web 自助注册")
    weak = validate_password_strength(body.password)
    if weak:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=weak)
    exists = db.query(User).filter(User.email == body.email).first()
    if exists:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="邮箱已注册")
    tenant = Tenant(name=body.tenant_name or f"{body.email} 的工作空间", slug=f"t-{body.email.split('@')[0]}-{uuid4().hex[:6]}", plan="trial")
    db.add(tenant)
    db.flush()
    user = User(email=body.email, password_hash=hash_password(body.password), full_name=body.full_name)
    db.add(user)
    db.flush()
    db.add(TenantUser(tenant_id=tenant.id, user_id=user.id, role="admin"))
    db.add(AuditLog(tenant_id=tenant.id, user_id=user.id, action="register"))
    db.commit()
    return {"email": user.email, "tenant": TenantOut.model_validate(tenant), **_tokens(user, tenant.id)}


@router.post("/login")
def login(body: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == body.email).first()
    if not user or not verify_password(body.password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="邮箱或密码错误")
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="账号已停用")
    membership = db.query(TenantUser).filter(TenantUser.user_id == user.id).order_by(TenantUser.id).first()
    if membership is None:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="账号未关联任何租户")
    db.add(AuditLog(tenant_id=membership.tenant_id, user_id=user.id, action="login"))
    db.commit()
    client = getattr(body, "client", "web")
    return {
        **_tokens(user, membership.tenant_id, client=client),
        "user": {"id": user.id, "email": user.email, "full_name": user.full_name, "role": membership.role, "tenant_id": membership.tenant_id, "client": client},
    }


@router.post("/refresh")
def refresh(body: RefreshRequest, db: Session = Depends(get_db)):
    payload = decode_refresh_token(body.refresh_token)
    # 改密吊销同样覆盖刷新通道,否则旧 refresh 还能换出新 access
    ensure_session_not_revoked(payload, db)
    client = payload.get("client", "web")
    return {
        "access_token": create_access_token(user_id=payload["sub"], tenant_id=payload["tenant_id"], client=client),
        "refresh_token": create_refresh_token(user_id=payload["sub"], tenant_id=payload["tenant_id"], client=client),
        "expires_in_minutes": settings.jwt_expire_minutes,
    }


def _load_me(db: Session, user: dict) -> User:
    row = db.query(User).filter(User.id == user["id"]).first()
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="用户不存在")
    return row


def _me_payload(db: Session, user: dict) -> dict:
    """GET/PUT /me 共用一个响应形状,免得两条路径的字段各飘各的。"""
    row = _load_me(db, user)
    membership = db.query(TenantUser).filter(TenantUser.tenant_id == user["tenant_id"], TenantUser.user_id == user["id"]).first()
    return {
        "id": row.id,
        "email": row.email,
        "full_name": row.full_name,
        "tenant_id": user["tenant_id"],
        "role": membership.role if membership else "member",
        "client": user.get("client", "web"),
        # 带 +00:00 后缀:库里存的是 naive UTC,不标时区的话前端会按本地时间解析,
        # 东八区看到的时间会早 8 小时。
        "password_changed_at": (
            row.password_changed_at.replace(tzinfo=timezone.utc).isoformat() if row.password_changed_at else None
        ),
    }


@router.get("/me")
def me(db: Session = Depends(get_db), user: dict = Depends(get_current_user)):
    return _me_payload(db, user)


@router.put("/me")
def update_me(body: ProfileUpdateRequest, db: Session = Depends(get_db), user: dict = Depends(get_current_user)):
    """本人改资料。只需要登录态,不需要租户管理员。"""
    row = _load_me(db, user)
    row.full_name = body.full_name.strip()
    db.add(AuditLog(tenant_id=user["tenant_id"], user_id=row.id, action="profile_update"))
    db.commit()
    return _me_payload(db, user)


@router.post("/me/password")
def change_password(body: ChangePasswordRequest, db: Session = Depends(get_db), user: dict = Depends(get_current_user)):
    """本人改密:验旧密码 → 校验复杂度 → 换新 → 踢掉其它会话。

    旧密码错误返回 400 而不是 401:前端的 axios 拦截器把 401 当"登录态过期",
    会清 token 并跳登录页——输错一次旧密码不该把人踹出去。
    """
    row = _load_me(db, user)
    if not verify_password(body.old_password, row.password_hash):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="当前密码不正确")
    weak = validate_password_strength(body.new_password)
    if weak:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=weak)
    set_password(row, body.new_password)
    db.add(AuditLog(tenant_id=user["tenant_id"], user_id=row.id, action="password_change"))
    db.commit()
    # 吊销是按签发时间判定的,所以必须给本次会话换一对新 token,
    # 否则操作者改完自己的密码会被自己踢下线。
    client = user.get("client", "web")
    return {**_tokens(row, user["tenant_id"], client=client), "user": _me_payload(db, user)}


@router.post("/forgot-password")
def forgot_password(body: ForgotPasswordRequest, db: Session = Depends(get_db)):
    """申请找回密码链接。

    恒定响应:账号是否存在、是否刚申请过,对外都是同一句话——否则这个
    端点就成了账号枚举器。投递方式(邮件 / 日志)由 /auth/config 统一告知。
    """
    row = db.query(User).filter(User.email == body.email).first()
    if row is not None and row.is_active:
        now = datetime.utcnow()
        # 60 秒内重复申请直接忽略:否则谁都能把某个人的邮箱/日志刷爆
        recent = (
            db.query(PasswordResetToken)
            .filter(
                PasswordResetToken.user_id == row.id,
                PasswordResetToken.created_at > now - timedelta(seconds=60),
            )
            .first()
        )
        if recent is None:
            # 新链接作废旧的:任何时刻只可能有一条有效链接
            db.query(PasswordResetToken).filter(
                PasswordResetToken.user_id == row.id,
                PasswordResetToken.used_at.is_(None),
            ).update({"used_at": now})
            raw, token_hash = new_reset_token()
            db.add(
                PasswordResetToken(
                    user_id=row.id,
                    token_hash=token_hash,
                    expires_at=now + timedelta(minutes=RESET_TOKEN_MINUTES),
                )
            )
            membership = db.query(TenantUser).filter(TenantUser.user_id == row.id).order_by(TenantUser.id).first()
            if membership is not None:
                db.add(
                    AuditLog(
                        tenant_id=membership.tenant_id,
                        user_id=row.id,
                        action="password_reset_request",
                    )
                )
            db.commit()
            deliver_reset_link(row.email, f"{settings.public_base_url}/reset-password?token={raw}")
    return {"ok": True}


@router.post("/reset-password")
def reset_password(body: ResetPasswordRequest, db: Session = Depends(get_db)):
    """用一次性令牌换新密码。成功后该账号所有旧会话立即失效(见 set_password)。"""
    token_row = (
        db.query(PasswordResetToken)
        .filter(
            PasswordResetToken.token_hash == hash_reset_token(body.token),
            PasswordResetToken.used_at.is_(None),
        )
        .first()
    )
    # 令牌不存在/已用/已过期,对外是同一句话:别把"这个 token 存在过"漏出去
    if token_row is None or token_row.expires_at < datetime.utcnow():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="重置链接无效或已过期,请重新申请")
    row = db.query(User).filter(User.id == token_row.user_id).first()
    if row is None or not row.is_active:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="重置链接无效或已过期,请重新申请")
    weak = validate_password_strength(body.new_password)
    if weak:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=weak)
    set_password(row, body.new_password)
    token_row.used_at = datetime.utcnow()
    membership = db.query(TenantUser).filter(TenantUser.user_id == row.id).order_by(TenantUser.id).first()
    if membership is not None:
        db.add(AuditLog(tenant_id=membership.tenant_id, user_id=row.id, action="password_reset"))
    db.commit()
    return {"ok": True}


# ─────────────────────────────────────────────────────────────────
# 用户偏好(替代前端的 localStorage,跨设备同步)
# ─────────────────────────────────────────────────────────────────
class PreferencesBody(BaseModel):
    """PUT /me/preferences 的请求体:任意 KV,后端整块覆盖存。"""
    preferences: dict = Field(default_factory=dict)


def _load_preferences(db: Session, user: dict) -> dict:
    row = db.query(UserPreference).filter(UserPreference.user_id == user["id"]).first()
    if not row:
        return {}
    try:
        import json as _json
        return _json.loads(row.preferences_json or "{}")
    except Exception:
        return {}


@router.get("/me/preferences")
def get_my_preferences(db: Session = Depends(get_db), user: dict = Depends(get_current_user)):
    """获取当前用户的偏好(JSON object)。首次访问返回空 dict。"""
    return {"preferences": _load_preferences(db, user)}


@router.put("/me/preferences")
def put_my_preferences(body: PreferencesBody, db: Session = Depends(get_db), user: dict = Depends(get_current_user)):
    """覆盖式写入偏好(全量替换)。前端 debounce 后调用。"""
    import json as _json
    row = db.query(UserPreference).filter(UserPreference.user_id == user["id"]).first()
    payload = _json.dumps(body.preferences or {}, ensure_ascii=False)
    if row:
        row.preferences_json = payload
    else:
        row = UserPreference(
            user_id=user["id"],
            tenant_id=user["tenant_id"],
            preferences_json=payload,
        )
        db.add(row)
    db.commit()
    return {"preferences": body.preferences or {}}
