"""安全:密码哈希(bcrypt)、JWT 编解码、FastAPI 依赖注入。"""

import re
import secrets
import hashlib
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

import bcrypt
import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db

if TYPE_CHECKING:
    from app.models import User

ALGORITHM = "HS256"
REFRESH_EXPIRE_DAYS = 30
PASSWORD_MIN_LENGTH = 8
RESET_TOKEN_MINUTES = 30
bearer_scheme = HTTPBearer(auto_error=False)


def _now_ts() -> float:
    """签发时间(浮点秒)。用浮点而非整秒:改密与换发新 token 在同一秒内完成,
    整秒粒度下"新旧"无法区分,要么踢掉操作者自己、要么放跑旧会话。"""
    return datetime.now(timezone.utc).timestamp()


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
    except ValueError:
        return False


def validate_password_strength(password: str) -> str | None:
    """密码复杂度策略:≥8 位且同时含字母与数字。合规返回 None,否则返回中文提示。

    只此一处实现:注册、成员创建/重置、本人改密都必须调用它。否则
    "管理员能把密码设成 123456、本人却不能"这类不一致会从别的入口漏回来。
    """
    if len(password) < PASSWORD_MIN_LENGTH:
        return f"密码至少 {PASSWORD_MIN_LENGTH} 位"
    if not re.search(r"[A-Za-z]", password) or not re.search(r"[0-9]", password):
        return "密码需同时包含字母和数字"
    return None


def set_password(user_row: "User", new_password: str) -> None:
    """写入新密码的唯一入口:换 hash 的同时打上 password_changed_at,
    该用户名下所有既有 token 立即失效(见 ensure_session_not_revoked)。

    本人自助改密会紧接着换发一对新 token(auth.change_password),所以操作者不掉线;
    管理员重置不给新 token——被重置的人必须重新登录,这正是重置的意义。
    """
    user_row.password_hash = hash_password(new_password)
    user_row.password_changed_at = datetime.utcnow()


def hash_reset_token(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def new_reset_token() -> tuple[str, str]:
    """生成找回密码令牌,返回 (明文, sha256)。

    明文只在邮件正文/服务端日志里出现这一次,库里存的是 sha256——
    库被读走也换不回可用链接。
    """
    raw = secrets.token_urlsafe(32)
    return raw, hash_reset_token(raw)


def create_access_token(user_id: int, tenant_id: int, client: str = "web") -> str:
    payload = {
        "sub": str(user_id),
        "tenant_id": tenant_id,
        "type": "access",
        "client": client,  # web | desktop(desktop 豁免管理权限校验)
        "iat": _now_ts(),  # 改密吊销的依据
        "exp": datetime.now(timezone.utc) + timedelta(minutes=settings.jwt_expire_minutes),
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm=ALGORITHM)


def create_internal_token(user_id: int, tenant_id: int) -> str:
    """内部服务令牌(不限过期):注入 Fluvia 流程 / 数据网关 / 定时任务等服务对服务通道。

    永不过期(无 exp 声明):与 Web 登录 token(create_access_token,12h 过期)分离语义。
    仅用于 FinHarness 系统内部(chat 路由 → Fluvia → 数据网关回调),
    校验端(网关 data_query / Fluvia 组件)接受无 exp 的 access 类型 JWT。
    """
    payload = {
        "sub": str(user_id),
        "tenant_id": tenant_id,
        "type": "access",
        "client": "internal",
        "iat": _now_ts(),
        # 无 exp → 永不过期;服务对服务凭据由网关鉴权兜底(内部网络),不随登录态失效
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm=ALGORITHM)


def create_refresh_token(user_id: int, tenant_id: int, client: str = "web") -> str:
    """独立刷新凭据:type=refresh + 30 天有效期,与 access token 语义分离。"""
    payload = {
        "sub": str(user_id),
        "tenant_id": tenant_id,
        "type": "refresh",
        "client": client,  # 刷新后保持客户端标识(desktop 豁免不丢失)
        "iat": _now_ts(),
        "exp": datetime.now(timezone.utc) + timedelta(days=REFRESH_EXPIRE_DAYS),
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm=ALGORITHM)


def _decode_jwt(token: str) -> dict:
    try:
        payload = jwt.decode(token, settings.jwt_secret, algorithms=[ALGORITHM])
    except jwt.PyJWTError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="无效或过期的登录凭证") from exc
    try:
        payload["sub"] = int(payload["sub"])
    except (ValueError, KeyError, TypeError) as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="无效或过期的登录凭证") from exc
    return payload


def decode_token(token: str) -> dict:
    """解码 access 凭据;N2:拒绝 type=refresh 的 token(向后兼容:无 type 的旧 token 视为 access)。"""
    payload = _decode_jwt(token)
    if payload.get("type", "access") != "access":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="无效或过期的登录凭证")
    return payload


def decode_refresh_token(token: str) -> dict:
    """校验刷新凭据:必须为 type=refresh 的 JWT,否则 401。"""
    payload = _decode_jwt(token)
    if payload.get("type") != "refresh":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="无效的刷新凭证")
    return payload


def ensure_session_not_revoked(payload: dict, db: Session) -> None:
    """本人改密后,签发时间早于 password_changed_at 的凭据一律失效。

    access 与 refresh 都要过这一关——只挡 access 的话,旧 refresh 还能换出新 access。
    client=internal 是服务间凭据(无 exp,生命周期不由登录态决定),不参与吊销。

    没有 iat 的旧 token 视为已失效(仅在用户改过密码之后才可能走到这里)。
    """
    if payload.get("client") == "internal":
        return
    from app.models import User

    row = db.query(User).filter(User.id == int(payload["sub"])).first()
    if row is None or row.password_changed_at is None:
        return
    # password_changed_at 由 datetime.utcnow() 写入(naive UTC),比较前补上时区
    changed_at = row.password_changed_at.replace(tzinfo=timezone.utc).timestamp()
    issued_at = payload.get("iat")
    if not isinstance(issued_at, (int, float)) or issued_at < changed_at:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="登录凭证已失效,请重新登录")


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> dict:
    """解析 token + 加载 user role 信息 (admin endpoints 需要)."""
    from app.models import User, TenantUser
    if credentials is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="缺少登录凭证")
    payload = decode_token(credentials.credentials)
    ensure_session_not_revoked(payload, db)
    user_id = int(payload["sub"])
    # 查 user role (查 TenantUser 表)
    tu = db.query(TenantUser).filter(TenantUser.user_id == user_id).first()
    role = tu.role if tu else "member"
    return {
        "id": user_id,
        "tenant_id": payload.get("tenant_id"),
        "client": payload.get("client", "web"),
        "role": role,
    }


def get_current_tenant_id(user: dict = Depends(get_current_user)) -> int:
    tenant_id = user.get("tenant_id")
    if tenant_id is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="缺少租户上下文")
    return tenant_id
