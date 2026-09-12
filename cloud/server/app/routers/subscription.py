"""Pod Cloud：订阅路由（薄层）。

这里只做三件事：鉴权、把请求转给 `services/billing.py` 的 provider、
把异常翻成 HTTP 状态码。**不在这里碰 Stripe 或任何支付平台的细节** ——
换平台只改 `services/billing.py`，不改路由。

- GET  /subscription            当前套餐与用量
- POST /subscription/checkout   建结账会话，返回 checkout_url
- POST /subscription/webhook    接收平台事件（验签后统一 apply）
- POST /subscription/plan       免支付切换（**默认只在 dev 开启**，见 config）
"""

import logging

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.dependencies import require_admin
from app.models import Agent, AuditLog, Subscription, User
from app.security import get_current_tenant_id, get_current_user
from app.services import billing
from app.services.billing import PLAN_LIMITS

logger = logging.getLogger("podcloud.subscription")

router = APIRouter(prefix="/subscription", tags=["subscription"])


class SubscriptionUpdateRequest(BaseModel):
    plan: str = Field(pattern="^(free|pro)$")


class CheckoutRequest(BaseModel):
    plan: str = Field(default="pro", pattern="^(free|pro)$")


def _get_or_create(db: Session, tenant_id: int) -> Subscription:
    sub = db.query(Subscription).filter(Subscription.tenant_id == tenant_id).first()
    if sub is None:
        sub = Subscription(tenant_id=tenant_id, plan="free", agent_limit=PLAN_LIMITS["free"])
        db.add(sub)
        db.commit()
        db.refresh(sub)
    return sub


@router.get("")
def get_subscription(db: Session = Depends(get_db), tenant_id: int = Depends(get_current_tenant_id)):
    sub = _get_or_create(db, tenant_id)
    agent_count = db.query(Agent).filter(Agent.tenant_id == tenant_id).count()
    try:
        provider = billing.get_provider()
        provider_name = provider.name if provider else ""
        configured = bool(provider and provider.is_configured())
    except billing.BillingConfigError:
        provider_name, configured = "", False
    return {
        "plan": sub.plan,
        # 计费关闭时返回不限量口径（前端据此显示"不限"而不是"3 个"）
        "agent_limit": billing.effective_agent_limit(sub.agent_limit),
        "agent_count": agent_count,
        "renews_at": sub.renews_at.isoformat() if sub.renews_at else None,
        # 本部署是否启用计费：false = 自托管，没有付费入口也不限 agent 数
        "billing_enabled": billing.billing_enabled(),
        # 保留旧字段名（前端在用）；语义 = "支付通道可用"
        "stripe_configured": configured,
        "billing_provider": provider_name,
        "billing_configured": configured,
        # Paddle Checkout 跑在**我们自己页面**上（Paddle.js overlay），不是托管页，
        # 所以前端需要 client-side token 才能弹收银台。它是公开值，可以下发给浏览器。
        "paddle_client_token": settings.paddle_client_token if provider_name == "paddle" else "",
        "paddle_environment": (settings.paddle_env or "sandbox").lower(),
    }


@router.post("/checkout")
def create_checkout(
    body: CheckoutRequest,
    db: Session = Depends(get_db),
    tenant_id: int = Depends(get_current_tenant_id),
    user: dict = Depends(get_current_user),
):
    """创建结账会话；返回 checkout_url 供前端跳转。"""
    require_admin(db, tenant_id, user)
    if not billing.billing_enabled():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="本部署未启用计费（自托管模式）：所有功能可用且不限 agent 数，无需订阅",
        )
    try:
        provider = billing.get_provider()
    except billing.BillingConfigError as e:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(e)) from e
    if provider is None or not provider.is_configured():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="支付通道未开通：请联系我们开通后升级（当前套餐能力不受影响）",
        )
    base = settings.public_base_url
    # Paddle 需要客户邮箱来建/复用 customer（Stripe 不需要，但签名统一）
    row = db.query(User).filter(User.id == user["id"]).first()
    try:
        return provider.create_checkout(
            tenant_id=tenant_id,
            plan=body.plan,
            email=(row.email if row else "") or "",
            success_url=f"{base}/subscription?status=success",
            cancel_url=f"{base}/subscription?status=cancelled",
        )
    except billing.BillingConfigError as e:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(e)) from e
    except billing.BillingError as e:
        logger.warning("创建结账会话失败 tenant=%s provider=%s: %s", tenant_id, provider.name, e)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY, detail="支付平台暂时不可用，请稍后重试"
        ) from e


@router.post("/webhook")
async def billing_webhook(request: Request, db: Session = Depends(get_db)):
    """接收支付平台事件：验签 → 归一 → 落订阅状态。

    验签所需的密钥缺失或签名不对一律 400；无法识别的事件正常 200 并标记 ignored
    （否则平台会一直重试）。
    """
    # 注意：这里**故意不受计费开关限制**。关掉计费 = 不再卖新订阅，
    # 而不是"抹掉已经发生的交易"——已订阅客户的续费/取消事件仍要能落库，
    # 否则订阅状态会永远停在旧值，而且支付平台会因 404 一直重试。
    try:
        provider = billing.get_provider()
    except billing.BillingConfigError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)) from e
    if provider is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="未配置计费平台")

    payload = await request.body()
    try:
        event = provider.parse_webhook(payload, request.headers)
    except billing.BillingSignatureError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)) from e

    if event is None:
        return {"received": True, "type": "ignored"}
    billing.apply_event(db, event)
    return {"received": True, "type": event.type}


@router.post("/plan")
def update_plan(
    body: SubscriptionUpdateRequest,
    db: Session = Depends(get_db),
    tenant_id: int = Depends(get_current_tenant_id),
    user: dict = Depends(get_current_user),
):
    """免支付切换套餐。

    默认只在 dev 开启（`PODCLOUD_ALLOW_PLAN_SWITCH`）。非 dev 环境下
    **只保留降级路径**：升级必须走 checkout，否则任何注册用户都能白拿 pro。
    """
    require_admin(db, tenant_id, user)
    if not settings.allow_plan_switch and body.plan != "free":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="免支付升级已关闭：请通过订阅结账升级（POST /subscription/checkout）",
        )
    sub = _get_or_create(db, tenant_id)
    sub.plan = body.plan
    sub.agent_limit = PLAN_LIMITS[body.plan]
    db.add(
        AuditLog(
            tenant_id=tenant_id,
            user_id=user["id"],
            action="subscription.change",
            detail_json=f'{{"plan": "{body.plan}", "self_service": true}}',
        )
    )
    db.commit()
    return {"plan": sub.plan, "agent_limit": sub.agent_limit}
