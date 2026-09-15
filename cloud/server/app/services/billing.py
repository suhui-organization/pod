"""Pod Cloud：订阅计费层（支付平台适配器）。

为什么要有这一层：**订阅状态属于我们，支付平台只是"收钱 + 通知"的适配器**。
早期 PSP 平台的分支直接长在路由里（建 Session、验签、改 Subscription 表），
换平台等于改路由和线上行为；而国内个人做海外收款的实际路径是 MoR
（Paddle / Creem / Waffo 这类），payload 形状与 PSP 完全不同。

三条约定：

1. **状态自持**：改 `Subscription` 只发生在 `apply_event()` 一处，
   provider 只负责"收钱"和"把平台事件翻译成我们的内部事件"。
2. **事件先归一**：不同平台的 webhook 字段差别很大，统一成 `BillingEvent`
   之后，上层代码与平台无关。新增平台 = 加一个 Provider 类，不动路由。
3. **未配置就报错，不静默降级**：少配一个 key 必须让人当场看见，
   不能让用户点"升级"之后以为成功了。

当前实现：**Paddle（MoR）**，唯一的计费通道。再接新平台只需实现
`BillingProvider` 协议并注册一行，路由与订阅表都不用动。
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import time
from datetime import datetime, timezone
from dataclasses import dataclass
from typing import Any, Mapping, Protocol

import httpx
from sqlalchemy.orm import Session

from app.config import settings
from app.models import AuditLog, Subscription

logger = logging.getLogger("podcloud.billing")

PLAN_LIMITS = {"free": 3, "pro": 100}

# 计费关闭时，agent 数量不再限制（自托管不该被套餐卡住）
UNLIMITED_AGENTS = 1_000_000


def billing_enabled() -> bool:
    """本部署是否启用计费。

    - `PODCLOUD_BILLING_ENABLED=off` → 关闭（本地/自托管部署的推荐值）
    - `=on` → 强制开启（即使没配好支付通道；结账会明确报"未配置"）
    - `=auto`（默认）→ 看支付通道是否配好：配了就用，没配就关

    为什么默认 auto 而不是 off：已经在跑的实例（配了 Paddle）不该因为升级
    而突然失去收费能力；而没配过的自托管实例天然就是关的。想要确定性行为
    就显式写 on/off。

    provider 名字写错（如 paypal）时返回 True —— 那是"启用了但配错了"，
    必须让 503 带着原因报出来，不能被 auto 悄悄降级成"免费无限"，否则
    运维把支付通道配错、用户白用，谁也不知道。
    """
    setting = (settings.billing_enabled_setting or "auto").lower()
    if setting in ("off", "false", "0", "no"):
        return False
    if setting in ("on", "true", "1", "yes"):
        return True
    try:
        provider = get_provider()
    except BillingConfigError:
        return True
    return bool(provider and provider.is_configured())


def effective_agent_limit(stored_limit: int) -> int:
    """计费关闭时不限量；开启时按套餐。"""
    return stored_limit if billing_enabled() else UNLIMITED_AGENTS

# 内部事件类型（与任何支付平台无关）
EVENT_ACTIVATED = "subscription.activated"
EVENT_CANCELED = "subscription.canceled"


class BillingConfigError(Exception):
    """计费配置缺失或非法。文案直接给用户看。"""


class BillingSignatureError(Exception):
    """webhook 验签失败（或验签所需的密钥没配）。"""


class BillingError(Exception):
    """与支付平台交互失败（网络、鉴权、返回体异常）。"""


@dataclass
class BillingEvent:
    """归一后的计费事件：平台无关，`apply_event` 只看这个。"""

    type: str
    tenant_id: int
    plan: str = "pro"
    provider_customer_id: str = ""
    provider_subscription_id: str = ""
    provider: str = ""
    renews_at: str | None = None


class BillingProvider(Protocol):
    """支付平台适配器。实现这三个方法就能接一个新平台。"""

    name: str

    def is_configured(self) -> bool: ...

    def create_checkout(
        self, *, tenant_id: int, plan: str, email: str, success_url: str, cancel_url: str
    ) -> dict[str, Any]: ...

    def parse_webhook(
        self, payload: bytes, headers: Mapping[str, str]
    ) -> BillingEvent | None: ...


class PaddleProvider:
    """Paddle（MoR）。没有海外主体时的正常路径：Paddle 是法律上的卖家，
    代收全球卡、代算代缴 VAT/GST、开发票、处理拒付，打款走 Wise/Payoneer。

    流程：建/复用 customer → 建 transaction → 把 checkout.url 交给前端跳转
    （Paddle.js overlay）。平台细节全在实现里，路由和订阅表都不感知。
    """

    name = "paddle"
    SANDBOX_BASE = "https://sandbox-api.paddle.com"
    LIVE_BASE = "https://api.paddle.com"
    # Paddle 官方 SDK 的防重放窗口就是 5 秒：本条要求服务器时钟准确
    SIGNATURE_MAX_AGE_SECONDS = 5
    TIMEOUT = 20.0

    @property
    def base_url(self) -> str:
        return self.LIVE_BASE if (settings.paddle_env or "").lower() == "live" else self.SANDBOX_BASE

    def is_configured(self) -> bool:
        return bool(settings.paddle_api_key and settings.paddle_price_pro)

    def _request(self, method: str, path: str, payload: dict | None = None) -> dict:
        url = f"{self.base_url}{path}"
        headers = {
            "Authorization": f"Bearer {settings.paddle_api_key}",
            "Content-Type": "application/json",
        }
        try:
            resp = httpx.request(method, url, json=payload, headers=headers, timeout=self.TIMEOUT)
        except httpx.HTTPError as e:
            raise BillingError(f"连接 Paddle 失败：{e}") from e
        if resp.status_code >= 400:
            # 正文里可能有 Paddle 的具体原因，截断后带给运维，但不回显给终端用户
            raise BillingError(f"Paddle {resp.status_code}：{resp.text[:200]}")
        try:
            return resp.json()
        except ValueError as e:
            raise BillingError("Paddle 返回体不是 JSON") from e

    def _ensure_customer(self, email: str) -> str:
        """复用同邮箱的 customer，避免每次结账都建一个新客户。"""
        if not email:
            raise BillingConfigError("缺少客户邮箱，无法创建 Paddle 结账")
        found = self._request("GET", f"/customers?email={email}")
        for c in found.get("data", []) or []:
            if str(c.get("email", "")).lower() == email.lower() and str(c.get("id", "")).startswith("ctm_"):
                return str(c["id"])
        created = self._request("POST", "/customers", {"email": email})
        cid = str((created.get("data") or {}).get("id", ""))
        if not cid:
            raise BillingError("Paddle 创建客户失败：返回体缺少 id")
        return cid

    def create_checkout(
        self, *, tenant_id: int, plan: str, email: str = "", success_url: str = "", cancel_url: str = ""
    ) -> dict[str, Any]:
        if not self.is_configured():
            raise BillingConfigError(
                "Paddle 未配置：缺少 PADDLE_API_KEY 或 PADDLE_PRICE_PRO"
            )
        if plan != "pro":
            raise BillingConfigError(f"plan={plan} 不需要结账（免费版直接可用）")

        customer_id = self._ensure_customer(email)
        # 注意：**不要**传 `checkout.url` —— 它指的是"收银台页面地址"（必须
        # 是 Paddle 已审核的域名），不是支付成功后的跳转地址。传了会被拒：
        #   transaction_checkout_url_domain_is_not_approved
        # 收银台地址由账号的 default payment link 决定，Paddle 会自动拼上
        # `?_ptxn=txn_...` 返回在 checkout.url 里；成功后跳哪由前端在
        # Paddle.js 里用 settings.successUrl 指定。
        txn = self._request(
            "POST",
            "/transactions",
            {
                "items": [{"price_id": settings.paddle_price_pro, "quantity": 1}],
                "customer_id": customer_id,
                "collection_mode": "automatic",  # 自助结账
                # tenant_id 挂在这里，Paddle 会在订阅与后续事件里原样回传，
                # 这是"钱到账后知道该给谁开通"的唯一凭据
                "custom_data": {"tenant_id": str(tenant_id), "plan": plan},
            },
        )
        data = txn.get("data") or {}
        url = str((data.get("checkout") or {}).get("url") or "")
        if not url:
            raise BillingError("Paddle 未返回 checkout.url")
        return {
            "checkout_url": url,          # 默认支付链接 + ?_ptxn=txn_...（前端页面需加载 Paddle.js）
            "transaction_id": str(data.get("id", "")),
            "success_url": success_url,   # 交给前端在 Paddle.js 里指定支付后跳回哪
            "provider": self.name,
        }

    @staticmethod
    def _parse_signature(header: str) -> tuple[str, str]:
        ts = h1 = ""
        for part in (header or "").split(";"):
            if part.startswith("ts="):
                ts = part[3:].strip()
            elif part.startswith("h1="):
                h1 = part[3:].strip()
        return ts, h1

    def verify_signature(self, payload: bytes, header: str, *, now: float | None = None) -> None:
        """验签：HMAC-SHA256(secret, "ts:rawBody") 与 h1 比对，并拒绝过期时间戳。

        三个容易踩的点（改这段前先读）：
        1. 参与签名的是**原始 body**，不能先 json.loads 再序列化；
        2. HMAC 的 key 是 secret 原文，不做 base64/hex 解码；
        3. 超过 5 秒的时间戳按重放拒绝 —— 所以服务器时钟要准。
        """
        secret = settings.paddle_webhook_secret
        if not secret:
            raise BillingSignatureError("Paddle webhook secret 未配置（PADDLE_WEBHOOK_SECRET）")
        ts, h1 = self._parse_signature(header)
        if not ts or not h1:
            raise BillingSignatureError("webhook 签名无效")
        try:
            ts_int = int(ts)
        except ValueError as e:
            raise BillingSignatureError("webhook 签名无效") from e
        current = time.time() if now is None else now
        if abs(current - ts_int) > self.SIGNATURE_MAX_AGE_SECONDS:
            raise BillingSignatureError("webhook 时间戳超出容差（重放或服务器时钟不同步）")
        expected = hmac.new(secret.encode(), ts.encode() + b":" + payload, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, h1):
            raise BillingSignatureError("webhook 签名无效")

    def _to_event(self, event: dict) -> BillingEvent | None:
        """Paddle 事件 → 内部事件。按**订阅状态**判定，而不是只看事件名：
        `subscription.updated` 既可能在支付成功时来，也可能在取消/逾期时来。"""
        event_type = str(event.get("event_type") or event.get("type") or "")
        if not event_type.startswith("subscription."):
            return None
        data = event.get("data") or {}
        custom = data.get("custom_data") or {}
        try:
            tenant_id = int(str(custom.get("tenant_id") or "0"))
        except ValueError:
            tenant_id = 0
        if not tenant_id:
            return None  # 不是我们发起的订阅（例如后台手工建的），不猜
        common = {
            "tenant_id": tenant_id,
            "provider_customer_id": str(data.get("customer_id") or ""),
            "provider_subscription_id": str(data.get("id") or ""),
            "provider": self.name,
        }
        status = str(data.get("status") or "")
        if event_type == "subscription.canceled" or status == "canceled":
            return BillingEvent(type=EVENT_CANCELED, plan="free", **common)
        if status in ("active", "trialing"):
            return BillingEvent(
                type=EVENT_ACTIVATED,
                plan="pro",
                renews_at=data.get("next_billed_at"),
                **common,
            )
        # past_due / paused / created(draft) 等：不改状态，保留现有权益走宽限期
        return None

    def parse_webhook(self, payload: bytes, headers: Mapping[str, str]) -> BillingEvent | None:
        self.verify_signature(payload, headers.get("paddle-signature", ""))
        try:
            event = json.loads(payload or b"{}")
        except ValueError as e:
            raise BillingSignatureError("webhook 负载不是合法 JSON") from e
        if not isinstance(event, dict):
            return None
        return self._to_event(event)


# 平台注册表：再接平台时在这里加一行（当前：paddle —— 唯一计费通道）
PROVIDERS: dict[str, type] = {
    "paddle": PaddleProvider,
}


def get_provider() -> BillingProvider | None:
    """按 `PODCLOUD_BILLING_PROVIDER` 取当前计费平台；名字不认识则明确报错。"""
    name = (settings.billing_provider or "").strip() or "paddle"
    cls = PROVIDERS.get(name)
    if cls is None:
        raise BillingConfigError(
            f"未知的计费平台：{name}（已实现：{' / '.join(PROVIDERS)}）"
        )
    return cls()


def _audit_actor(db: Session, tenant_id: int) -> int | None:
    """webhook 没有登录用户，把审计挂在租户管理员名下；查不到就跳过留痕。"""
    from app.models import TenantUser

    admin = (
        db.query(TenantUser)
        .filter(TenantUser.tenant_id == tenant_id, TenantUser.role == "admin")
        .first()
    )
    return admin.user_id if admin else None


def apply_event(db: Session, event: BillingEvent) -> Subscription:
    """把归一事件写进订阅状态。**改 Subscription 只在这里发生。**"""
    sub = db.query(Subscription).filter(Subscription.tenant_id == event.tenant_id).first()
    if sub is None:
        sub = Subscription(
            tenant_id=event.tenant_id, plan="free", agent_limit=PLAN_LIMITS["free"]
        )
        db.add(sub)
        db.flush()

    if event.type == EVENT_ACTIVATED:
        plan = event.plan if event.plan in PLAN_LIMITS else "pro"
        sub.plan = plan
        sub.agent_limit = PLAN_LIMITS[plan]
        action = f"subscription.{event.provider}_activated"
    elif event.type == EVENT_CANCELED:
        sub.plan = "free"
        sub.agent_limit = PLAN_LIMITS["free"]
        action = f"subscription.{event.provider}_canceled"
    else:
        raise BillingConfigError(f"未知的计费事件：{event.type}")

    if event.provider:
        sub.billing_provider = event.provider
    if event.provider_customer_id:
        sub.provider_customer_id = event.provider_customer_id
    if event.provider_subscription_id:
        sub.provider_subscription_id = event.provider_subscription_id
    if event.renews_at:
        sub.renews_at = _parse_iso(event.renews_at)

    actor = _audit_actor(db, event.tenant_id)
    if actor is not None:
        db.add(
            AuditLog(
                tenant_id=event.tenant_id,
                user_id=actor,
                action=action,
                detail_json=f'{{"plan": "{sub.plan}", "provider": "{event.provider}"}}',
            )
        )
    else:
        logger.warning(
            "计费事件无管理员可归属，跳过审计 tenant=%s type=%s", event.tenant_id, event.type
        )
    db.commit()
    return sub


def _parse_iso(value: str) -> datetime | None:
    """解析平台的 ISO 时间戳（Paddle 给的是 UTC 带 Z）；失败返回 None。"""
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt.astimezone(timezone.utc).replace(tzinfo=None) if dt.tzinfo else dt
