"""Pod Cloud 订阅与计费层测试（monkeypatch stripe，不依赖真实账号）。

分层后：路由只做鉴权与状态码，平台细节在 services/billing.py。
所以这里除了路由行为，还直接测事件归一与 apply_event。
"""

from types import SimpleNamespace

import pytest

from app.config import settings
from app.services import billing

from tests.conftest import register_and_login  # noqa: F401


class FakeSession:
    url = "https://checkout.stripe.com/c/pay/cs_test_123"
    id = "cs_test_123"


class FakeCheckoutSessions:
    def __init__(self):
        self.last_kwargs = None

    def create(self, **kwargs):
        self.last_kwargs = kwargs
        return FakeSession()


class FakeClient:
    def __init__(self):
        self.checkout = SimpleNamespace(sessions=FakeCheckoutSessions())


@pytest.fixture()
def fake_stripe(monkeypatch):
    """配置 Stripe key + 注入 fake 客户端，返回 fake client 供断言。"""
    monkeypatch.setattr(settings, "stripe_secret_key", "sk_test_fake")
    monkeypatch.setattr(settings, "stripe_price_pro", "price_pro_123")
    monkeypatch.setattr(settings, "stripe_price_free", "")
    fake = FakeClient()
    monkeypatch.setattr(billing.StripeProvider, "_client", lambda self: fake)
    return fake


def test_checkout_without_stripe_returns_503(client):
    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(settings, "stripe_secret_key", "")
    token = register_and_login(client)
    r = client.post(
        "/api/v1/subscription/checkout",
        json={"plan": "pro"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 503
    monkeypatch.undo()


def test_plan_switch_disabled_outside_dev(client, monkeypatch):
    """非 dev 环境：升级必须走结账，降级仍然自助。"""
    monkeypatch.setattr(settings, "allow_plan_switch", False)
    token = register_and_login(client)
    headers = {"Authorization": f"Bearer {token}"}

    blocked = client.post("/api/v1/subscription/plan", json={"plan": "pro"}, headers=headers)
    assert blocked.status_code == 403
    assert "免支付升级已关闭" in blocked.json()["error"]["message"]

    # 降级路径保留
    assert client.post("/api/v1/subscription/plan", json={"plan": "free"}, headers=headers).status_code == 200


def test_unknown_billing_provider_is_loud(client, monkeypatch):
    """配错平台名要明确报错，不能静默当成 Stripe。"""
    monkeypatch.setattr(settings, "billing_provider", "paypal")
    token = register_and_login(client)
    headers = {"Authorization": f"Bearer {token}"}

    # 读取接口不炸：只报"不可用"
    body = client.get("/api/v1/subscription", headers=headers).json()
    assert body["billing_configured"] is False

    r = client.post("/api/v1/subscription/checkout", json={"plan": "pro"}, headers=headers)
    assert r.status_code == 503
    assert "未知的计费平台" in r.json()["error"]["message"]


def test_parse_webhook_ignores_unknown_events(monkeypatch):
    """不关心的事件返回 None（路由回 ignored 200），否则平台会一直重试。"""
    import stripe

    monkeypatch.setattr(settings, "stripe_webhook_secret", "whsec_test")
    monkeypatch.setattr(
        stripe.Webhook,
        "construct_event",
        lambda payload, sig, secret: {"type": "invoice.paid", "data": {"object": {}}},
    )
    assert billing.StripeProvider().parse_webhook(b"{}", {"stripe-signature": "x"}) is None


def test_billing_event_normalized_to_internal_types(monkeypatch):
    """平台字段 → 内部事件：换平台时上层不用改。"""
    import stripe

    monkeypatch.setattr(settings, "stripe_webhook_secret", "whsec_test")
    monkeypatch.setattr(
        stripe.Webhook,
        "construct_event",
        lambda payload, sig, secret: {
            "type": "checkout.session.completed",
            "data": {
                "object": {
                    "client_reference_id": "7",
                    "metadata": {"plan": "pro"},
                    "customer": "cus_1",
                }
            },
        },
    )
    ev = billing.StripeProvider().parse_webhook(b"{}", {"stripe-signature": "x"})
    assert ev.type == billing.EVENT_ACTIVATED
    assert ev.tenant_id == 7 and ev.plan == "pro" and ev.provider == "stripe"


def test_apply_event_writes_subscription_once(client, db):
    """状态自持：apply_event 是唯一改订阅的地方。"""
    register_and_login(client)  # 造出 tenant 1 + 管理员
    ev = billing.BillingEvent(
        type=billing.EVENT_ACTIVATED, tenant_id=1, plan="pro", provider="stripe"
    )
    sub = billing.apply_event(db, ev)
    assert (sub.plan, sub.agent_limit) == ("pro", 100)

    ev2 = billing.BillingEvent(type=billing.EVENT_CANCELED, tenant_id=1, provider="stripe")
    sub2 = billing.apply_event(db, ev2)
    assert (sub2.plan, sub2.agent_limit) == ("free", 3)


def test_checkout_creates_session_with_correct_params(client, fake_stripe):
    token = register_and_login(client)
    r = client.post(
        "/api/v1/subscription/checkout",
        json={"plan": "pro"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["checkout_url"].startswith("https://checkout.stripe.com")
    kwargs = fake_stripe.checkout.sessions.last_kwargs
    assert kwargs["mode"] == "subscription"
    assert kwargs["line_items"] == [{"price": "price_pro_123", "quantity": 1}]
    assert kwargs["metadata"]["plan"] == "pro"
    assert kwargs["client_reference_id"]  # tenant id


def test_webhook_without_secret_rejected(client):
    token = register_and_login(client)
    r = client.post(
        "/api/v1/subscription/webhook",
        json={"type": "checkout.session.completed", "data": {"object": {}}},
        headers={"Authorization": f"Bearer {token}", "stripe-signature": "sig"},
    )
    assert r.status_code == 400


def test_webhook_checkout_completed_upgrades_subscription(client, monkeypatch):
    token = register_and_login(client)
    monkeypatch.setattr(settings, "stripe_webhook_secret", "whsec_test")

    def fake_construct(payload, sig, secret):
        assert secret == "whsec_test"
        return {
            "type": "checkout.session.completed",
            "data": {
                "object": {
                    "client_reference_id": "1",
                    "metadata": {"tenant_id": "1", "plan": "pro"},
                    "customer": "cus_test_abc",
                }
            },
        }

    import stripe

    monkeypatch.setattr(stripe.Webhook, "construct_event", fake_construct)
    r = client.post(
        "/api/v1/subscription/webhook",
        json={},  # payload 由 fake_construct 忽略
        headers={"stripe-signature": "t=1,v1=fake"},
    )
    assert r.status_code == 200
    # 订阅已升级
    r2 = client.get("/api/v1/subscription", headers={"Authorization": f"Bearer {token}"})
    assert r2.json()["plan"] == "pro"
    assert r2.json()["agent_limit"] == 100


def test_webhook_subscription_deleted_downgrades(client, monkeypatch):
    token = register_and_login(client)
    monkeypatch.setattr(settings, "stripe_webhook_secret", "whsec_test")

    # 先升级
    client.post("/api/v1/subscription/plan", json={"plan": "pro"}, headers={"Authorization": f"Bearer {token}"})

    def fake_construct(payload, sig, secret):
        return {
            "type": "customer.subscription.deleted",
            "data": {"object": {"metadata": {"tenant_id": "1"}}},
        }

    import stripe

    monkeypatch.setattr(stripe.Webhook, "construct_event", fake_construct)
    r = client.post(
        "/api/v1/subscription/webhook",
        json={},
        headers={"stripe-signature": "t=1,v1=fake"},
    )
    assert r.status_code == 200
    r2 = client.get("/api/v1/subscription", headers={"Authorization": f"Bearer {token}"})
    assert r2.json()["plan"] == "free"
    assert r2.json()["agent_limit"] == 3


def test_invalid_webhook_signature_rejected(client, monkeypatch):
    token = register_and_login(client)
    monkeypatch.setattr(settings, "stripe_webhook_secret", "whsec_test")

    import stripe

    def bad_construct(payload, sig, secret):
        raise ValueError("bad signature")

    monkeypatch.setattr(stripe.Webhook, "construct_event", bad_construct)
    r = client.post(
        "/api/v1/subscription/webhook",
        json={},
        headers={"stripe-signature": "t=1,v1=forged"},
    )
    assert r.status_code == 400
    assert "签名无效" in r.json()["error"]["message"]


# ── Paddle（MoR）────────────────────────────────────────────────────────────


def _sign(secret: str, body: bytes, ts: int | None = None) -> str:
    """按 Paddle 口径签名：HMAC-SHA256(secret, "ts:rawBody")。"""
    import hashlib
    import hmac
    import time as _t

    stamp = str(ts if ts is not None else int(_t.time()))
    mac = hmac.new(secret.encode(), stamp.encode() + b":" + body, hashlib.sha256).hexdigest()
    return f"ts={stamp};h1={mac}"


@pytest.fixture()
def paddle(monkeypatch):
    """配置 Paddle（sandbox）。出网由各用例自己 monkeypatch。"""
    monkeypatch.setattr(settings, "billing_provider", "paddle")
    monkeypatch.setattr(settings, "paddle_api_key", "pdl_sdbx_apikey_test")
    monkeypatch.setattr(settings, "paddle_price_pro", "pri_test_pro")
    monkeypatch.setattr(settings, "paddle_webhook_secret", "ntfset_test_secret")
    monkeypatch.setattr(settings, "paddle_env", "sandbox")
    return billing.PaddleProvider()


def test_paddle_unconfigured_is_loud(monkeypatch):
    monkeypatch.setattr(settings, "paddle_api_key", "")
    monkeypatch.setattr(settings, "paddle_price_pro", "")
    p = billing.PaddleProvider()
    assert p.is_configured() is False
    with pytest.raises(billing.BillingConfigError):
        p.create_checkout(tenant_id=1, plan="pro", email="a@b.com")


def test_paddle_sandbox_is_the_default_base_url(monkeypatch):
    """默认打 sandbox：配错也只是测试环境，不会误扣真钱。"""
    monkeypatch.setattr(settings, "paddle_env", "sandbox")
    assert billing.PaddleProvider().base_url == "https://sandbox-api.paddle.com"
    monkeypatch.setattr(settings, "paddle_env", "live")
    assert billing.PaddleProvider().base_url == "https://api.paddle.com"


class _Resp:
    def __init__(self, data):
        self.status_code = 200
        self._data = data
        self.text = "{}"

    def json(self):
        return self._data


def test_paddle_create_checkout_creates_customer_and_transaction(paddle, monkeypatch):
    calls = []

    def fake_request(method, url, json=None, headers=None, timeout=None):
        calls.append((method, url, json))
        assert headers["Authorization"].startswith("Bearer pdl_sdbx_")
        if method == "GET" and "/customers" in url:
            return _Resp({"data": []})
        if method == "POST" and url.endswith("/customers"):
            return _Resp({"data": {"id": "ctm_new"}})
        if method == "POST" and url.endswith("/transactions"):
            return _Resp({"data": {"id": "txn_1", "checkout": {"url": "https://pay.paddle.io/x"}}})
        raise AssertionError(f"未预期的请求 {method} {url}")

    monkeypatch.setattr(billing.httpx, "request", fake_request)
    out = paddle.create_checkout(
        tenant_id=42, plan="pro", email="ops@example.com", success_url="https://app/ok"
    )
    assert out["checkout_url"] == "https://pay.paddle.io/x"
    assert out["provider"] == "paddle"
    txn = [c for c in calls if c[1].endswith("/transactions")][0][2]
    assert txn["items"] == [{"price_id": "pri_test_pro", "quantity": 1}]
    assert txn["customer_id"] == "ctm_new"
    # 不能传 checkout.url：Paddle 会要求该域名已审核，而收银台地址本来就由
    # 账号的 default payment link 决定（Paddle 自动拼 ?_ptxn=）
    assert "checkout" not in txn
    # tenant_id 是"钱到账后知道给谁开通"的唯一凭据，必须带出去
    assert txn["custom_data"]["tenant_id"] == "42"


def test_paddle_reuses_existing_customer(paddle, monkeypatch):
    calls = []

    def fake_request(method, url, json=None, headers=None, timeout=None):
        calls.append((method, url))
        if method == "GET":
            return _Resp({"data": [{"id": "ctm_existing", "email": "Ops@Example.com"}]})
        if url.endswith("/transactions"):
            return _Resp({"data": {"id": "txn_1", "checkout": {"url": "https://pay.paddle.io/x"}}})
        raise AssertionError("不该再建新客户")

    monkeypatch.setattr(billing.httpx, "request", fake_request)
    paddle.create_checkout(tenant_id=1, plan="pro", email="ops@example.com")
    assert not any(m == "POST" and u.endswith("/customers") for m, u in calls)


def _paddle_event(event_type: str, **sub) -> dict:
    data = {
        "id": "sub_1",
        "customer_id": "ctm_1",
        "status": "active",
        "custom_data": {"tenant_id": "1", "plan": "pro"},
        "next_billed_at": "2026-10-11T12:00:00.000000Z",
    }
    data.update(sub)
    return {"event_id": "evt_1", "event_type": event_type, "data": data}


def test_paddle_webhook_signature_and_event_mapping(paddle, db):
    """签名正确 → 归一成 activated；tenant 从 custom_data 读回。"""
    import json

    payload = json.dumps(_paddle_event("subscription.created")).encode()
    ev = paddle.parse_webhook(payload, {"paddle-signature": _sign("ntfset_test_secret", payload)})
    assert ev.type == billing.EVENT_ACTIVATED
    assert ev.tenant_id == 1 and ev.plan == "pro"
    assert ev.provider_subscription_id == "sub_1"
    assert ev.renews_at == "2026-10-11T12:00:00.000000Z"

    sub = billing.apply_event(db, ev)
    assert (sub.plan, sub.agent_limit) == ("pro", 100)
    assert sub.billing_provider == "paddle"
    assert sub.provider_subscription_id == "sub_1"
    assert sub.renews_at is not None


def test_paddle_webhook_rejects_tampered_and_stale(paddle):
    import json

    payload = json.dumps(_paddle_event("subscription.created")).encode()
    good = _sign("ntfset_test_secret", payload)
    with pytest.raises(billing.BillingSignatureError):  # body 被改
        paddle.parse_webhook(payload + b" ", {"paddle-signature": good})
    with pytest.raises(billing.BillingSignatureError):  # 用错 secret
        paddle.parse_webhook(payload, {"paddle-signature": _sign("wrong_secret", payload)})
    stale = _sign("ntfset_test_secret", payload, ts=1)  # 过期时间戳（重放）
    with pytest.raises(billing.BillingSignatureError):
        paddle.parse_webhook(payload, {"paddle-signature": stale})


def test_paddle_event_mapping_edges(paddle):
    import json

    def parse(event):
        payload = json.dumps(event).encode()
        return paddle.parse_webhook(
            payload, {"paddle-signature": _sign("ntfset_test_secret", payload)}
        )

    assert parse(_paddle_event("subscription.canceled", status="canceled")).type == billing.EVENT_CANCELED
    # 逾期不改状态（保留宽限期），交给后续事件决定
    assert parse(_paddle_event("subscription.updated", status="past_due")) is None
    # 不是我们发起的订阅（没有 custom_data）→ 不猜
    assert parse(_paddle_event("subscription.created", custom_data={})) is None
    # 无关事件 → 忽略（否则 Paddle 会一直重试）
    assert parse({"event_type": "transaction.completed", "data": {}}) is None


def test_paddle_end_to_end_via_router(client, paddle):
    """整条链路：Paddle 回调 → 验签 → 归一 → 租户升到 pro。"""
    import json

    token = register_and_login(client)
    payload = json.dumps(_paddle_event("subscription.activated")).encode()
    r = client.post(
        "/api/v1/subscription/webhook",
        content=payload,
        headers={"paddle-signature": _sign("ntfset_test_secret", payload)},
    )
    assert r.status_code == 200
    assert r.json()["type"] == billing.EVENT_ACTIVATED
    info = client.get("/api/v1/subscription", headers={"Authorization": f"Bearer {token}"}).json()
    assert info["plan"] == "pro" and info["agent_limit"] == 100


def test_paddle_bad_signature_via_router_is_400(client, paddle):
    import json

    payload = json.dumps(_paddle_event("subscription.created")).encode()
    r = client.post(
        "/api/v1/subscription/webhook",
        content=payload,
        headers={"paddle-signature": "ts=1;h1=deadbeef"},
    )
    assert r.status_code == 400
    assert "签名" in r.json()["error"]["message"] or "时间戳" in r.json()["error"]["message"]
