"""一键自检 / 自修复：检查项齐全、真能修、权限与语言都对。"""

from datetime import datetime, timedelta

from tests.conftest import register_and_login


def _headers(token: str, locale: str | None = None) -> dict:
    h = {"Authorization": f"Bearer {token}"}
    if locale:
        h["Accept-Language"] = locale
    return h


def _run(client, token, repair=False, locale=None):
    return client.post(
        "/api/v1/selfcheck/run",
        json={"repair": repair},
        headers=_headers(token, locale),
    )


def test_run_returns_every_check_with_summary(client):
    token = register_and_login(client)
    r = _run(client, token)
    assert r.status_code == 200
    body = r.json()
    ids = [c["id"] for c in body["checks"]]
    assert ids == [
        "database",
        "write",
        "secret",
        "tenant",
        "agents",
        "chain",
        "policies",
        "llm",
        "mail",
        "billing",
    ]
    assert all(c["status"] in ("pass", "warn", "fail") for c in body["checks"])
    assert all(c["detail"] for c in body["checks"])  # 不允许空话式"请稍后再试"
    s = body["summary"]
    assert s["pass"] + s["warn"] + s["fail"] == len(body["checks"])
    assert s["repaired"] == 0 and body["repairs"] == []

    # 没有 agent / 没配模型的新租户：这两条要如实反映出来（而不是一律 pass）
    by_id = {c["id"]: c for c in body["checks"]}
    assert by_id["agents"]["status"] == "warn"
    assert by_id["llm"]["status"] == "warn"
    assert by_id["database"]["status"] == "pass"
    assert by_id["write"]["status"] == "pass"


def test_repair_creates_missing_rows_and_fixes_agent_status(client, db):
    from app.models import Agent, Subscription, TenantSettings

    token = register_and_login(client)
    agent = client.post("/api/v1/agents", json={"name": "codex"}, headers=_headers(token)).json()["agent"]

    # 伪造三种"脏状态"：状态与心跳不一致、设置行缺失、订阅行缺失
    row = db.query(Agent).filter(Agent.id == agent["id"]).one()
    row.status = "online"
    row.last_seen_at = datetime.utcnow() - timedelta(days=3)
    db.query(TenantSettings).delete()
    db.query(Subscription).delete()
    db.commit()

    r = _run(client, token, repair=True)
    assert r.status_code == 200
    body = r.json()
    joined = " | ".join(body["repairs"])
    assert "已补默认行" in joined
    assert "已补免费计划行" in joined
    assert "在线状态与心跳不一致" in joined
    assert body["summary"]["repaired"] == 3

    db.expire_all()
    assert db.query(Agent).filter(Agent.id == agent["id"]).one().status == "offline"
    assert db.query(TenantSettings).filter(TenantSettings.tenant_id == 1).first() is not None
    assert db.query(Subscription).filter(Subscription.tenant_id == 1).first() is not None
    # 修完的条目要打上"已修复"，且 agents 检查不再因为状态问题报警
    by_id = {c["id"]: c for c in body["checks"]}
    assert by_id["agents"]["repaired"] is True
    assert by_id["tenant"]["repaired"] is False


def test_repair_cleans_dangling_membership(client, db):
    from app.models import TenantUser

    token = register_and_login(client)
    db.add(TenantUser(tenant_id=1, user_id=99999, role="member"))
    db.commit()

    before = _run(client, token).json()
    by_id = {c["id"]: c for c in before["checks"]}
    assert by_id["tenant"]["status"] == "warn"
    assert by_id["tenant"]["repairable"] is True

    after = _run(client, token, repair=True).json()
    assert any("point" in r or "成员" in r for r in after["repairs"])
    assert db.query(TenantUser).filter(TenantUser.user_id == 99999).first() is None


def test_run_is_admin_only(client):
    admin = register_and_login(client, "boss@x.com")
    client.post(
        "/api/v1/admin/users",
        json={"email": "staff@x.com", "password": "staffpass123", "role": "member"},
        headers=_headers(admin),
    )
    member = client.post(
        "/api/v1/auth/login", json={"email": "staff@x.com", "password": "staffpass123"}
    ).json()["access_token"]
    assert _run(client, member).status_code == 403
    assert _run(client, admin).status_code == 200


def test_texts_follow_accept_language(client):
    token = register_and_login(client)
    en = _run(client, token, locale="en-US").json()
    titles = [c["title"] for c in en["checks"]]
    assert "Database connection and schema" in titles
    assert "Agent gateways and heartbeats" in titles
    assert en["locale"] == "en-US"

    zh = _run(client, token, locale="zh-CN").json()
    assert any(c["title"] == "数据库连接与表结构" for c in zh["checks"])
