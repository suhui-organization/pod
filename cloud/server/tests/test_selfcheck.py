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
    assert all(c["status"] in ("pass", "warn", "fail", "info") for c in body["checks"])
    assert all(c["detail"] for c in body["checks"])  # 不允许空话式"请稍后再试"
    s = body["summary"]
    assert s["pass"] + s["warn"] + s["fail"] + s["info"] == len(body["checks"])
    assert s["repaired"] == 0 and body["repairs"] == []

    # 没有 agent / 没配模型的新租户：这两条要如实反映出来（而不是一律 pass）
    by_id = {c["id"]: c for c in body["checks"]}
    assert by_id["agents"]["status"] == "warn"
    # 没配模型不是故障：自托管可以不启用任何 AI 功能。标 info —— 不计入警告/失败、
    # 不进告警列表、不推通知，只在页面上说明"要用 AI 去哪儿配"。
    assert by_id["llm"]["status"] == "info"
    assert by_id["llm"]["hint"]
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


# ── 模型没配 / 配了不通 / 某检查自己炸了：三种情况的策略 ────────────────────


def test_unconfigured_model_is_info_not_a_problem(client, db):
    """没配模型 = 没启用可选功能，不是故障：不报警、不进告警列表、不推通知。"""
    from app.models import PodAlert

    token = register_and_login(client)
    body = _run(client, token).json()
    llm = next(c for c in body["checks"] if c["id"] == "llm")
    assert llm["status"] == "info"
    assert body["summary"]["info"] >= 1
    # 注意：测试环境的 JWT 密钥就是默认值，所以「签名密钥强度」这项会 fail —— 与本用例无关，
    # 这里只断言"模型没配"没有制造失败，也没有制造告警。
    assert not [
        a for a in db.query(PodAlert).filter(PodAlert.kind == "selfcheck").all() if a.message.startswith("大模型")
    ]
    assert all(not c["id"] == "llm" for c in body["checks"] if c["status"] == "fail")
    # 其余 9 项照常给出结论 —— 模型没配不影响自检本身
    assert len(body["checks"]) == 10
    assert body["summary"]["pass"] >= 5


def test_configured_but_broken_model_is_a_failure(client, db, monkeypatch):
    """配了却调不通才是 fail：说明"说好要用却用不了"，进告警列表。"""
    from app.models import PodAlert, TenantSettings
    from app.services import selfcheck as selfcheck_service

    db.add(
        TenantSettings(
            tenant_id=1, provider="custom", base_url="http://127.0.0.1:9/v1", model="m", api_key="k"
        )
    )
    db.commit()
    monkeypatch.setattr(
        selfcheck_service.llm,
        "test_connection",
        lambda cfg: {"ok": False, "provider": cfg.provider, "model": cfg.model, "error": "连接模型端点失败：Connection refused", "latency_ms": 1},
    )
    token = register_and_login(client)
    body = _run(client, token).json()
    llm = next(c for c in body["checks"] if c["id"] == "llm")
    assert llm["status"] == "fail"
    assert "Connection refused" in llm["detail"]
    # 只断言"模型这条"建了告警（测试环境里签名密钥也会 fail 并建一条，那条与本用例无关）
    model_alerts = [a for a in db.query(PodAlert).filter(PodAlert.kind == "selfcheck").all() if a.message.startswith("大模型")]
    assert len(model_alerts) == 1
    # 模型挂了，其余检查照样跑完并给结论
    assert len(body["checks"]) == 10


def test_one_broken_check_does_not_kill_the_run(client, db, monkeypatch):
    """某一项自己抛异常，只让那一项变红，其余 9 项照样出结论（整轮不能 500）。"""
    from app.services import selfcheck as selfcheck_service

    def boom(*a, **k):
        raise RuntimeError("模拟这项检查自己炸了")

    monkeypatch.setattr(selfcheck_service, "_check_chain", boom)
    token = register_and_login(client)
    r = _run(client, token)
    assert r.status_code == 200, "单项异常不能把整轮自检变成 500"
    body = r.json()
    assert len(body["checks"]) == 10
    chain = next(c for c in body["checks"] if c["id"] == "chain")
    assert chain["status"] == "fail" and "自身出错" in chain["detail"]
    # 排在它后面的项也跑到了（不是"抛异常就中断"）
    assert next(c for c in body["checks"] if c["id"] == "billing")["status"] in ("pass", "warn", "fail", "info")


def test_self_repair_needs_no_model_at_all(client, db, monkeypatch):
    """自愈能力不依赖大模型：一个模型都没配，该修的照样修。

    这条是给"AI 用不了的时候系统还救不救得回来"这个疑问上锁：
    把模型调用换成"一旦被调用就爆炸"，再制造三处脏状态（agent 状态与心跳不符、
    缺租户设置行、缺订阅行），自检并修复之后三类问题都要被修掉。
    """
    from app.models import Agent, Subscription, TenantSettings
    from app.services import selfcheck as selfcheck_service

    token = register_and_login(client)
    assert db.query(TenantSettings).filter(TenantSettings.tenant_id == 1).first() is None  # 没配模型
    db.add(
        Agent(
            tenant_id=1,
            name="dirty-agent",
            platform="codex",
            status="online",
            last_seen_at=datetime.utcnow() - timedelta(days=3),
        )
    )
    db.commit()
    db.query(TenantSettings).delete()
    db.query(Subscription).delete()
    db.commit()

    def must_not_call(*a, **k):
        raise AssertionError("自愈路径不该调用大模型")

    monkeypatch.setattr(selfcheck_service.llm, "test_connection", must_not_call)

    body = _run(client, token, repair=True).json()
    repairs = " | ".join(body["repairs"])
    assert "在线状态与心跳不一致" in repairs, repairs
    assert "已补默认行" in repairs, repairs
    assert "已补免费计划行" in repairs, repairs
    db.expire_all()
    assert db.query(Agent).filter(Agent.name == "dirty-agent").one().status == "offline"
    assert db.query(TenantSettings).filter(TenantSettings.tenant_id == 1).first() is not None
    assert db.query(Subscription).filter(Subscription.tenant_id == 1).first() is not None
    # 模型那一项如实标"未配置"，不影响上面这些修复
    assert next(c for c in body["checks"] if c["id"] == "llm")["status"] == "info"
