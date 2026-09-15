"""每日巡检 + 失败告警：按自然日幂等、失败才推、走租户已配的通知渠道。"""

from datetime import datetime, timedelta

from app.config import settings
from app.models import Agent, PodAlert, SelfCheckRun, TenantSettings
from app.services import selfcheck_scheduler

from tests.conftest import register_and_login


def _headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _capture_notifications(monkeypatch):
    """拦下两个通知出口，返回收集到的调用。"""
    sent: list[tuple[str, list[dict]]] = []
    monkeypatch.setattr(
        selfcheck_scheduler, "notify_async", lambda cfg, items: sent.append(("webhook", items))
    )
    monkeypatch.setattr(
        selfcheck_scheduler, "email_async", lambda cfg, items: sent.append(("email", items))
    )
    return sent


def test_daily_round_runs_once_per_day_and_persists(client, db):
    register_and_login(client, "a@b.com")
    register_and_login(client, "c@d.com")  # 第二个租户：从没打开过设置页

    ran = selfcheck_scheduler.run_daily_round(db)
    assert sorted(ran) == [1, 2]
    assert db.query(SelfCheckRun).filter(SelfCheckRun.trigger == "daily").count() == 2

    # 同一天再跑：幂等，不重复巡检、不重复告警
    assert selfcheck_scheduler.run_daily_round(db) == []
    assert db.query(SelfCheckRun).filter(SelfCheckRun.trigger == "daily").count() == 2

    # 换一天再跑：继续巡检
    tomorrow = datetime.now(selfcheck_scheduler.PUSH_TZ) + timedelta(days=1)
    assert sorted(selfcheck_scheduler.run_daily_round(db, tomorrow)) == [1, 2]


def test_daily_round_alerts_on_failure_only(client, db, monkeypatch):
    register_and_login(client)
    row = db.query(TenantSettings).filter(TenantSettings.tenant_id == 1).first()
    if row is None:
        row = TenantSettings(tenant_id=1)
        db.add(row)
    row.alert_webhook_json = '{"enabled": true, "channel": "wecom", "url": "https://hook.example/x"}'
    db.commit()
    sent = _capture_notifications(monkeypatch)

    selfcheck_scheduler.run_daily_round(db)

    runs = db.query(SelfCheckRun).all()
    assert len(runs) == 1
    summary = selfcheck_scheduler.selfcheck_service.serialize_run(runs[0])["summary"]
    # 测试环境的 JWT 密钥就是默认值 → 「签名密钥强度」必然 fail，这条链路才有东西可推
    assert summary["fail"] >= 1

    assert len(sent) == 1 and sent[0][0] == "webhook"
    items = sent[0][1]
    assert items[0]["message"].startswith("每日自检：")
    # 时间必须是"带时区标签的本地时间"：存库是 UTC，但给人看的这行要能对上墙上的钟
    assert "北京时间" in items[0]["message"]
    assert items[0]["ts"].endswith("+00:00")
    assert any(i["kind"] == "selfcheck" and i["severity"] == "high" for i in items[1:])
    # warn 默认不推：SMTP/模型未配这类"能更好"不该半夜吵人
    assert all(i["severity"] == "high" for i in items)


def test_notify_all_includes_warnings(client, db, monkeypatch):
    register_and_login(client)
    monkeypatch.setattr(settings, "selfcheck_notify", "all")
    sent = _capture_notifications(monkeypatch)
    db.add(TenantSettings(tenant_id=1, alert_webhook_json='{"url": "https://hook.example/x"}'))
    db.commit()

    selfcheck_scheduler.run_daily_round(db)
    items = sent[0][1]
    assert any(i["severity"] == "medium" for i in items)


def test_notify_off_silences_everything(client, db, monkeypatch):
    register_and_login(client)
    monkeypatch.setattr(settings, "selfcheck_notify", "off")
    sent = _capture_notifications(monkeypatch)
    db.add(TenantSettings(tenant_id=1, alert_webhook_json='{"url": "https://hook.example/x"}'))
    db.commit()

    assert selfcheck_scheduler.run_daily_round(db) == [1]
    assert sent == []


def test_daily_round_repairs_when_enabled(client, db, monkeypatch):
    register_and_login(client)
    # 造一个"状态写着 online、心跳停在 3 天前"的脏 agent
    db.add(
        Agent(
            tenant_id=1,
            name="dirty",
            platform="codex",
            status="online",
            last_seen_at=datetime.utcnow() - timedelta(days=3),
        )
    )
    db.commit()
    monkeypatch.setattr(settings, "selfcheck_repair", "1")

    selfcheck_scheduler.run_daily_round(db)
    dirty = db.query(Agent).filter(Agent.name == "dirty").one()
    assert dirty.status == "offline"
    run = db.query(SelfCheckRun).filter(SelfCheckRun.tenant_id == 1).one()
    repairs = selfcheck_scheduler.selfcheck_service.serialize_run(run)["repairs"]
    assert any("在线状态与心跳不一致" in r for r in repairs)


def test_history_endpoint_lists_manual_and_daily_runs(client, db):
    token = register_and_login(client)
    client.post("/api/v1/selfcheck/run", json={"repair": False}, headers=_headers(token))
    selfcheck_scheduler.run_daily_round(db)

    body = client.get("/api/v1/selfcheck/history", headers=_headers(token)).json()
    triggers = [r["trigger"] for r in body["runs"]]
    assert triggers == ["daily", "manual"]
    assert all("checks" not in r for r in body["runs"])  # 默认只回摘要
    assert all(r["summary"]["pass"] >= 0 for r in body["runs"])

    full = client.get(
        "/api/v1/selfcheck/history?with_checks=true&limit=1", headers=_headers(token)
    ).json()
    assert len(full["runs"][0]["checks"]) == 10


def test_scheduler_switch(monkeypatch):
    monkeypatch.setattr(settings, "selfcheck_enabled", "off")
    assert selfcheck_scheduler.enabled() is False
    monkeypatch.setattr(settings, "selfcheck_enabled", "on")
    assert selfcheck_scheduler.enabled() is True


def test_failures_land_in_the_alert_list(client, db):
    """巡检发现 fail → 告警列表里留一条平台级记录（agent_id 为空，显示 Pod Cloud）。"""
    token = register_and_login(client)
    selfcheck_scheduler.run_daily_round(db)

    alerts = db.query(PodAlert).filter(PodAlert.kind == "selfcheck").all()
    assert alerts, "fail 项应当各留一条告警"
    assert all(a.agent_id is None for a in alerts)
    assert all(a.severity == "high" and a.state == "open" for a in alerts)

    listed = client.get("/api/v1/alerts", headers=_headers(token)).json()["alerts"]
    platform = [a for a in listed if a["kind"] == "selfcheck"]
    assert platform and all(a["agent"] == "Pod Cloud" and a["agent_id"] is None for a in platform)
    # 平台告警和 agent 告警在同一条列表里，用户一个入口看全
    assert {a["kind"] for a in listed} >= {"selfcheck"}


def test_same_failure_is_not_alerted_twice_while_open(client, db):
    register_and_login(client)
    selfcheck_scheduler.run_daily_round(db)
    first = db.query(PodAlert).filter(PodAlert.kind == "selfcheck").count()
    assert first >= 1

    # 换一天再巡检：同一件事还开着 → 不重复建（否则列表很快被刷屏）
    tomorrow = datetime.now(selfcheck_scheduler.PUSH_TZ) + timedelta(days=1)
    selfcheck_scheduler.run_daily_round(db, tomorrow)
    assert db.query(PodAlert).filter(PodAlert.kind == "selfcheck").count() == first

    # 人处理完之后（resolved）又复发 → 该重新报一次
    db.query(PodAlert).filter(PodAlert.kind == "selfcheck").update({"state": "resolved"})
    db.commit()
    day3 = tomorrow + timedelta(days=1)
    selfcheck_scheduler.run_daily_round(db, day3)
    assert db.query(PodAlert).filter(PodAlert.kind == "selfcheck").count() == first * 2


def test_manual_run_also_records_alerts(client, db):
    """手动「自检」与每日巡检用同一套落库逻辑，避免两套判定。"""
    token = register_and_login(client)
    before = db.query(PodAlert).filter(PodAlert.kind == "selfcheck").count()
    client.post("/api/v1/selfcheck/run", json={"repair": False}, headers=_headers(token))
    after = db.query(PodAlert).filter(PodAlert.kind == "selfcheck").count()
    assert after > before


def _secret_alert(db) -> PodAlert:
    """测试环境 JWT 密钥就是默认值 → 「签名密钥强度」必然 fail，用它当抓手。"""
    row = (
        db.query(PodAlert)
        .filter(PodAlert.kind == "selfcheck", PodAlert.message.like("签名密钥强度：%"))
        .order_by(PodAlert.id.desc())
        .first()
    )
    assert row is not None, "默认密钥应当先产生一条失败告警"
    return row


def test_recovery_auto_resolves_the_alert(client, db, monkeypatch):
    register_and_login(client)
    day0 = datetime.now(selfcheck_scheduler.PUSH_TZ)
    selfcheck_scheduler.run_daily_round(db, day0)
    alert = _secret_alert(db)
    assert alert.state == "open"

    # 把密钥换强 → 这条检查过了 → 那条告警应当自动关掉
    monkeypatch.setattr(settings, "jwt_secret", "x" * 40)
    token = client.post(
        "/api/v1/auth/login", json={"email": "a@b.com", "password": "secret123"}
    ).json()["access_token"]
    body = client.post("/api/v1/selfcheck/run", json={"repair": False}, headers=_headers(token)).json()
    db.expire_all()
    assert db.query(PodAlert).filter(PodAlert.id == alert.id).one().state == "resolved"
    assert alert.id in body["alerts"]["resolved"]
    # 历史里也留痕：这一轮"自动关了几条"，用户翻记录时看得见
    latest = client.get("/api/v1/selfcheck/history?limit=1", headers=_headers(token)).json()["runs"][0]
    assert latest["summary"]["alerts_resolved"] == 1


def test_acknowledged_alert_also_auto_resolves(client, db, monkeypatch):
    """「已确认」只说明有人在看，不代表问题还在；检查过了照样关。"""
    register_and_login(client)
    selfcheck_scheduler.run_daily_round(db, datetime.now(selfcheck_scheduler.PUSH_TZ))
    alert = _secret_alert(db)
    alert.state = "acknowledged"
    db.commit()

    monkeypatch.setattr(settings, "jwt_secret", "y" * 40)
    selfcheck_scheduler.run_daily_round(
        db, datetime.now(selfcheck_scheduler.PUSH_TZ) + timedelta(days=1)
    )
    db.expire_all()
    assert db.query(PodAlert).filter(PodAlert.id == alert.id).one().state == "resolved"


def test_recurrence_after_resolve_opens_a_new_alert(client, db, monkeypatch):
    """关掉之后再复发 → 新开一条，历史那条保留（否则丢了处置记录）。"""
    register_and_login(client)
    day0 = datetime.now(selfcheck_scheduler.PUSH_TZ)
    selfcheck_scheduler.run_daily_round(db, day0)
    first = _secret_alert(db)
    first.state = "resolved"
    db.commit()

    selfcheck_scheduler.run_daily_round(db, day0 + timedelta(days=1))  # 还在失败
    rows = (
        db.query(PodAlert)
        .filter(PodAlert.kind == "selfcheck", PodAlert.message.like("签名密钥强度：%"))
        .order_by(PodAlert.id)
        .all()
    )
    assert [r.state for r in rows] == ["resolved", "open"]


def test_error_text_change_updates_in_place(client, db, monkeypatch):
    """同一项检查报错文案变了（比如密钥长度不同）→ 更新那条，而不是再开一条。"""
    register_and_login(client)
    day0 = datetime.now(selfcheck_scheduler.PUSH_TZ)
    selfcheck_scheduler.run_daily_round(db, day0)
    first = _secret_alert(db)

    monkeypatch.setattr(settings, "jwt_secret", "short")  # 还是弱，但长度不同
    selfcheck_scheduler.run_daily_round(db, day0 + timedelta(days=1))
    rows = (
        db.query(PodAlert)
        .filter(PodAlert.kind == "selfcheck", PodAlert.message.like("签名密钥强度：%"))
        .all()
    )
    assert len(rows) == 1
    assert rows[0].id == first.id
    assert "长度 5" in rows[0].message
