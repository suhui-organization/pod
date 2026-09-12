"""Pod Cloud 告警：规则引擎（11 条）与 webhook 通知。"""

from datetime import datetime, timedelta

from tests.conftest import register_and_login
import json
from app.models import Agent, PodAlert, SyncEvent


def _headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _register_agent(client, token, name="agent-a"):
    r = client.post("/api/v1/agents", json={"name": name}, headers=_headers(token))
    return r.json()["agent"]["id"], r.json()["sync_token"]


def _sync(client, token, events, server="filesystem", prev=""):
    """推一批事件，返回 (status, body)。events: [{seq, tool, decision, reason, ...}]"""
    body = {"events": []}
    ph = prev
    for i, e in enumerate(events):
        h = f"h{e['seq']:063d}"
        body["events"].append({
            "seq": e["seq"], "ts": "2026-09-01T00:00:00Z", "server": server,
            "tool": e["tool"], "args_hash": "a" * 64, "decision": e.get("decision", "allow"),
            "outcome": e.get("outcome", "ok"), "approver": e.get("approver", ""),
            "reason": e.get("reason", ""), "policy_version": "0.1.0",
            "enforced": True, "prev_hash": ph, "hash": h,
        })
        ph = h
    return client.post("/api/v1/sync/events", json=body, headers={"X-Sync-Token": token})


def _alerts(client, token, kind=None, state=None):
    q = []
    if kind: q.append(f"kind={kind}")
    if state: q.append(f"state={state}")
    url = "/api/v1/alerts" + ("?" + "&".join(q) if q else "")
    return client.get(url, headers=_headers(token)).json()["alerts"]


def test_sensitive_path_rule(client):
    token = register_and_login(client)
    aid, sync = _register_agent(client, token)
    r = _sync(client, sync, [
        {"seq": 1, "tool": "read_file", "reason": 'argument hits sensitive path pattern "~/.ssh" (secrets.deny_input_paths)', "decision": "deny"},
    ])
    assert r.status_code == 200
    alerts = _alerts(client, token, kind="sensitive_path")
    assert len(alerts) == 1
    assert alerts[0]["severity"] == "high"
    assert alerts[0]["agent"] == "agent-a"


def test_policy_mismatch_and_unregistered(client):
    token = register_and_login(client)
    aid, sync = _register_agent(client, token)
    _sync(client, sync, [
        {"seq": 1, "tool": "read_file", "reason": 'policy is bound to agent "other", got "agent-a"', "decision": "deny"},
        {"seq": 2, "tool": "list_directory", "reason": 'server "billing" is not registered (default deny)', "decision": "deny"},
    ])
    assert len(_alerts(client, token, kind="policy_mismatch")) == 1
    assert len(_alerts(client, token, kind="unregistered_server")) == 1
    assert _alerts(client, token, kind="policy_mismatch")[0]["severity"] == "high"
    assert _alerts(client, token, kind="unregistered_server")[0]["severity"] == "medium"


def test_manual_approval_and_tool_first_use(client):
    token = register_and_login(client)
    aid, sync = _register_agent(client, token)
    _sync(client, sync, [
        {"seq": 1, "tool": "write_file", "decision": "approve", "approver": "admin", "reason": 'tool "write_file" requires approval on "filesystem"'},
        {"seq": 2, "tool": "write_file", "decision": "approve", "approver": "admin", "reason": 'tool "write_file" requires approval on "filesystem"'},
    ])
    # manual_approval：每个事件各一条
    assert len(_alerts(client, token, kind="manual_approval")) == 2
    # tool_first_use：write_file 首次使用一条（第二次不重复）
    assert len(_alerts(client, token, kind="tool_first_use")) == 1
    assert _alerts(client, token, kind="manual_approval")[0]["severity"] == "low"


def test_deny_burst_and_tool_spike(client):
    token = register_and_login(client)
    aid, sync = _register_agent(client, token)
    events = []
    for i in range(1, 9):
        events.append({"seq": i, "tool": f"tool_{i % 3}", "decision": "deny", "reason": f'tool "t" is denied on "filesystem"'})
    _sync(client, sync, events)
    assert len(_alerts(client, token, kind="deny_burst")) == 1
    # 同窗口再推一批：不重复
    events2 = [{"seq": 9 + i, "tool": "x", "decision": "deny", "reason": "denied"} for i in range(2)]
    _sync(client, sync, events2, prev=f"h0008{'' :0<56}")
    assert len(_alerts(client, token, kind="deny_burst")) == 1


def test_agent_silence_rule(client, db):
    # 失联告警已独立为巡检（services/silence_watch），sync 不再内嵌
    from app.services.silence_watch import run_silence_check

    token = register_and_login(client)
    aid1, sync1 = _register_agent(client, token, name="active-agent")
    aid2, sync2 = _register_agent(client, token, name="sleepy-agent")
    sleepy = db.query(Agent).filter(Agent.id == aid2).first()
    sleepy.last_seen_at = datetime.utcnow() - timedelta(hours=30)
    db.commit()
    # sync 事件不产生失联告警
    _sync(client, sync1, [{"seq": 1, "tool": "read_file"}])
    assert _alerts(client, token, kind="agent_silence") == []
    # 巡检产生，且 24h 去重
    created = run_silence_check(db)
    assert len(created) == 1 and "sleepy-agent" in created[0].message
    assert len(run_silence_check(db)) == 0


def test_webhook_config_roundtrip(client):
    token = register_and_login(client)
    r = client.put("/api/v1/settings", json={
        "alert_webhook": {"enabled": True, "channel": "wecom", "url": "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=abc", "secret": "s3cret", "min_severity": "high"},
    }, headers=_headers(token))
    assert r.status_code == 200
    out = r.json()["alert_webhook"]
    assert out["enabled"] is True
    assert out["channel"] == "wecom"
    assert out["url_set"] is True  # url 不回显
    assert out["min_severity"] == "high"
    # GET 一致
    g = client.get("/api/v1/settings", headers=_headers(token)).json()["alert_webhook"]
    assert g["url_set"] is True and g["channel"] == "wecom"
    # 非法渠道拒绝
    r2 = client.put("/api/v1/settings", json={"alert_webhook": {"channel": "irc"}}, headers=_headers(token))
    assert r2.status_code == 400


def test_notify_payload_formats():
    from app.services.alert_notify import format_payload, _severity_ok

    alerts = [
        {"kind": "sensitive_path", "severity": "high", "message": "尝试访问敏感路径被拦截", "agent": "a", "ts": "t"},
        {"kind": "tool_first_use", "severity": "low", "message": "首次使用工具", "agent": "a", "ts": "t"},
    ]
    p = format_payload("wecom", alerts)
    assert p["msgtype"] == "text" and "敏感路径" in p["text"]["content"]
    p = format_payload("slack", alerts)
    assert p["blocks"][0]["text"]["text"].startswith("Pod Cloud")
    p = format_payload("feishu", alerts)
    assert p["msg_type"] == "text"
    p = format_payload("generic", alerts)
    assert p["event"] == "alert" and p["count"] == 2
    # 严重级别过滤
    assert _severity_ok("high", "high") and not _severity_ok("high", "low")
    assert _severity_ok("medium", "high") and _severity_ok("", "low")


def test_alert_state_lifecycle(client):
    token = register_and_login(client)
    aid, sync = _register_agent(client, token)
    _sync(client, sync, [
        {"seq": 1, "tool": "read_file", "reason": 'argument hits sensitive path pattern "~/.ssh" (secrets.deny_input_paths)', "decision": "deny"},
    ])
    alerts = _alerts(client, token)
    assert len(alerts) == 2 and all(a["state"] == "open" for a in alerts)  # sensitive_path + tool_first_use
    # 确认第一条 → 仍有一条 open
    r = client.put(f"/api/v1/alerts/{alerts[0]['id']}/state", json={"state": "acknowledged"}, headers=_headers(token))
    assert r.status_code == 200 and r.json()["state"] == "acknowledged"
    assert len(_alerts(client, token, state="open")) == 1
    # 全部解决 → 无 open
    for a in _alerts(client, token):
        client.put(f"/api/v1/alerts/{a['id']}/state", json={"state": "resolved"}, headers=_headers(token))
    assert len(_alerts(client, token, state="resolved")) == 2
    assert len(_alerts(client, token, state="open")) == 0
    # 非法状态
    r = client.put(f"/api/v1/alerts/{alerts[0]['id']}/state", json={"state": "boom"}, headers=_headers(token))
    assert r.status_code == 400


def test_alert_batch_state(client):
    token = register_and_login(client)
    aid, sync = _register_agent(client, token)
    _sync(client, sync, [
        {"seq": 1, "tool": "a", "reason": 'argument hits sensitive path pattern ".env" (secrets.deny_input_paths)', "decision": "deny"},
        {"seq": 2, "tool": "b", "reason": 'tool "b" is denied on "filesystem"', "decision": "deny"},
    ])
    ids = [a["id"] for a in _alerts(client, token)]
    assert len(ids) == 3  # sensitive_path + tool_first_use ×2
    r = client.post("/api/v1/alerts/batch-state", params={"state": "resolved"}, json=ids, headers=_headers(token))
    assert r.status_code == 200 and r.json()["updated"] == len(ids)
    assert len(_alerts(client, token, state="resolved")) == len(ids)


def test_smtp_config_roundtrip(client):
    token = register_and_login(client)
    r = client.put("/api/v1/settings", json={
        "alert_smtp": {"enabled": True, "host": "smtp.example.com", "port": 587, "user": "alert@example.com",
                       "password": "pw123", "from_addr": "alert@example.com", "to_addrs": "ops@example.com, boss@example.com", "tls": True},
    }, headers=_headers(token))
    assert r.status_code == 200
    out = r.json()["alert_smtp"]
    assert out["enabled"] is True and out["host"] == "smtp.example.com"
    assert out["user_set"] is True and "password" not in out
    assert out["to_addrs"] == "ops@example.com, boss@example.com"
    # 密码留空 = 保留
    r2 = client.put("/api/v1/settings", json={"alert_smtp": {"enabled": True, "host": "smtp.example.com", "password": ""}}, headers=_headers(token))
    assert r2.status_code == 200 and r2.json()["alert_smtp"]["host"] == "smtp.example.com"
    # 启用但无 host 拒绝
    r3 = client.put("/api/v1/settings", json={"alert_smtp": {"enabled": True, "host": ""}}, headers=_headers(token))
    assert r3.status_code == 400


def test_email_payload_build():
    from app.services.alert_notify import send_email

    # 不真的发信：用不存在的端口验证失败路径不抛异常（日志 warning）
    cfg = {"enabled": True, "host": "127.0.0.1", "port": 1, "user": "", "password": "",
           "from_addr": "a@b.c", "to_addrs": "x@y.z", "tls": False}
    send_email(cfg, [{"kind": "sensitive_path", "severity": "high", "message": "m", "agent": "a", "ts": "t"}])  # 不应抛异常


def test_silence_check_creates_alerts(client, db):
    from app.models import Agent
    from app.services.silence_watch import run_silence_check

    token = register_and_login(client)
    aid, sync = _register_agent(client, token, name="offline-agent")
    a = db.query(Agent).filter(Agent.id == aid).first()
    a.last_seen_at = datetime.utcnow() - timedelta(hours=30)
    db.commit()
    created = run_silence_check(db)
    assert len(created) == 1
    assert created[0].kind == "agent_silence"
    assert "offline-agent" in created[0].message
    # 去重：再跑一轮不新增
    created2 = run_silence_check(db)
    assert len(created2) == 0


def test_alert_rules_config_roundtrip(client):
    token = register_and_login(client)
    r = client.put("/api/v1/settings", json={
        "alert_rules": {"deny_burst_threshold": 3, "burst_window_seconds": 30, "spike_threshold": 50, "silence_hours": 6},
    }, headers=_headers(token))
    assert r.status_code == 200
    out = r.json()["alert_rules"]
    assert out == {"deny_burst_threshold": 3, "burst_window_seconds": 30, "spike_threshold": 50, "silence_hours": 6}
    g = client.get("/api/v1/settings", headers=_headers(token)).json()["alert_rules"]
    assert g["deny_burst_threshold"] == 3
    # 非法值拒绝
    r2 = client.put("/api/v1/settings", json={"alert_rules": {"deny_burst_threshold": 0}}, headers=_headers(token))
    assert r2.status_code == 400
    r3 = client.put("/api/v1/settings", json={"alert_rules": {"burst_window_seconds": "abc"}}, headers=_headers(token))
    assert r3.status_code == 400


def test_deny_burst_uses_tenant_threshold(client):
    token = register_and_login(client)
    aid, sync = _register_agent(client, token)
    # 阈值调低到 2 → 2 次 deny 即触发
    client.put("/api/v1/settings", json={"alert_rules": {"deny_burst_threshold": 2, "burst_window_seconds": 60}}, headers=_headers(token))
    _sync(client, sync, [
        {"seq": 1, "tool": "a", "decision": "deny", "reason": 'tool "a" is denied on "filesystem"'},
        {"seq": 2, "tool": "b", "decision": "deny", "reason": 'tool "b" is denied on "filesystem"'},
    ])
    bursts = _alerts(client, token, kind="deny_burst")
    assert len(bursts) == 1
    assert "2 次" in bursts[0]["message"]


def test_silence_hours_uses_tenant_threshold(client, db):
    from app.services.silence_watch import _tenant_silence_hours, run_silence_check

    token = register_and_login(client)
    aid, sync = _register_agent(client, token, name="half-day-agent")
    client.put("/api/v1/settings", json={"alert_rules": {"silence_hours": 6}}, headers=_headers(token))
    a = db.query(Agent).filter(Agent.id == aid).first()
    a.last_seen_at = datetime.utcnow() - timedelta(hours=12)
    db.commit()
    assert _tenant_silence_hours(db, a.tenant_id) == 6
    created = run_silence_check(db)
    assert len(created) == 1
    assert "6h" in created[0].message


def test_policy_templates_listed(client):
    token = register_and_login(client)
    r = client.get("/api/v1/policies/templates", headers=_headers(token))
    assert r.status_code == 200
    ids = {t["id"] for t in r.json()["templates"]}
    assert {"balanced", "high-security", "audit-only", "locked-down"} <= ids
    by_id = {t["id"]: t for t in r.json()["templates"]}
    assert by_id["high-security"]["deny"] == ["write_file", "edit_file", "delete_file"]
    assert by_id["audit-only"]["default_decision"] == "allow"


def test_apply_template_creates_and_overwrites(client):
    token = register_and_login(client)
    aid, sync = _register_agent(client, token, name="tpl-agent")
    # 首次应用 → 创建
    r = client.post("/api/v1/policies/apply-template",
                    json={"template": "high-security", "agent_id": aid}, headers=_headers(token))
    assert r.status_code == 200 and r.json()["applied"] is True
    pid = r.json()["policy"]["id"]
    import json as j
    policy = j.loads(r.json()["policy"]["policy_json"])
    assert policy["servers"]["filesystem"]["deny"] == ["write_file", "edit_file", "delete_file"]
    assert policy.get("agent") == "tpl-agent"  # 注入目标 agent 名
    assert len(policy["secrets"]["deny_input_paths"]) >= 10
    # 再应用另一模板 → 覆盖（同一 agent 仍一条策略）
    r2 = client.post("/api/v1/policies/apply-template",
                     json={"template": "locked-down", "agent_id": aid}, headers=_headers(token))
    assert r2.status_code == 200 and r2.json()["policy"]["id"] == pid
    policy2 = j.loads(r2.json()["policy"]["policy_json"])
    assert policy2["defaultDecision"] == "deny" and policy2["servers"]["filesystem"]["deny"] == ["*"]
    # 未知模板拒绝
    r3 = client.post("/api/v1/policies/apply-template",
                     json={"template": "nope", "agent_id": aid}, headers=_headers(token))
    assert r3.status_code == 400


def test_dashboard_alert_kind_and_trend(client):
    token = register_and_login(client)
    aid, sync = _register_agent(client, token)
    _sync(client, sync, [
        {"seq": 1, "tool": "read_file", "reason": 'argument hits sensitive path pattern "~/.ssh" (secrets.deny_input_paths)', "decision": "deny"},
        {"seq": 2, "tool": "write_file", "decision": "approve", "approver": "admin", "reason": 'tool "write_file" requires approval on "filesystem"'},
    ])
    d = client.get("/api/v1/dashboard/summary", headers=_headers(token)).json()
    kinds = {k["kind"]: k["count"] for k in d["alerts"]["by_kind"]}
    assert kinds.get("sensitive_path") == 1
    assert kinds.get("manual_approval") == 1
    assert len(d["alerts"]["trend_7d"]) >= 1
    assert d["alerts"]["trend_7d"][0]["count"] >= 2


def test_ai_summary_requires_config(client):
    token = register_and_login(client)
    r = client.post("/api/v1/alerts/summarize", headers=_headers(token))
    assert r.status_code == 400
    assert "未配置模型" in r.json()["error"]["message"]


def test_ai_summary_calls_llm_and_returns(client, monkeypatch):
    from app.services import ai_summary

    token = register_and_login(client)
    aid, sync = _register_agent(client, token)
    _sync(client, sync, [
        {"seq": 1, "tool": "read_file", "reason": 'argument hits sensitive path pattern "~/.ssh" (secrets.deny_input_paths)', "decision": "deny"},
    ])
    # 配置模型
    client.put("/api/v1/settings", json={"provider": "deepseek", "api_key": "sk-test", "model": "deepseek-chat"}, headers=_headers(token))

    captured = {}

    def fake_summarize(cfg, alerts, **kwargs):
        captured.update(provider=cfg.provider, model=cfg.model, n=len(alerts), kinds={a["kind"] for a in alerts})
        return {"summary": "## 总体情况\n共 2 条告警，涉及 agent-a。", "model": cfg.model}

    monkeypatch.setattr(ai_summary, "summarize", fake_summarize)
    r = client.post("/api/v1/alerts/summarize", headers=_headers(token))
    assert r.status_code == 200
    body = r.json()
    assert body["ai_generated"] is True
    assert "总体情况" in body["summary"]
    assert captured["provider"] == "deepseek"
    assert captured["n"] >= 2
    assert "sensitive_path" in captured["kinds"]
    # 摘要不改动告警状态
    assert _alerts(client, token)[0]["state"] == "open"


def test_ai_summary_failure_returns_502(client, monkeypatch):
    from app.services import ai_summary

    token = register_and_login(client)
    client.put("/api/v1/settings", json={"provider": "deepseek", "api_key": "sk-test"}, headers=_headers(token))

    def boom(*a, **k):
        raise RuntimeError("model down")

    monkeypatch.setattr(ai_summary, "summarize", boom)
    r = client.post("/api/v1/alerts/summarize", headers=_headers(token))
    assert r.status_code == 502


def test_policy_generate_returns_preview_not_saved(client, monkeypatch):
    import app.services.ai_summary as ai_mod

    token = register_and_login(client)
    client.put("/api/v1/settings", json={"provider": "deepseek", "api_key": "sk-test"}, headers=_headers(token))

    def fake_gen(cfg, description, **kwargs):
        return {"policy": {"version": "0.1.0", "defaultDecision": "deny",
                           "servers": {"filesystem": {"allow": ["read_file"], "deny": ["delete_file"], "approve": []}}},
                "model": cfg.model}

    monkeypatch.setattr(ai_mod, "generate_policy", fake_gen)
    r = client.post("/api/v1/policies/generate", json={"description": "禁止 agent 删除文件"}, headers=_headers(token))
    assert r.status_code == 200
    body = r.json()
    assert body["saved"] is False
    assert "delete_file" in body["policy_json"] and '"deny"' in body["policy_json"]
    # 生成不落库
    assert client.get("/api/v1/policies", headers=_headers(token)).json()["policies"] == []


def test_policy_generate_no_model_400(client):
    token = register_and_login(client)
    r = client.post("/api/v1/policies/generate", json={"description": "禁止访问生产服务器"}, headers=_headers(token))
    assert r.status_code == 400
    assert "未配置模型" in r.json()["error"]["message"]


def test_extract_json_strips_codeblock():
    from app.services.ai_summary import extract_json

    raw = "好的，这是策略：\n```json\n{\"a\": 1}\n```\n如有问题请指出。"
    assert extract_json(raw) == '{"a": 1}'
    assert extract_json('{"b": 2}') == '{"b": 2}'


def test_digest_round_pushes_and_dedups(client, db, monkeypatch):
    from app.models import TenantSettings
    from app.services import digest_scheduler as ds

    token = register_and_login(client)
    aid, sync = _register_agent(client, token, name="digest-agent")
    _sync(client, sync, [
        {"seq": 1, "tool": "read_file", "reason": 'argument hits sensitive path pattern ".env" (secrets.deny_input_paths)', "decision": "deny"},
    ])
    # 启用日报 + webhook 渠道
    client.put("/api/v1/settings", json={"provider": "deepseek", "api_key": "sk-test"}, headers=_headers(token))
    client.put("/api/v1/settings", json={"ai_digest": {"enabled": True}}, headers=_headers(token))
    client.put("/api/v1/settings", json={"alert_webhook": {"enabled": True, "channel": "wecom", "url": "http://127.0.0.1:9999/x"}}, headers=_headers(token))

    # mock 摘要与推送发送
    import app.services.digest_scheduler as ds_mod
    monkeypatch.setattr(ds_mod, "summarize", lambda *a, **k: {"summary": "## 日报\n昨日 2 条告警。", "model": "m"})
    sent = []
    monkeypatch.setattr(ds_mod, "notify_async", lambda cfg, alerts: sent.append(alerts))

    # 时间固定为北京时间 9 点（跳过 at_hour 检查，直接跑 round）
    pushed = ds.run_digest_round(db)
    assert len(pushed) == 1
    assert len(sent) == 1
    assert "日报" in sent[0][0]["message"]
    # 幂等：再跑不重复
    assert ds.run_digest_round(db) == []
    assert len(sent) == 1
    # 未启用日报的租户不推
    row = db.query(TenantSettings).filter(TenantSettings.tenant_id == 1).first()
    import json as j
    st = j.loads(row.ai_digest_json)
    st["enabled"] = False
    row.ai_digest_json = j.dumps(st)
    db.commit()
    assert ds.run_digest_round(db) == []


def test_policy_generate_returns_explanation(client, monkeypatch):
    from app.services import ai_summary

    token = register_and_login(client)
    client.put("/api/v1/settings", json={"provider": "deepseek", "api_key": "sk-test"}, headers=_headers(token))

    def fake_gen(cfg, description, **kwargs):
        return {"policy": {"defaultDecision": "deny", "servers": {}},
                "model": cfg.model, "explanation": "删除风险高故一律拒绝；读取放行以便开发。"}

    monkeypatch.setattr(ai_summary, "generate_policy", fake_gen)
    r = client.post("/api/v1/policies/generate", json={"description": "禁止删除"}, headers=_headers(token))
    assert r.status_code == 200
    body = r.json()
    assert "删除风险高" in body["explanation"]
    # explanation 不进入策略本体
    assert "explanation" not in body["policy"]


def test_digest_now_manual_push(client, db, monkeypatch):
    from app.models import TenantSettings
    from app.services import digest_scheduler as ds

    token = register_and_login(client)
    aid, sync = _register_agent(client, token, name="manual-agent")
    _sync(client, sync, [
        {"seq": 1, "tool": "read_file", "reason": 'argument hits sensitive path pattern ".env" (secrets.deny_input_paths)', "decision": "deny"},
    ])
    client.put("/api/v1/settings", json={"provider": "deepseek", "api_key": "sk-test"}, headers=_headers(token))
    client.put("/api/v1/settings", json={"ai_digest": {"enabled": False}}, headers=_headers(token))  # 开关关着也能手动推
    client.put("/api/v1/settings", json={"alert_webhook": {"enabled": True, "channel": "wecom", "url": "http://127.0.0.1:9999/x"}}, headers=_headers(token))

    import app.services.digest_scheduler as ds_mod
    monkeypatch.setattr(ds_mod, "summarize", lambda *a, **k: {"summary": "## 手动日报\n内容", "model": "m"})
    sent = []
    monkeypatch.setattr(ds_mod, "notify_async", lambda cfg, alerts: sent.append(alerts))

    r = client.post("/api/v1/alerts/digest-now", headers=_headers(token))
    assert r.status_code == 200
    assert r.json()["pushed"] is True
    assert len(sent) == 1 and "手动日报" in sent[0][0]["message"]
    # 手动推送更新 last_sent_date
    row = db.query(TenantSettings).filter(TenantSettings.tenant_id == 1).first()
    import json as j
    assert j.loads(row.ai_digest_json)["last_sent_date"]
    # 无渠道 → 400
    client.put("/api/v1/settings", json={"alert_webhook": {"enabled": False, "url": ""}}, headers=_headers(token))
    r2 = client.post("/api/v1/alerts/digest-now", headers=_headers(token))
    assert r2.status_code == 400


def test_policy_note_roundtrip_and_template_note(client):
    token = register_and_login(client)
    # 创建带 note
    r = client.post("/api/v1/policies", json={
        "name": "prod-policy", "note": "禁止访问生产配置（AI 生成）",
        "policy_json": json.dumps({"version": "0.1.0", "defaultDecision": "deny", "servers": {}}),
    }, headers=_headers(token))
    assert r.status_code == 201
    pid = r.json()["policy"]["id"]
    assert r.json()["policy"]["note"] == "禁止访问生产配置（AI 生成）"
    # 更新 note
    r2 = client.put(f"/api/v1/policies/{pid}", json={
        "name": "prod-policy", "note": "更新后的说明",
        "policy_json": json.dumps({"version": "0.1.0", "defaultDecision": "deny", "servers": {}}),
    }, headers=_headers(token))
    assert r2.json()["policy"]["note"] == "更新后的说明"
    # 模板应用带 note（模板描述）
    aid, sync = _register_agent(client, token, name="note-agent")
    r3 = client.post("/api/v1/policies/apply-template", json={"template": "high-security", "agent_id": aid}, headers=_headers(token))
    assert "只读环境" in r3.json()["policy"]["note"]


def test_policy_versions_and_revert(client):
    token = register_and_login(client)
    # v1 创建
    r = client.post("/api/v1/policies", json={
        "name": "ver-policy", "note": "v1 说明",
        "policy_json": json.dumps({"version": "0.1.0", "defaultDecision": "deny",
                                   "servers": {"filesystem": {"allow": ["read_file"], "deny": [], "approve": []}}}),
    }, headers=_headers(token))
    pid = r.json()["policy"]["id"]
    assert r.json()["policy"]["version"] == "1"
    # v2 更新
    client.put(f"/api/v1/policies/{pid}", json={
        "name": "ver-policy", "note": "v2 收紧",
        "policy_json": json.dumps({"version": "0.1.0", "defaultDecision": "deny",
                                   "servers": {"filesystem": {"allow": [], "deny": ["delete_file"], "approve": []}}}),
    }, headers=_headers(token))
    # 版本历史 2 条
    vs = client.get(f"/api/v1/policies/{pid}/versions", headers=_headers(token)).json()
    assert vs["current_version"] == "2"
    assert [v["version"] for v in vs["versions"]] == [1, 2]
    assert "delete_file" in vs["versions"][1]["policy_json"]
    # 回滚 v1
    rv = client.post(f"/api/v1/policies/{pid}/revert", json={"version": 1}, headers=_headers(token))
    assert rv.status_code == 200
    assert "read_file" in rv.json()["policy"]["policy_json"]
    assert "delete_file" not in rv.json()["policy"]["policy_json"]
    # 回滚产生 v3（当前快照入历史）
    vs2 = client.get(f"/api/v1/policies/{pid}/versions", headers=_headers(token)).json()
    assert vs2["current_version"] == "3"
    assert len(vs2["versions"]) == 3
    # 模板覆盖也入版本
    aid, sync = _register_agent(client, token, name="ver-agent")
    client.post("/api/v1/policies/apply-template", json={"template": "locked-down", "agent_id": aid}, headers=_headers(token))
    ap = [p for p in client.get("/api/v1/policies", headers=_headers(token)).json()["policies"] if p["agent_id"] == aid][0]
    v3 = client.get(f"/api/v1/policies/{ap['id']}/versions", headers=_headers(token)).json()
    assert len(v3["versions"]) == 1 and v3["current_version"] == "1"
