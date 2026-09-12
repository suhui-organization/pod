"""AI 模型设置与调用层：配置可解释、部分更新不误伤、出网可留痕。

这些断言对应三个真实缺陷，改动 `services/llm.py` 或 `/settings` 前先读：
1. 前端保存 webhook/SMTP 时把模型配置打回 auto + 空模型（数据静默丢失）；
2. `mock` 被静默当成 deepseek 发出去（报错指错方向）；
3. 模型调用没有留痕，"什么时候把数据发给了谁"无从查证。
"""

import json

import pytest

from app.models import AuditLog
from app.services import llm
from tests.conftest import register_and_login


def _h(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def test_unconfigured_llm_explains_why(client):
    """没配模型时，界面要拿到「为什么不可用」，而不是一个空表单。"""
    token = register_and_login(client)
    body = client.get("/api/v1/settings/llm", headers=_h(token)).json()
    assert body["configured"] is False
    assert "未配置模型" in body["reason"]
    assert body["api_key_set"] is False
    # Provider 清单与依赖清单由后端给，前端不各写一份
    assert {p["id"] for p in body["providers"]} == {"deepseek", "openai", "custom", "mock"}
    assert {f["id"] for f in body["features"]} == {
        "policies.generate",
        "alerts.summary",
        "alerts.digest",
    }


def test_saving_other_settings_does_not_wipe_model(client):
    """回归：保存告警 webhook 曾把 provider 打回 auto、model 清空。"""
    token = register_and_login(client)
    client.put(
        "/api/v1/settings/llm",
        json={"provider": "deepseek", "api_key": "sk-test-key-1234", "model": "deepseek-chat"},
        headers=_h(token),
    )
    client.put(
        "/api/v1/settings",
        json={"alert_webhook": {"enabled": True, "channel": "wecom", "url": "http://127.0.0.1:9/x"}},
        headers=_h(token),
    )
    body = client.get("/api/v1/settings/llm", headers=_h(token)).json()
    assert body["provider"] == "deepseek"
    assert body["model"] == "deepseek-chat"
    assert body["api_key_set"] is True
    assert body["configured"] is True
    # key 只回显尾号，不回显本体
    assert body["api_key_hint"].endswith("1234")
    assert "sk-test-key-1234" not in str(body)


def test_custom_provider_needs_base_url_then_joins_endpoint(client):
    """自定义端点：缺 base_url 要说人话；给了要拼成 chat/completions。"""
    token = register_and_login(client)
    client.put(
        "/api/v1/settings/llm",
        json={"provider": "custom", "model": "qwen-max", "api_key": "sk-x"},
        headers=_h(token),
    )
    body = client.get("/api/v1/settings/llm", headers=_h(token)).json()
    assert body["configured"] is False
    assert "Base URL" in body["reason"]

    client.put(
        "/api/v1/settings/llm",
        json={"base_url": "https://gateway.example.com/v1/"},
        headers=_h(token),
    )
    body = client.get("/api/v1/settings/llm", headers=_h(token)).json()
    assert body["configured"] is True
    assert body["base_url"] == "https://gateway.example.com/v1"  # 归一去掉尾斜杠
    assert body["effective"]["endpoint"] == "https://gateway.example.com/v1/chat/completions"


def test_base_url_must_be_http(client):
    token = register_and_login(client)
    r = client.put(
        "/api/v1/settings/llm",
        json={"provider": "custom", "base_url": "gateway.example.com/v1"},
        headers=_h(token),
    )
    assert r.status_code == 400
    assert "http" in r.json()["error"]["message"]


def test_unknown_provider_is_rejected_loudly(client):
    """不再静默回落：选错 provider 直接 400，而不是拿别人的端点去发请求。"""
    token = register_and_login(client)
    r = client.put("/api/v1/settings/llm", json={"provider": "gpt5"}, headers=_h(token))
    assert r.status_code == 400
    assert "未知 Provider" in r.json()["error"]["message"]


def test_mock_provider_needs_no_key_and_stays_local(client, monkeypatch):
    """离线模拟：不联网也能把链路跑通（演示 / 验收 / CI）。"""
    token = register_and_login(client)

    def boom(*a, **k):  # 任何真实出网都会让这条测试失败
        raise AssertionError("mock provider 不应发起网络请求")

    monkeypatch.setattr(llm.httpx, "post", boom)
    client.put("/api/v1/settings/llm", json={"provider": "mock"}, headers=_h(token))
    r = client.post("/api/v1/settings/llm/test", json={}, headers=_h(token))
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True
    assert body["provider"] == "mock" and body["model"] == "mock-1"


def test_test_connection_failure_returns_reason_not_500(client, monkeypatch):
    """测试连接失败要回可读原因（鉴权 / 端点），不是 500。"""
    token = register_and_login(client)
    client.put(
        "/api/v1/settings/llm",
        json={"provider": "deepseek", "api_key": "sk-bad"},
        headers=_h(token),
    )

    class FakeResp:
        status_code = 401
        text = '{"error":"invalid api key"}'

    monkeypatch.setattr(llm.httpx, "post", lambda *a, **k: FakeResp())
    body = client.post("/api/v1/settings/llm/test", json={}, headers=_h(token)).json()
    assert body["ok"] is False
    assert "401" in body["error"]


def test_model_calls_are_audited_without_content(client, db):
    """留痕：记谁、用哪个模型、成没成；不记 prompt / 响应正文。"""
    token = register_and_login(client)
    client.put("/api/v1/settings/llm", json={"provider": "mock"}, headers=_h(token))
    client.post("/api/v1/settings/llm/test", json={}, headers=_h(token))
    client.post(
        "/api/v1/policies/generate", json={"description": "禁止删除文件"}, headers=_h(token)
    )

    rows = db.query(AuditLog).filter(AuditLog.action == "llm.call").all()
    assert rows, "模型调用必须留痕"
    details = " ".join(r.detail_json for r in rows)
    assert "settings.llm_test" in details
    assert "policies.generate" in details
    for row in rows:
        # 只记形状（字数 / 耗时 / 成败），不记正文——记正文等于把控制台变成第二个泄露面
        keys = set(json.loads(row.detail_json))
        assert not {"prompt", "response", "content", "messages"} & keys
        assert {"feature", "provider", "model", "ok"} <= keys


def test_member_can_read_but_not_write_llm_settings(client):
    """只读成员：能看（知道 AI 为什么不可用），不能改。"""
    admin = register_and_login(client)
    client.post(
        "/api/v1/users",
        json={
            "email": "member@b.com",
            "password": "secret123",
            "full_name": "M",
            "role": "member",
        },
        headers=_h(admin),
    )
    member = client.post(
        "/api/v1/auth/login", json={"email": "member@b.com", "password": "secret123"}
    ).json()["access_token"]

    assert client.get("/api/v1/settings/llm", headers=_h(member)).status_code == 200
    write = client.put("/api/v1/settings/llm", json={"provider": "mock"}, headers=_h(member))
    assert write.status_code == 403
    assert client.post("/api/v1/settings/llm/test", json={}, headers=_h(member)).status_code == 403


def test_auto_provider_resolves_to_deepseek(monkeypatch):
    """auto 不再「猜一个 provider」，语义固定：按 deepseek 直连。"""
    monkeypatch.setenv("PODCLOUD_LLM_API_KEY", "sk-env-key-abcdef")
    cfg = llm.resolve_config(None)
    assert cfg.provider == "deepseek"
    assert cfg.key_source == "env"
    assert cfg.endpoint == "https://api.deepseek.com/chat/completions"


def test_resolve_config_rejects_unknown_provider_value():
    class Row:
        provider = "some-other-vendor"
        api_key = "sk-x"
        base_url = ""
        model = ""

    with pytest.raises(llm.LlmConfigError):
        llm.resolve_config(Row())


def test_shape_alert_whitelists_fields_and_truncates():
    """出网裁剪：白名单字段 + 自由文本截断（message 最容易夹带路径）。"""
    shaped = llm.shape_alert(
        {
            "ts": "2026-09-11T10:00:00",
            "agent": "claude-code",
            "severity": "high",
            "kind": "sensitive_path",
            "message": "x" * 500,
            "args": {"path": "/Users/walden/.ssh/id_rsa"},  # 不在白名单，必须丢掉
        }
    )
    assert set(shaped) == {"ts", "agent", "severity", "kind", "message"}
    assert len(shaped["message"]) == llm.MAX_FREETEXT_CHARS + 1  # 截断标记
