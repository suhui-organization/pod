"""规则包：发布 / 分发 / 撤回。

这里只测"云端做的那三件事"（存、标 active、记审计）与两条鉴权边界。
**验签与放宽守卫不在服务端**——那是客户端的事，所以这里刻意不断言签名有效性，
只断言"没有 signature 的包不收"。
"""

import json

from tests.conftest import register_and_login


def _headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _register_agent(client, token, name="agent-a"):
    r = client.post("/api/v1/agents", json={"name": name}, headers=_headers(token))
    return r.json()["agent"]["id"], r.json()["sync_token"]


def _pack(version: str = "2026.09.12", signature: str = "c2ln") -> str:
    return json.dumps(
        {
            "schema": "pod-rules-pack/v1",
            "packVersion": version,
            "issuedBy": "podsec",
            "issuedAt": "2026-09-12T00:00:00.000Z",
            "note": "测试包",
            "rules": {"injection": {"block": True}},
            "signature": signature,
        }
    )


def test_publish_then_client_pulls(client):
    token = register_and_login(client)
    _, sync_token = _register_agent(client, token)

    r = client.post("/api/v1/rules/packs", json={"pack_json": _pack(), "note": "首发"}, headers=_headers(token))
    assert r.status_code in (200, 201), r.text
    assert r.json()["pack"]["active"] is True

    # 分发面：用 sync token 拉（与 /sync/policies 同一套凭证）
    r = client.get("/api/v1/rules/pack", headers={"X-Sync-Token": sync_token})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["pack_version"] == "2026.09.12"
    assert body["issued_by"] == "podsec"
    # 原文原样返回：客户端要拿它自己验签
    assert json.loads(body["pack_json"])["signature"] == "c2ln"


def test_publish_deactivates_previous_and_activate_rolls_back(client):
    token = register_and_login(client)
    _register_agent(client, token)

    first = client.post("/api/v1/rules/packs", json={"pack_json": _pack("v1")}, headers=_headers(token)).json()["pack"]
    second = client.post("/api/v1/rules/packs", json={"pack_json": _pack("v2")}, headers=_headers(token)).json()["pack"]

    packs = client.get("/api/v1/rules/packs", headers=_headers(token)).json()["packs"]
    assert [(p["pack_version"], p["active"]) for p in packs] == [("v2", True), ("v1", False)]

    # 撤回：激活旧版而不是删除——历史还在
    r = client.post(f"/api/v1/rules/packs/{first['id']}/activate", headers=_headers(token))
    assert r.status_code == 200, r.text
    packs = client.get("/api/v1/rules/packs", headers=_headers(token)).json()["packs"]
    assert [(p["pack_version"], p["active"]) for p in packs] == [("v2", False), ("v1", True)]
    assert second["id"] != first["id"]


def test_unsigned_pack_rejected(client):
    token = register_and_login(client)
    r = client.post(
        "/api/v1/rules/packs",
        json={"pack_json": _pack(signature="")},
        headers=_headers(token),
    )
    assert r.status_code == 400
    # 错误走全局统一格式 {"error": {"code", "message"}}
    assert "signature" in r.json()["error"]["message"]


def test_bad_schema_and_bad_json_rejected(client):
    token = register_and_login(client)
    r = client.post("/api/v1/rules/packs", json={"pack_json": "{not json"}, headers=_headers(token))
    assert r.status_code == 400
    r = client.post(
        "/api/v1/rules/packs",
        json={"pack_json": json.dumps({"schema": "other/v1", "signature": "x"})},
        headers=_headers(token),
    )
    assert r.status_code == 400
    assert "schema" in r.json()["error"]["message"]


def test_publish_requires_admin(client):
    token = register_and_login(client)
    # 注册者默认是管理员，所以显式加一个普通成员（走租户内的用户接口，不依赖邀请流程）
    r = client.post(
        "/api/v1/users",
        json={"email": "member@b.com", "password": "secret123", "role": "member"},
        headers=_headers(token),
    )
    assert r.status_code in (200, 201), r.text

    member_token = client.post(
        "/api/v1/auth/login", json={"email": "member@b.com", "password": "secret123"}
    ).json()["access_token"]

    # 成员能看（列表），不能发布
    assert client.get("/api/v1/rules/packs", headers=_headers(member_token)).status_code == 200
    r = client.post("/api/v1/rules/packs", json={"pack_json": _pack()}, headers=_headers(member_token))
    assert r.status_code in (401, 403)


def test_client_pull_requires_valid_token(client):
    token = register_and_login(client)
    _register_agent(client, token)

    assert client.get("/api/v1/rules/pack").status_code == 401
    assert client.get("/api/v1/rules/pack", headers={"X-Sync-Token": "nope"}).status_code == 401


def test_pull_before_any_publish_is_404_with_hint(client):
    token = register_and_login(client)
    _, sync_token = _register_agent(client, token)
    r = client.get("/api/v1/rules/pack", headers={"X-Sync-Token": sync_token})
    assert r.status_code == 404
    assert "规则包" in r.json()["error"]["message"]
