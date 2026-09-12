"""云端下发熔断：期望状态的存取与鉴权边界。

这里只测"云端记的对不对"。**机器侧怎么收敛、以及"云端解不掉人工熔断"那条规则**，
在本地那侧测（apps/cli/test/quarantine-sync.test.ts）——那是真正决定安全性的地方。
"""

from tests.conftest import register_and_login


def _headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _register_agent(client, token, name="mac-mini"):
    r = client.post("/api/v1/agents", json={"name": name}, headers=_headers(token))
    return r.json()["agent"]["id"], r.json()["sync_token"]


def test_quarantine_lifecycle(client):
    token = register_and_login(client)
    agent_id, sync_token = _register_agent(client, token)

    # 初始：未熔断
    r = client.get("/api/v1/sync/quarantine", headers={"X-Sync-Token": sync_token})
    assert r.status_code == 200, r.text
    assert r.json()["quarantined"] is False
    assert r.json()["agent_id"] == agent_id

    # 下发
    r = client.post(
        f"/api/v1/agents/{agent_id}/quarantine",
        json={"reason": "疑似被注入，先切断"},
        headers=_headers(token),
    )
    assert r.status_code == 200, r.text
    assert r.json()["agent"]["quarantined"] is True
    assert r.json()["agent"]["quarantine_reason"] == "疑似被注入，先切断"

    # 机器侧能看到（含原因与下发人）
    body = client.get("/api/v1/sync/quarantine", headers={"X-Sync-Token": sync_token}).json()
    assert body["quarantined"] is True
    assert body["reason"] == "疑似被注入，先切断"
    assert body["since"]
    assert body["by"] == "a@b.com"

    # 幂等：重复下发不改变结果
    client.post(f"/api/v1/agents/{agent_id}/quarantine", json={"reason": "再点一次"}, headers=_headers(token))
    assert client.get("/api/v1/sync/quarantine", headers={"X-Sync-Token": sync_token}).json()["quarantined"] is True

    # 解除
    r = client.delete(f"/api/v1/agents/{agent_id}/quarantine", headers=_headers(token))
    assert r.status_code == 200
    body = client.get("/api/v1/sync/quarantine", headers={"X-Sync-Token": sync_token}).json()
    assert body["quarantined"] is False
    assert body["reason"] == ""


def test_agent_list_exposes_quarantine_state(client):
    token = register_and_login(client)
    agent_id, _ = _register_agent(client, token)
    client.post(f"/api/v1/agents/{agent_id}/quarantine", json={"reason": "x"}, headers=_headers(token))
    agents = client.get("/api/v1/agents", headers=_headers(token)).json()["agents"]
    assert agents[0]["quarantined"] is True
    assert agents[0]["quarantine_reason"] == "x"


def test_quarantine_requires_admin(client):
    token = register_and_login(client)
    agent_id, _ = _register_agent(client, token)
    client.post(
        "/api/v1/users",
        json={"email": "member@b.com", "password": "secret123", "role": "member"},
        headers=_headers(token),
    )
    member = client.post(
        "/api/v1/auth/login", json={"email": "member@b.com", "password": "secret123"}
    ).json()["access_token"]
    r = client.post(f"/api/v1/agents/{agent_id}/quarantine", json={"reason": "x"}, headers=_headers(member))
    assert r.status_code in (401, 403)


def test_quarantine_endpoints_are_tenant_scoped(client):
    """另一个租户的 agent 不能被本租户下发熔断。"""
    token = register_and_login(client, email="a@b.com")
    agent_id, _ = _register_agent(client, token)

    other = register_and_login(client, email="c@d.com")
    r = client.post(f"/api/v1/agents/{agent_id}/quarantine", json={"reason": "x"}, headers=_headers(other))
    assert r.status_code == 404


def test_sync_quarantine_requires_valid_token(client):
    assert client.get("/api/v1/sync/quarantine").status_code == 401
    assert client.get("/api/v1/sync/quarantine", headers={"X-Sync-Token": "nope"}).status_code == 401
