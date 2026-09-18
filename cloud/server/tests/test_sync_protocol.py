# 端 A <-> 端 B 的协议契约（服务端一侧）。
#
# 守四件事，每条都对应一种真实会发生的错配：
# 1. 心跳能收下"这台机器现在什么状态"（只含计数），并给控制台；
# 2. 版本要记下来——否则控制台无法回答"这台机器装的是哪一版"；
# 3. 老客户端不带 body / 不带 header，心跳照常 200（可用性优先）；
# 4. 客户端协议过旧时响应里明说 client_outdated + 说明，而不是静默少一半能力。

from tests.conftest import register_and_login


def _register_agent(client, token, name="mac-mini"):
    r = client.post("/api/v1/agents", json={"name": name}, headers={"Authorization": f"Bearer {token}"})
    return r.json()["agent"]["id"], r.json()["sync_token"]


HEALTH = {
    "audit": {"chains": 2, "broken": 0, "last_call_at": "2026-09-18T06:00:00.000Z"},
    "coverage": {"servers": 3, "unmanaged": 1},
    "guard": {"high": 2, "medium": 1, "low": 0, "scanned_at": "2026-09-18T06:00:00.000Z"},
    "errors": [],
}


def test_ping_stores_health_and_version(client):
    token = register_and_login(client)
    agent_id, sync_token = _register_agent(client, token)

    r = client.post(
        "/api/v1/sync/ping",
        json={"protocol_version": 1, "pod_version": "0.4.0", "health": HEALTH},
        headers={"X-Sync-Token": sync_token, "X-Pod-Protocol": "1", "X-Pod-Version": "0.4.0"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["pong"] is True
    assert body["server_protocol"] >= 1
    assert body["client_outdated"] is False

    agents = client.get("/api/v1/agents", headers={"Authorization": f"Bearer {token}"}).json()["agents"]
    row = next(a for a in agents if a["id"] == agent_id)
    assert row["pod_version"] == "0.4.0"
    assert row["protocol_version"] == 1
    assert row["health"]["audit"]["broken"] == 0
    assert row["health"]["coverage"]["unmanaged"] == 1
    assert row["health"]["guard"]["high"] == 2
    assert row["health_at"] is not None


def test_ping_from_old_client_without_body_still_works(client):
    # v0.4.0 之前的客户端：不带 body、不带 header。心跳必须照常成功。
    token = register_and_login(client)
    agent_id, sync_token = _register_agent(client, token)

    r = client.post("/api/v1/sync/ping", headers={"X-Sync-Token": sync_token})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["client_outdated"] is True
    assert "协议版本" in body["message"]

    agents = client.get("/api/v1/agents", headers={"Authorization": f"Bearer {token}"}).json()["agents"]
    row = next(a for a in agents if a["id"] == agent_id)
    assert row["protocol_version"] == 0
    assert row["health"] is None


def test_events_headers_also_record_version(client):
    # 只有事件上来、心跳被防火墙挡掉时，也要能记下客户端版本。
    token = register_and_login(client)
    agent_id, sync_token = _register_agent(client, token)

    r = client.post(
        "/api/v1/sync/events",
        json={
            "events": [
                {
                    "seq": 1,
                    "ts": "2026-09-18T06:00:00.000Z",
                    "kind": "tool-call",
                    "server": "fs",
                    "tool": "read_file",
                    "args_hash": "a" * 64,
                    "decision": "allow",
                    "outcome": "ok",
                    "prev_hash": "",
                    "hash": "b" * 64,
                }
            ]
        },
        headers={"X-Sync-Token": sync_token, "X-Pod-Protocol": "1", "X-Pod-Version": "0.4.0"},
    )
    assert r.status_code == 200, r.text

    agents = client.get("/api/v1/agents", headers={"Authorization": f"Bearer {token}"}).json()["agents"]
    row = next(a for a in agents if a["id"] == agent_id)
    assert row["pod_version"] == "0.4.0"
    assert row["protocol_version"] == 1
