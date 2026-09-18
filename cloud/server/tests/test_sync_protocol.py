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


INVENTORY = {
    "inventory": {
        "pod_version": "0.4.0",
        "rules_version": "1",
        "scanned_at": "2026-09-18T06:00:00.000Z",
        "coverage": {"servers": 2, "unmanaged": 1},
        "harnesses": [
            {"id": "claude-code", "label": "Claude Code", "installed": True, "managed": True, "managed_by": ["policy"]},
            {"id": "codex", "label": "Codex", "installed": True, "managed": False, "managed_by": []},
        ],
        "servers": [
            {"name": "github", "harness": "claude-code", "transport": "stdio", "behind_gateway": False,
             "record_only": False, "scope": "user", "package": "@modelcontextprotocol/server-github", "pinned": False},
            {"name": "fs", "harness": "codex", "transport": "stdio", "behind_gateway": True,
             "record_only": True, "scope": "user", "package": "", "pinned": False},
        ],
    }
}

FINDINGS = {
    "findings": {
        "scanned_at": "2026-09-18T06:00:00.000Z",
        "totals": {"high": 3, "medium": 1, "low": 0},
        "findings": [
            {"source": "guard", "key": "AG-03", "severity": "high", "harness": "claude-code", "count": 2},
            {"source": "guard", "key": "AG-12", "severity": "high", "harness": "machine", "count": 1},
            {"source": "posture", "key": "hook", "severity": "medium", "harness": "machine", "count": 1},
        ],
    }
}


def _push_inventory(client, sync_token, payload=INVENTORY):
    return client.post("/api/v1/sync/inventory", json=payload, headers={"X-Sync-Token": sync_token})


def _push_findings(client, sync_token, payload=FINDINGS):
    return client.post("/api/v1/sync/findings", json=payload, headers={"X-Sync-Token": sync_token})


def test_inventory_lands_and_is_exposed_on_the_agent(client):
    """② 资产：本机纳管的 harness / 绕过网关的 server，要出现在云端资产视图里。"""
    token = register_and_login(client)
    agent_id, sync_token = _register_agent(client, token)
    assert _push_inventory(client, sync_token).status_code == 200

    agents = client.get("/api/v1/agents", headers={"Authorization": f"Bearer {token}"}).json()["agents"]
    row = next(a for a in agents if a["id"] == agent_id)
    assert {h["id"] for h in row["assets"]["harnesses"]} == {"claude-code", "codex"}
    assert row["assets"]["unmanaged"] == 1
    assert row["inventory_at"] is not None
    # 隐私：资产里不该出现任何路径或命令行
    import json as _json

    assert "/Users" not in _json.dumps(row["assets"])
    assert "npx" not in _json.dumps(row["assets"])


def test_inventory_is_a_snapshot_not_an_append(client):
    """资产是快照：第二次上报只留新的那批（server 被删掉时云端要跟着消失）。"""
    token = register_and_login(client)
    agent_id, sync_token = _register_agent(client, token)
    _push_inventory(client, sync_token)
    shrink = {
        "inventory": {
            **INVENTORY["inventory"],
            "servers": [INVENTORY["inventory"]["servers"][1]],
            "harnesses": [INVENTORY["inventory"]["harnesses"][0]],
        }
    }
    _push_inventory(client, sync_token, shrink)
    agents = client.get("/api/v1/agents", headers={"Authorization": f"Bearer {token}"}).json()["agents"]
    row = next(a for a in agents if a["id"] == agent_id)
    assert [s["name"] for s in row["assets"]["servers"]] == ["fs"]
    assert [h["id"] for h in row["assets"]["harnesses"]] == ["claude-code"]


def test_findings_land_and_shrink_on_recheck(client):
    """③ 发现：修好之后下次上报就消失，不在云端永远留一条红。"""
    token = register_and_login(client)
    agent_id, sync_token = _register_agent(client, token)
    assert _push_findings(client, sync_token).status_code == 200

    agents = client.get("/api/v1/agents", headers={"Authorization": f"Bearer {token}"}).json()["agents"]
    row = next(a for a in agents if a["id"] == agent_id)
    assert row["findings"]["high"] == 3
    assert row["findings"]["medium"] == 1
    assert any(f["key"] == "AG-03" for f in row["findings"]["rows"])
    assert row["findings_at"] is not None

    empty = {"findings": {"scanned_at": "2026-09-18T07:00:00.000Z", "totals": {}, "findings": []}}
    _push_findings(client, sync_token, empty)
    agents = client.get("/api/v1/agents", headers={"Authorization": f"Bearer {token}"}).json()["agents"]
    row = next(a for a in agents if a["id"] == agent_id)
    assert row["findings"]["rows"] == []
    assert row["findings"]["high"] == 0


def test_inventory_and_findings_require_a_valid_token(client):
    register_and_login(client)
    assert client.post("/api/v1/sync/inventory", json=INVENTORY).status_code == 401
    assert client.post("/api/v1/sync/findings", json=FINDINGS).status_code == 401
    assert (
        client.post("/api/v1/sync/inventory", json=INVENTORY, headers={"X-Sync-Token": "nope"}).status_code == 401
    )


def test_dashboard_aggregates_assets_and_findings_across_agents(client):
    """Dashboard：跨机器聚合"还有多少 server 绕过网关"与"扫出多少 high"。"""
    token = register_and_login(client)
    _, token_a = _register_agent(client, token, "mac-mini")
    _, token_b = _register_agent(client, token, "linux-box")
    _push_inventory(client, token_a)
    _push_inventory(client, token_b)
    _push_findings(client, token_a)
    _push_findings(client, token_b)

    summary = client.get("/api/v1/dashboard/summary", headers={"Authorization": f"Bearer {token}"}).json()
    assert summary["assets"]["servers"] == 4  # 两台机器 × 2 个 server
    assert summary["assets"]["unmanaged"] == 2
    assert summary["assets"]["agents_with_unmanaged"] == 2
    assert summary["findings"]["totals"]["high"] == 6  # 两台机器 × 3
    assert summary["findings"]["top"][0]["key"] == "AG-03"
