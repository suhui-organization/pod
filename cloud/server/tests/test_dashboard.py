"""仪表盘摘要：Agent 活跃度的双口径（累计 vs 近 7 天）与控制平面事件计数。"""

from hashlib import sha256

from tests.conftest import register_and_login


def _headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _register_agent(client, token, name="agent-a"):
    r = client.post("/api/v1/agents", json={"name": name}, headers=_headers(token))
    return r.json()["agent"]["id"], r.json()["sync_token"]


def _events(count: int, kind: str, server: str, start_seq: int = 1, prev: str = ""):
    events = []
    ph = prev
    for i in range(count):
        seq = start_seq + i
        body = {
            "seq": seq,
            "ts": f"2026-09-11T00:00:{seq:02d}Z",
            "kind": kind,
            "server": server,
            "tool": "read_file" if kind == "tool-call" else "hook",
            "args_hash": sha256(f"{kind}{seq}".encode()).hexdigest(),
            "decision": "allow",
            "outcome": "ok",
            "approver": "",
            "reason": f"{kind}-{seq}",
            "policy_version": "0.1.0",
            "enforced": True,
            "prev_hash": ph,
        }
        body["hash"] = sha256(str(sorted(body.items())).encode()).hexdigest()
        events.append(body)
        ph = body["hash"]
    return events


def _sync(client, sync_token: str, events: list):
    return client.post(
        "/api/v1/sync/events", json={"events": events}, headers={"X-Sync-Token": sync_token}
    )


def test_agent_activity_has_both_accumulated_and_recent(client):
    token = register_and_login(client)
    _, sync_token = _register_agent(client, token)
    assert _sync(client, sync_token, _events(3, "tool-call", "filesystem")).status_code == 200
    assert _sync(client, sync_token, _events(2, "hook", "control")).status_code == 200

    body = client.get("/api/v1/dashboard/summary", headers=_headers(token)).json()
    rows = body["events"]["per_agent"]
    assert len(rows) == 1
    row = rows[0]
    assert row["agent"] == "agent-a"
    # 两个口径都要有：累计值只增不减，近 7 天才是"活跃度"
    assert row["events"] == 3
    assert row["events_recent"] == 3
    assert row["control"] == 2
    assert row["control_recent"] == 2
    # 控制平面事件单独统计，不与工具调用混算
    assert body["events"]["control_total"] == 2
    assert body["events"]["control_by_kind_7d"] == {"hook": 2}


def test_agent_without_events_still_listed(client):
    token = register_and_login(client)
    _register_agent(client, token, name="idle-agent")
    body = client.get("/api/v1/dashboard/summary", headers=_headers(token)).json()
    rows = body["events"]["per_agent"]
    assert [r["agent"] for r in rows] == ["idle-agent"]
    assert rows[0]["events"] == 0
    assert rows[0]["events_recent"] == 0


def test_activity_sorted_by_recent_activity(client):
    token = register_and_login(client)
    _, quiet = _register_agent(client, token, name="quiet")
    _, busy = _register_agent(client, token, name="busy")
    # busy 有很多累计事件但都是旧的（ts 早，synced_at 是入库时间所以仍算近 7 天）
    assert _sync(client, busy, _events(5, "tool-call", "filesystem")).status_code == 200
    assert _sync(client, quiet, _events(1, "tool-call", "filesystem")).status_code == 200
    rows = client.get("/api/v1/dashboard/summary", headers=_headers(token)).json()["events"]["per_agent"]
    # 近 7 天事件多的排前面
    assert [r["agent"] for r in rows] == ["busy", "quiet"]
