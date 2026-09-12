"""控制平面事件：同步分流、链连续性、读取接口与聚合。"""

from hashlib import sha256

from app.models import PodControlEvent, SyncEvent
from tests.conftest import register_and_login


def _headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _register_agent(client, token, name="agent-a"):
    r = client.post("/api/v1/agents", json={"name": name}, headers=_headers(token))
    return r.json()["agent"]["id"], r.json()["sync_token"]


def _control_events(count: int, kinds: list[str], start_seq: int = 1, prev: str = ""):
    # 构造一段连续的控制平面哈希链（与 pod 本地 <audit>/<agent>/control.jsonl 同构）
    events = []
    ph = prev
    for i in range(count):
        seq = start_seq + i
        body = {
            "seq": seq,
            "ts": f"2026-09-11T00:00:{seq:02d}Z",
            "kind": kinds[i % len(kinds)],
            "server": "control",  # 链标识，与文件名一致
            "tool": "hook" if kinds[i % len(kinds)] == "hook" else "config",
            "args_hash": sha256(f"ctrl{seq}".encode()).hexdigest(),
            "decision": "allow",
            "outcome": "ok",
            "approver": "",
            "reason": f"posture:finding-{seq}",
            "policy_version": "control",
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


def test_control_events_go_to_their_own_table(client, db):
    token = register_and_login(client)
    _, sync_token = _register_agent(client, token)
    r = _sync(client, sync_token, _control_events(3, ["hook", "config-change"]))
    assert r.status_code == 200
    assert db.query(PodControlEvent).count() == 3
    # 数据平面表不被污染
    assert db.query(SyncEvent).count() == 0
    stored = db.query(PodControlEvent).order_by(PodControlEvent.seq).all()
    assert [e.kind for e in stored] == ["hook", "config-change", "hook"]
    assert stored[0].chain == "control"
    assert stored[0].category == "hook"
    # 链在云端继续串起来
    assert stored[1].prev_hash == stored[0].hash


def test_tool_call_events_still_use_the_data_plane_table(client, db):
    token = register_and_login(client)
    _, sync_token = _register_agent(client, token)
    events = _control_events(2, ["hook"])
    for e in events:
        e["kind"] = "tool-call"
        e["server"] = "filesystem"
    assert _sync(client, sync_token, events).status_code == 200
    assert db.query(SyncEvent).count() == 2
    assert db.query(PodControlEvent).count() == 0


def test_chain_break_is_rejected(client):
    token = register_and_login(client)
    _, sync_token = _register_agent(client, token)
    events = _control_events(2, ["hook"])
    events[1]["prev_hash"] = "0" * 64  # 断链
    r = _sync(client, sync_token, events)
    assert r.status_code == 409
    assert "哈希链断裂" in r.json()["error"]["message"]


def test_mixed_batch_is_rejected(client):
    token = register_and_login(client)
    _, sync_token = _register_agent(client, token)
    events = _control_events(2, ["hook"])
    events[1]["kind"] = "tool-call"
    r = _sync(client, sync_token, events)
    assert r.status_code == 400
    assert "不能混合" in r.json()["error"]["message"]


def test_list_control_events_with_filters_and_severity(client, db):
    token = register_and_login(client)
    aid, sync_token = _register_agent(client, token)
    events = _control_events(3, ["hook", "identity", "metadata"])
    # 委托事件带阻断语义 → 展示级别应为 high（服务端只校验 prev_hash 连续性，
    # 不改 hash 也能改语义字段，这里刻意不伪造链）
    events[1]["kind"] = "delegation"
    events[1]["decision"] = "deny"
    events[1]["outcome"] = "blocked"
    assert _sync(client, sync_token, events).status_code == 200

    body = client.get("/api/v1/control-events", headers=_headers(token)).json()
    assert body["severity_source"] == "derived"
    assert len(body["events"]) == 3
    by_kind = {e["kind"]: e for e in body["events"]}
    assert by_kind["delegation"]["severity"] == "high"
    assert by_kind["hook"]["severity"] == "medium"
    assert by_kind["metadata"]["severity"] == "low"
    assert by_kind["hook"]["agent"] == "agent-a"

    only_hook = client.get("/api/v1/control-events?kind=hook", headers=_headers(token)).json()
    assert [e["kind"] for e in only_hook["events"]] == ["hook"]

    by_agent = client.get(f"/api/v1/control-events?agent_id={aid}", headers=_headers(token)).json()
    assert len(by_agent["events"]) == 3
    other = client.get("/api/v1/control-events?agent_id=999", headers=_headers(token)).json()
    assert other["events"] == []


def test_summary_counts_by_kind_and_severity(client):
    token = register_and_login(client)
    _, sync_token = _register_agent(client, token)
    assert _sync(client, sync_token, _control_events(4, ["hook", "config-change"])).status_code == 200
    s = client.get("/api/v1/control-events/summary", headers=_headers(token)).json()
    assert s["total"] == 4
    assert s["by_kind"] == {"hook": 2, "config-change": 2}
    assert s["by_severity"]["medium"] == 4


def test_control_events_are_tenant_isolated(client):
    token_a = register_and_login(client, email="a@b.com")
    _, sync_a = _register_agent(client, token_a, name="agent-a")
    assert _sync(client, sync_a, _control_events(2, ["hook"])).status_code == 200

    token_b = register_and_login(client, email="c@d.com")
    body = client.get("/api/v1/control-events", headers=_headers(token_b)).json()
    assert body["events"] == []
    assert client.get("/api/v1/control-events/summary", headers=_headers(token_b)).json()["total"] == 0
