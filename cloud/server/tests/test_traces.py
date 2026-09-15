"""调用链追踪：任务聚类、窗口过滤，以及"窗口里没数据"时的最近一条回填。

回填是给空态用的：窗口按**事件时间 ts** 过滤，而机器可能是几天后才把攒下的
审计补传上云。没有 last_event_at，界面只能说"暂无数据"，用户会把"数据太旧、
窗口够不着"误读成"压根没采到"——这正是线上踩过的坑。
"""

import re
from datetime import datetime, timedelta
from hashlib import sha256

from tests.conftest import register_and_login


def _headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _register_agent(client, token, name="codex"):
    r = client.post("/api/v1/agents", json={"name": name}, headers=_headers(token))
    return r.json()["agent"]["id"], r.json()["sync_token"]


def _events(
    count: int,
    server: str,
    ts_at: datetime,
    tools=("read_file", "write_file", "delete_file"),
    start_seq: int = 1,
    prev: str = "",
):
    """造一条哈希链：每 30 秒一次调用，delete_file 判 deny，其余 allow。"""
    events = []
    ph = prev
    for i in range(count):
        seq = start_seq + i
        tool = tools[i % len(tools)]
        body = {
            "seq": seq,
            "ts": (ts_at + timedelta(seconds=30 * i)).isoformat(timespec="milliseconds") + "Z",
            "server": server,
            "tool": tool,
            "args_hash": sha256(f"{server}{seq}".encode()).hexdigest(),
            "decision": "deny" if tool == "delete_file" else "allow",
            "outcome": "blocked" if tool == "delete_file" else "ok",
            "approver": "",
            "reason": f"{server}-{seq}",
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


def test_window_filters_by_event_time_but_reports_last_event(client):
    """审计补传（事件时间旧、同步时间新）：窗口内为空，但要如实回填最近一条。"""
    token = register_and_login(client)
    _, sync_token = _register_agent(client, token)
    old = datetime.utcnow() - timedelta(days=12)
    assert _sync(client, sync_token, _events(4, "filesystem", old)).status_code == 200

    body = client.get("/api/v1/traces?minutes=1440", headers=_headers(token)).json()
    assert body["tasks"] == []  # 12 天前的事件不在 24 小时窗口里
    assert body["last_event_at"] is not None
    assert re.match(r"^\d{4}-\d{2}-\d{2}T", body["last_event_at"])
    assert body["last_event_at"].startswith(old.strftime("%Y-%m-%d"))
    # 同步时间就是刚才上传的 —— "机器刚同步过" 与 "最近一次调用在 12 天前" 是两件事
    assert body["last_synced_at"] is not None
    assert body["last_synced_at"].startswith(datetime.utcnow().strftime("%Y-%m-%d"))

    wide = client.get("/api/v1/traces?minutes=43200", headers=_headers(token)).json()
    assert len(wide["tasks"]) == 1
    task = wide["tasks"][0]
    assert task["call_count"] == 4
    # 工具循环 read_file/write_file/delete_file/read_file → 3 allow + 1 deny
    assert task["decisions"] == {"allow": 3, "deny": 1}
    assert task["calls"][1]["inter_gap_seconds"] == 30
    assert task["duration_seconds"] == 90


def test_no_events_at_all_reports_nulls(client):
    """全新租户：空态不该编造时间，两个字段都为空。"""
    token = register_and_login(client)
    body = client.get("/api/v1/traces", headers=_headers(token)).json()
    assert body["tasks"] == []
    assert body["last_event_at"] is None
    assert body["last_synced_at"] is None


def test_gap_splits_tasks(client):
    """相邻调用间隔 > gap 分钟切新任务（默认 15 分钟），任务按新→旧排序。"""
    token = register_and_login(client)
    _, sync_token = _register_agent(client, token)
    now = datetime.utcnow() - timedelta(minutes=2)
    first = _events(2, "filesystem", now)
    second = _events(
        3, "filesystem", now + timedelta(minutes=40), tools=("search_files",), start_seq=3, prev=first[-1]["hash"]
    )
    assert _sync(client, sync_token, first + second).status_code == 200

    body = client.get("/api/v1/traces?minutes=1440", headers=_headers(token)).json()
    assert len(body["tasks"]) == 2
    assert {t["call_count"] for t in body["tasks"]} == {2, 3}
    assert body["tasks"][0]["started_at"] > body["tasks"][1]["started_at"]
