"""Pod Cloud 合规报告测试：GDPR 报告内容与权限。"""

from hashlib import sha256

from tests.conftest import register_and_login


def _hash_chain(seq_start: int, count: int, server: str = "filesystem"):
    """构造一段连续哈希链事件（与服务端 /sync/events 同构）。"""
    events = []
    prev = ""
    for i in range(count):
        seq = seq_start + i
        body = {
            "seq": seq,
            "ts": f"2026-09-01T00:00:{seq:02d}Z",
            "server": server,
            "tool": "read_file" if seq % 2 else "write_file",
            "args_hash": sha256(f"args{seq}".encode()).hexdigest(),
            "decision": "approve" if seq % 5 == 0 else "allow",
            "outcome": "ok",
            "approver": "walden" if seq % 5 == 0 else "",
            "reason": "manual review" if seq % 5 == 0 else "",
            "policy_version": "0.1.0",
            "enforced": True,
            "prev_hash": prev,
        }
        body["hash"] = sha256(str(sorted(body.items())).encode()).hexdigest()
        events.append(body)
        prev = body["hash"]
    return events


def _setup_tenant_with_events(client, token: str) -> None:
    """建 agent + 同步 6 条事件（含审批记录）。"""
    r = client.post(
        "/api/v1/agents",
        json={"name": "openclaw-main", "platform": "openclaw"},
        headers={"Authorization": f"Bearer {token}"},
    )
    sync_token = r.json()["sync_token"]
    events = _hash_chain(1, 6)
    r = client.post(
        "/api/v1/sync/events",
        json={"events": events},
        headers={"X-Sync-Token": sync_token},
    )
    assert r.status_code == 200, r.text


def test_gdpr_report_requires_admin(client):
    token = register_and_login(client)
    r = client.get("/api/v1/reports/gdpr", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200  # 第一个注册用户是 admin


def test_gdpr_report_aggregates_events(client):
    token = register_and_login(client)
    _setup_tenant_with_events(client, token)
    r = client.get("/api/v1/reports/gdpr?days=30", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    body = r.json()
    assert body["activities"]["total_events"] == 6
    assert body["activities"]["by_server"]["filesystem"] == 6
    assert body["activities"]["by_decision"]["allow"] == 5  # 6 条中 seq%5==0 的是 approve（seq 5）
    assert body["activities"]["by_decision"]["approve"] == 1
    assert body["activities"]["approvals"][0]["approver"] == "walden"
    assert body["agents"][0]["name"] == "openclaw-main"
    assert body["agents"][0]["events"] == 6


def test_gdpr_report_markdown_download(client):
    token = register_and_login(client)
    _setup_tenant_with_events(client, token)
    r = client.get("/api/v1/reports/gdpr?format=markdown", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/markdown")
    md = r.text
    assert "# GDPR 合规报告" in md
    assert "## 1. 处理活动记录" in md
    assert "## 3. 技术安全措施" in md
    assert "SHA-256 哈希链" in md
    assert "walden" in md  # 审批人出现在报告中


def _sync_with_reasons(client, token: str, events: list) -> None:
    """按给定事件列表同步（直接 POST sync/events）。"""
    r = client.post(
        "/api/v1/agents",
        json={"name": "alert-agent", "platform": "openclaw"},
        headers={"Authorization": f"Bearer {token}"},
    )
    sync_token = r.json()["sync_token"]
    r = client.post(
        "/api/v1/sync/events",
        json={"events": events},
        headers={"X-Sync-Token": sync_token},
    )
    assert r.status_code == 200, r.text


def test_cloud_alerts_generated_on_sync(client):
    token = register_and_login(client)
    # 一次 secret_leak + 一次注入信号 + 5 条 deny（触发 burst）
    events = []
    prev = ""
    for i in range(1, 8):
        reason = ""
        decision = "allow"
        if i == 1:
            reason = "secret_leak: output matched pattern ghp_"
        elif i == 2:
            reason = "injection_suspect: output contains prompt-override"
        elif i >= 3:
            decision = "deny"
            reason = "denied by rule"
        body = {
            "seq": i,
            "ts": f"2026-09-01T00:00:{i:02d}Z",
            "server": "filesystem",
            "tool": "read_file",
            "args_hash": sha256(f"a{i}".encode()).hexdigest(),
            "decision": decision,
            "outcome": "blocked" if decision == "deny" else "ok",
            "reason": reason,
            "policy_version": "0.1.0",
            "prev_hash": prev,
        }
        body["hash"] = sha256(str(sorted(body.items())).encode()).hexdigest()
        events.append(body)
        prev = body["hash"]
    _sync_with_reasons(client, token, events)

    r = client.get("/api/v1/alerts", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    kinds = {a["kind"] for a in r.json()["alerts"]}
    assert "secret_leak" in kinds
    assert "injection_suspect" in kinds
    assert "deny_burst" in kinds
    leak = next(a for a in r.json()["alerts"] if a["kind"] == "secret_leak")
    assert leak["severity"] == "high"
    assert leak["agent"] == "alert-agent"


def test_timeline_api_filters_and_sorts(client):
    token = register_and_login(client)
    _setup_tenant_with_events(client, token)  # 6 条事件
    r = client.get("/api/v1/timeline?limit=50", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    events = r.json()["events"]
    assert len(events) == 6
    # 新→旧排序（ts 降序）
    ts = [e["ts"] for e in events]
    assert ts == sorted(ts, reverse=True)
    # 字段完整
    e = events[0]
    for field in ("agent", "ts", "server", "tool", "args_hash", "decision", "outcome", "approver", "policy_version"):
        assert field in e
    # 过滤
    r2 = client.get("/api/v1/timeline?tool=write_file", headers={"Authorization": f"Bearer {token}"})
    assert all(e["tool"] == "write_file" for e in r2.json()["events"])
    r3 = client.get("/api/v1/timeline?minutes=1", headers={"Authorization": f"Bearer {token}"})
    assert len(r3.json()["events"]) >= 0


def test_gdpr_report_includes_timeline_section(client):
    token = register_and_login(client)
    _setup_tenant_with_events(client, token)
    r = client.get("/api/v1/reports/gdpr?format=markdown", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    md = r.text
    assert "## 1.5 事件时间线" in md
    assert "证据链节选" in md
    assert "walden" in md  # 审批人出现在时间线
