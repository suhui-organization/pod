"""加固报告上传与查看：租户隔离、大小上限、列表不带正文。"""

from tests.conftest import register_and_login


def _headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _register_agent(client, token, name="mac-mini"):
    r = client.post("/api/v1/agents", json={"name": name}, headers=_headers(token))
    return r.json()["agent"]["id"], r.json()["sync_token"]


def _payload(**overrides) -> dict:
    body = {
        "generated_at": "2026-09-12T10:00:00.000Z",
        "rules_version": "2026.09.12",
        "high": 3,
        "medium": 2,
        "low": 0,
        "mcp_servers": 5,
        "exposed_secrets": 1,
        "broken_chains": 0,
        "report_md": "# pod 加固审计报告\n\n内容…",
        "findings_json": '{"format": "pod-harden-findings/v1", "findings": []}',
    }
    body.update(overrides)
    return body


def test_upload_then_list_and_detail(client):
    token = register_and_login(client)
    agent_id, sync_token = _register_agent(client, token)

    r = client.post("/api/v1/harden/reports", json=_payload(), headers={"X-Sync-Token": sync_token})
    assert r.status_code == 201, r.text
    assert r.json()["report"]["high"] == 3

    # 列表：带 agent 名与计数，不带正文
    rows = client.get("/api/v1/harden/reports", headers=_headers(token)).json()["reports"]
    assert len(rows) == 1
    assert rows[0]["agent_name"] == "mac-mini"
    assert rows[0]["high"] == 3 and rows[0]["exposed_secrets"] == 1
    assert "report_md" not in rows[0]

    # 详情：带正文
    detail = client.get(f"/api/v1/harden/reports/{rows[0]['id']}", headers=_headers(token)).json()["report"]
    assert detail["report_md"].startswith("# pod 加固审计报告")
    assert detail["findings_json"].startswith('{"format"')
    assert detail["agent_id"] == agent_id


def test_list_can_filter_by_agent(client):
    token = register_and_login(client)
    a1, t1 = _register_agent(client, token, "mac-mini")
    a2, t2 = _register_agent(client, token, "mac-book")
    client.post("/api/v1/harden/reports", json=_payload(), headers={"X-Sync-Token": t1})
    client.post("/api/v1/harden/reports", json=_payload(generated_at="2026-09-13T10:00:00.000Z"), headers={"X-Sync-Token": t2})

    rows = client.get(f"/api/v1/harden/reports?agent_id={a1}", headers=_headers(token)).json()["reports"]
    assert len(rows) == 1
    assert rows[0]["agent_id"] == a1


def test_upload_requires_valid_token(client):
    assert client.post("/api/v1/harden/reports", json=_payload()).status_code == 401
    assert (
        client.post("/api/v1/harden/reports", json=_payload(), headers={"X-Sync-Token": "nope"}).status_code
        == 401
    )


def test_rejects_broken_findings_json_and_oversized_report(client):
    token = register_and_login(client)
    _, sync_token = _register_agent(client, token)
    r = client.post(
        "/api/v1/harden/reports",
        json=_payload(findings_json="{not json"),
        headers={"X-Sync-Token": sync_token},
    )
    assert r.status_code == 400

    r = client.post(
        "/api/v1/harden/reports",
        json=_payload(report_md="x" * 900_000),
        headers={"X-Sync-Token": sync_token},
    )
    assert r.status_code == 422  # 超出字段上限，由 pydantic 拦下


def test_reports_are_tenant_scoped(client):
    token = register_and_login(client, email="a@b.com")
    _, sync_token = _register_agent(client, token)
    client.post("/api/v1/harden/reports", json=_payload(), headers={"X-Sync-Token": sync_token})
    report_id = client.get("/api/v1/harden/reports", headers=_headers(token)).json()["reports"][0]["id"]

    other = register_and_login(client, email="c@d.com")
    assert client.get("/api/v1/harden/reports", headers=_headers(other)).json()["reports"] == []
    assert client.get(f"/api/v1/harden/reports/{report_id}", headers=_headers(other)).status_code == 404
