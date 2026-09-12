"""Pod Cloud：Agent 资产注册/列表/轮换/删除 + 平台自动推断。"""

from tests.conftest import register_and_login


def _headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def test_register_infers_platform(client):
    token = register_and_login(client)
    r = client.post("/api/v1/agents", json={"name": "openclaw-main"}, headers=_headers(token))
    assert r.status_code == 201
    body = r.json()
    assert body["agent"]["platform"] == "openclaw"
    assert body["agent"]["status"] == "offline"
    # 一次性明文 token
    assert len(body["sync_token"]) >= 40


def test_register_infers_other_and_explicit_override(client):
    token = register_and_login(client)
    r1 = client.post("/api/v1/agents", json={"name": "macbook-01"}, headers=_headers(token))
    assert r1.json()["agent"]["platform"] == "other"
    r2 = client.post(
        "/api/v1/agents", json={"name": "weird-name", "platform": "cursor"}, headers=_headers(token)
    )
    assert r2.json()["agent"]["platform"] == "cursor"


def test_register_requires_name(client):
    token = register_and_login(client)
    r = client.post("/api/v1/agents", json={"name": ""}, headers=_headers(token))
    assert r.status_code == 422


def test_list_agents_and_rotate_token(client):
    token = register_and_login(client)
    r = client.post("/api/v1/agents", json={"name": "hermes"}, headers=_headers(token))
    agent_id = r.json()["agent"]["id"]
    old_token = r.json()["sync_token"]

    lst = client.get("/api/v1/agents", headers=_headers(token)).json()
    assert len(lst["agents"]) == 1
    assert lst["agents"][0]["name"] == "hermes"
    assert lst["agents"][0]["platform"] == "hermes"

    rot = client.post(f"/api/v1/agents/{agent_id}/rotate-token", headers=_headers(token))
    assert rot.status_code == 200
    assert rot.json()["sync_token"] != old_token
    assert len(rot.json()["sync_token"]) >= 40


def test_remove_agent(client):
    token = register_and_login(client)
    r = client.post("/api/v1/agents", json={"name": "codex"}, headers=_headers(token))
    agent_id = r.json()["agent"]["id"]
    d = client.delete(f"/api/v1/agents/{agent_id}", headers=_headers(token))
    assert d.status_code == 200
    assert client.get("/api/v1/agents", headers=_headers(token)).json()["agents"] == []


def test_agents_require_auth(client):
    r = client.get("/api/v1/agents")
    assert r.status_code in (401, 403)


def test_setup_script_returns_install_command(client):
    token = register_and_login(client)
    r = client.post("/api/v1/agents", json={"name": "openclaw-main"}, headers=_headers(token))
    agent = r.json()["agent"]
    sync_token = r.json()["sync_token"]

    s = client.get(f"/api/v1/agent-setup/{agent['id']}/{sync_token}")
    assert s.status_code == 200
    assert s.headers["content-type"].startswith("text/x-shellscript")
    body = s.text
    # 脚本内嵌 agent 信息与写入逻辑
    assert "openclaw-main" in body
    assert f"agent_id" in body
    assert "cloud.json" in body
    assert "pod sync" in body
    assert f"api_url" in body


def test_setup_script_installs_periodic_sync(client):
    """接入脚本必须装定时同步：熔断下发依赖机器主动拉，不装通道就是死的。"""
    token = register_and_login(client)
    r = client.post("/api/v1/agents", json={"name": "mac-mini"}, headers=_headers(token))
    agent = r.json()["agent"]
    body = client.get(f"/api/v1/agent-setup/{agent['id']}/{r.json()['sync_token']}").text
    for needle in ("install_schedule", "dev.podsec.sync.plist", "pod-sync.timer", "crontab -", "POD_NO_SCHEDULE"):
        assert needle in body, needle


def test_setup_script_has_no_unbraced_var_before_multibyte(client):
    """回归：bash 在 C.UTF-8 下会把紧跟 `$VAR` 的多字节字符开头字节吃进变量名，
    结果是变量消失 + 汉字乱码（`$SCHED——` 实际输出 `—` 少一个字节）。
    生成脚本里凡 `$VAR` 后面紧跟非 ASCII 的，都必须写成 `${VAR}`。"""
    import re

    token = register_and_login(client)
    r = client.post("/api/v1/agents", json={"name": "mac-mini"}, headers=_headers(token))
    body = client.get(f"/api/v1/agent-setup/{r.json()['agent']['id']}/{r.json()['sync_token']}").text
    pattern = re.compile(rb"\$[A-Za-z_][A-Za-z0-9_]*")
    offenders = []
    for line in body.split("\n"):
        raw = line.encode("utf-8")
        for m in pattern.finditer(raw):
            nxt = raw[m.end() : m.end() + 1]
            if nxt and nxt[0] >= 0x80:
                offenders.append(line.strip())
    assert offenders == [], f"这些行会让变量展开错乱：{offenders}"


def test_setup_script_rejects_bad_token(client):
    token = register_and_login(client)
    r = client.post("/api/v1/agents", json={"name": "hermes"}, headers=_headers(token))
    agent = r.json()["agent"]
    s = client.get(f"/api/v1/agent-setup/{agent['id']}/wrong-token-xyz")
    assert s.status_code == 401
