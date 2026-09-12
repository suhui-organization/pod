# 服务端 i18n：错误文案、接入脚本、Provider 说明按 Accept-Language 切换。

from app.i18n import resolve_locale, t, t_dynamic
from tests.conftest import register_and_login


def test_resolve_locale_picks_supported_language():
    assert resolve_locale("en-US,en;q=0.9") == "en-US"
    assert resolve_locale("zh-CN,zh;q=0.9,en;q=0.8") == "zh-CN"
    # 显式声明了不认识的语言时给英文（开源项目面向英文用户）
    assert resolve_locale("fr-FR,fr;q=0.9") == "en-US"
    # 什么都没有时用中文（默认部署形态）
    assert resolve_locale(None) == "zh-CN"
    # ?lang= 优先于请求头
    assert resolve_locale("zh-CN", "en") == "en-US"


def test_translate_falls_back_to_source():
    # 没翻译过的字符串原样返回，不会变成 key 名或空白
    assert t("这条还没翻译", "en-US") == "这条还没翻译"
    assert t("邮箱已注册", "zh-CN") == "邮箱已注册"
    assert t("邮箱已注册", "en-US") == "This email is already registered"
    # 带数值的文案按模式认领
    assert (
        t_dynamic("当前计划最多 3 个 agent（已用 5）；升级计划后再注册", "en-US")
        == "Your plan allows up to 3 agents (currently 5); upgrade to add more"
    )


def test_error_message_switches_with_accept_language(client):
    register_and_login(client)  # 建一个账号
    body = {"email": "a@b.com", "password": "wrong-password", "client": "web"}

    zh = client.post("/api/v1/auth/login", json=body, headers={"Accept-Language": "zh-CN"})
    assert zh.status_code == 401
    assert zh.json()["error"]["message"] == "邮箱或密码错误"

    en = client.post("/api/v1/auth/login", json=body, headers={"Accept-Language": "en-US"})
    assert en.status_code == 401
    assert en.json()["error"]["message"] == "Wrong email or password"


def test_setup_script_speaks_english(client):
    token = register_and_login(client)
    r = client.post(
        "/api/v1/agents", json={"name": "agent-a"}, headers={"Authorization": f"Bearer {token}"}
    )
    agent_id, sync_token = r.json()["agent"]["id"], r.json()["sync_token"]

    en = client.get(
        f"/api/v1/agent-setup/{agent_id}/{sync_token}", headers={"Accept-Language": "en-US"}
    )
    assert en.status_code == 200
    assert "Wrote" in en.text
    assert "已写入" not in en.text

    zh = client.get(
        f"/api/v1/agent-setup/{agent_id}/{sync_token}", headers={"Accept-Language": "zh-CN"}
    )
    assert "已写入" in zh.text


def test_llm_provider_notes_are_translated(client):
    token = register_and_login(client)
    headers = {"Authorization": f"Bearer {token}"}
    en = client.get("/api/v1/settings/llm", headers={**headers, "Accept-Language": "en-US"}).json()
    assert "国内直连" not in " ".join(p["note"] for p in en["providers"])

    zh = client.get("/api/v1/settings/llm", headers={**headers, "Accept-Language": "zh-CN"}).json()
    assert "国内直连" in " ".join(p["note"] for p in zh["providers"])
