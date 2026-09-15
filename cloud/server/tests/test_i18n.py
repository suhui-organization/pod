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
    # 带占位符时中文也要填充：曾经中文直接返回原文，界面上就出现 "{err}" 这种半成品
    assert t("模型还没配好：{err}", "zh-CN", err="缺 API Key") == "模型还没配好：缺 API Key"
    assert t("模型还没配好：{err}", "en-US", err="missing API key") == "Model is not configured yet: missing API key"
    # 占位符没给全时退回原文，不抛错（错误文案不该再制造一个错误）
    assert t("模型还没配好：{err}", "zh-CN") == "模型还没配好：{err}"
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


def test_llm_features_list_is_translated(client):
    """结构化 payload 不走 translate_detail：能力清单的每个字段都得自己过词表。

    这条曾经漏过——`features` 直接透传 AI_FEATURES，英文界面上整块能力说明是中文。
    """
    token = register_and_login(client)
    headers = {"Authorization": f"Bearer {token}"}
    en = client.get("/api/v1/settings/llm", headers={**headers, "Accept-Language": "en-US"}).json()
    blob = " ".join(f"{f['name']} {f['where']} {f['degraded']}" for f in en["features"])
    assert not any("\u4e00" <= ch <= "\u9fa5" for ch in blob), f"能力清单里还有中文: {blob}"
    assert "Policies" in blob and "AI alert summary" in blob

    zh = client.get("/api/v1/settings/llm", headers={**headers, "Accept-Language": "zh-CN"}).json()
    assert "策略中心" in " ".join(f["where"] for f in zh["features"])


def test_llm_unconfigured_reason_is_translated(client):
    """设置页要回答"为什么不能用 AI"——这句话也必须跟着语言走。"""
    token = register_and_login(client)
    headers = {"Authorization": f"Bearer {token}"}
    en = client.get("/api/v1/settings/llm", headers={**headers, "Accept-Language": "en-US"}).json()
    assert en["configured"] is False
    assert not any("\u4e00" <= ch <= "\u9fa5" for ch in en["reason"]), en["reason"]
    assert "API key" in en["reason"]


def test_catalog_has_no_duplicate_keys():
    """Python dict 的重复键**静默覆盖**——TS 那边 tsc 会报 TS1117，这边没人拦。

    真踩过：加词条时把 provider 那几条又写了一遍，值不同就会悄悄改掉已有翻译。
    """
    import re as _re
    from pathlib import Path

    src = Path(__file__).resolve().parents[1] / "app" / "i18n.py"
    keys = _re.findall(r'^    "([^"]+)":', src.read_text(), _re.MULTILINE)
    dupes = {k for k in keys if keys.count(k) > 1}
    assert not dupes, f"词表里有重复键（会被静默覆盖）: {sorted(dupes)}"
