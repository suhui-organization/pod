"""连通性探测要认得推理模型：别把"预算被 reasoning 吃掉"误报成模型不可用。

线上真实误报：租户配的是推理模型，探测只给 16 个 token，服务端把预算全用在
reasoning 通道上，content 为空、finish_reason=length —— 接口明明是通的，
自检却报「大模型可用性：调用失败：模型返回了空内容」。
"""

import httpx
import pytest

from app.services import llm


def _cfg() -> llm.LlmConfig:
    return llm.LlmConfig(
        provider="deepseek",
        model="deepseek-flash",
        api_key="sk-test",
        endpoint="https://api.example.com/chat/completions",
        base_url="",
    )


class _Resp:
    status_code = 200
    text = "{}"

    def __init__(self, payload):
        self._payload = payload

    def json(self):
        return self._payload


def _payload(content: str, reasoning: str = "", finish: str = "stop") -> dict:
    msg = {"role": "assistant", "content": content}
    if reasoning:
        msg["reasoning_content"] = reasoning
    return {
        "model": "deepseek-flash",
        "choices": [{"index": 0, "message": msg, "finish_reason": finish}],
        "usage": {"completion_tokens": 16, "completion_tokens_details": {"reasoning_tokens": 16}},
    }


def test_probe_accepts_reasoning_only_response(monkeypatch):
    """推理模型只回 reasoning 通道 → 判定为"通"（业务侧仍按空内容失败）。"""
    monkeypatch.setattr(
        llm.httpx, "post", lambda *a, **k: _Resp(_payload("", "让我想想……", finish="length"))
    )
    res = llm.test_connection(_cfg())
    assert res["ok"] is True, res
    assert "推理" in res["sample"]


def test_business_call_still_rejects_empty_content(monkeypatch):
    """放宽只给探测用：AI 摘要这类要文本的功能，空内容必须继续报错。"""
    monkeypatch.setattr(
        llm.httpx, "post", lambda *a, **k: _Resp(_payload("", "让我想想……", finish="length"))
    )
    with pytest.raises(llm.LlmError, match="空内容"):
        llm.call_chat(_cfg(), [{"role": "user", "content": "写个摘要"}], feature="alerts.summary")


def test_probe_still_fails_on_truly_empty_response(monkeypatch):
    """连 reasoning 都没有的空壳响应，仍要如实报错（不能把放宽当成放水）。"""
    monkeypatch.setattr(llm.httpx, "post", lambda *a, **k: _Resp(_payload("")))
    res = llm.test_connection(_cfg())
    assert res["ok"] is False
    assert "空内容" in res["error"]


def test_probe_uses_a_budget_big_enough_for_reasoning():
    """探测别再回到 16：抓真实请求体里的 max_tokens。"""
    seen = {}

    def fake_post(url, json=None, headers=None, timeout=None):
        seen.update(json or {})
        return _Resp(_payload("OK"))

    import unittest.mock

    with unittest.mock.patch.object(llm.httpx, "post", fake_post):
        assert llm.test_connection(_cfg())["ok"] is True
    assert seen["max_tokens"] >= 128


def test_http_error_mapping_unchanged(monkeypatch):
    """401/429 这些真实故障的文案不能被这次放宽影响。"""
    monkeypatch.setattr(
        llm.httpx, "post", lambda *a, **k: type("R", (), {"status_code": 401, "text": "{}"})()
    )
    res = llm.test_connection(_cfg())
    assert res["ok"] is False and "401" in res["error"]
