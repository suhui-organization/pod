"""找回密码:一次性令牌、防枚举、日志兜底、会话吊销。"""

import logging
import re
from datetime import datetime, timedelta

from app.models import PasswordResetToken
from app.security import hash_reset_token
from tests.conftest import register_and_login


def _h(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _request_reset(client, caplog, email="a@b.com") -> str:
    """申请重置并从服务端日志里取回明文令牌(实例未配 SMTP 时的既定通道)。"""
    with caplog.at_level(logging.WARNING, logger="podcloud.mailer"):
        r = client.post("/api/v1/auth/forgot-password", json={"email": email})
    assert r.status_code == 200
    # 取最后一条:caplog 会累积,同一用例里申请两次时 re.search 会拿到上一次的
    found = re.findall(r"token=([A-Za-z0-9_\-]+)", caplog.text)
    assert found, f"日志里没有重置链接: {caplog.text!r}"
    return found[-1]


def test_forgot_password_does_not_leak_whether_account_exists(client, caplog):
    """这个端点是公开的:响应必须对"已注册"和"没注册"完全一致,否则就是账号枚举器。"""
    register_and_login(client, "a@b.com")
    with caplog.at_level(logging.WARNING, logger="podcloud.mailer"):
        known = client.post("/api/v1/auth/forgot-password", json={"email": "a@b.com"})
        unknown = client.post("/api/v1/auth/forgot-password", json={"email": "nobody@x.com"})
    assert known.status_code == unknown.status_code == 200
    assert known.json() == unknown.json() == {"ok": True}
    # 没注册的邮箱不该产生任何令牌
    assert "nobody@x.com" not in caplog.text


def test_config_tells_where_the_link_goes(client, monkeypatch):
    """投递方式是实例级属性,提前告诉用户,而不是提交后才说。"""
    from app.config import settings

    assert client.get("/api/v1/auth/config").json()["password_reset"] == "log"
    monkeypatch.setattr(settings, "smtp_host", "smtp.example.com")
    assert client.get("/api/v1/auth/config").json()["password_reset"] == "email"


def test_reset_flow_end_to_end(client, caplog):
    register_and_login(client, "a@b.com", "secret123")
    token = _request_reset(client, caplog)

    r = client.post(
        "/api/v1/auth/reset-password",
        json={"token": token, "new_password": "brandnew123"},
    )
    assert r.status_code == 200
    assert client.post("/api/v1/auth/login", json={"email": "a@b.com", "password": "secret123"}).status_code == 401
    assert client.post("/api/v1/auth/login", json={"email": "a@b.com", "password": "brandnew123"}).status_code == 200


def test_reset_token_is_single_use(client, caplog, db):
    register_and_login(client, "a@b.com")
    token = _request_reset(client, caplog)
    assert client.post("/api/v1/auth/reset-password", json={"token": token, "new_password": "brandnew123"}).status_code == 200
    again = client.post("/api/v1/auth/reset-password", json={"token": token, "new_password": "another12345"})
    assert again.status_code == 400


def test_reset_rejects_expired_token(client, caplog, db):
    register_and_login(client, "a@b.com")
    token = _request_reset(client, caplog)
    row = db.query(PasswordResetToken).first()
    row.expires_at = datetime.utcnow() - timedelta(minutes=1)
    db.commit()
    r = client.post("/api/v1/auth/reset-password", json={"token": token, "new_password": "brandnew123"})
    assert r.status_code == 400
    assert "过期" in r.json()["error"]["message"]


def test_reset_rejects_bogus_token(client):
    r = client.post("/api/v1/auth/reset-password", json={"token": "not-a-real-token", "new_password": "brandnew123"})
    assert r.status_code == 400


def test_reset_revokes_existing_sessions(client, caplog):
    """找回密码的真正用途是"我怀疑号被盗了",所以重置必须连带踢掉旧会话。"""
    old_token = register_and_login(client, "a@b.com", "secret123")
    assert client.get("/api/v1/auth/me", headers=_h(old_token)).status_code == 200
    token = _request_reset(client, caplog)
    assert client.post("/api/v1/auth/reset-password", json={"token": token, "new_password": "brandnew123"}).status_code == 200
    assert client.get("/api/v1/auth/me", headers=_h(old_token)).status_code == 401


def test_reset_enforces_password_complexity(client, caplog):
    register_and_login(client, "a@b.com")
    token = _request_reset(client, caplog)
    for weak in ["ab1", "abcdefgh", "12345678"]:
        r = client.post("/api/v1/auth/reset-password", json={"token": token, "new_password": weak})
        assert r.status_code == 400, weak
    # 弱密码失败不该把令牌烧掉,还能正常用一次
    assert client.post("/api/v1/auth/reset-password", json={"token": token, "new_password": "brandnew123"}).status_code == 200


def test_forgot_password_throttles_repeat_requests(client, caplog, db):
    """60 秒内重复申请直接忽略:否则谁都能把某个人的邮箱/日志刷爆。"""
    register_and_login(client, "a@b.com")
    _request_reset(client, caplog)
    caplog.clear()
    client.post("/api/v1/auth/forgot-password", json={"email": "a@b.com"})
    assert db.query(PasswordResetToken).count() == 1
    assert "token=" not in caplog.text


def test_new_request_invalidates_previous_link(client, caplog, db):
    register_and_login(client, "a@b.com")
    first = _request_reset(client, caplog)
    # 越过节流窗口(直接改库里的时间,不动 60 秒逻辑)
    row = db.query(PasswordResetToken).first()
    row.created_at = datetime.utcnow() - timedelta(minutes=5)
    db.commit()
    second = _request_reset(client, caplog)
    assert first != second
    assert client.post("/api/v1/auth/reset-password", json={"token": first, "new_password": "brandnew123"}).status_code == 400
    assert client.post("/api/v1/auth/reset-password", json={"token": second, "new_password": "brandnew123"}).status_code == 200


def test_token_is_stored_hashed(client, caplog, db):
    """库被读走也换不回可用链接。"""
    register_and_login(client, "a@b.com")
    token = _request_reset(client, caplog)
    stored = [r.token_hash for r in db.query(PasswordResetToken).all()]
    assert token not in stored
    assert stored == [hash_reset_token(token)]
