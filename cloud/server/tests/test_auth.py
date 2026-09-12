from tests.conftest import register_and_login


def _h(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def test_register_creates_user_and_default_tenant(client, db):
    r = client.post("/api/v1/auth/register", json={"email": "u@x.com", "password": "secret123", "full_name": "U"})
    assert r.status_code == 200
    data = r.json()
    assert data["email"] == "u@x.com"
    assert data["tenant"]["name"] != ""
    assert "access_token" in data
    assert "refresh_token" in data


def test_register_same_prefix_different_domain_no_conflict(client):
    r1 = client.post("/api/v1/auth/register", json={"email": "a@x.com", "password": "secret123"})
    r2 = client.post("/api/v1/auth/register", json={"email": "a@y.com", "password": "secret123"})
    assert r1.status_code == 200
    assert r2.status_code == 200


def test_register_duplicate_email_409(client):
    client.post("/api/v1/auth/register", json={"email": "u@x.com", "password": "secret123"})
    r = client.post("/api/v1/auth/register", json={"email": "u@x.com", "password": "secret123"})
    assert r.status_code == 409


def test_register_forbidden_in_private_mode(client, monkeypatch):
    from app.config import settings

    monkeypatch.setattr(settings, "is_private", True)
    r = client.post("/api/v1/auth/register", json={"email": "p@x.com", "password": "secret123"})
    assert r.status_code == 403


def test_login_success_and_bad_password(client):
    client.post("/api/v1/auth/register", json={"email": "u@x.com", "password": "secret123"})
    ok = client.post("/api/v1/auth/login", json={"email": "u@x.com", "password": "secret123"})
    assert ok.status_code == 200
    assert "access_token" in ok.json()
    assert "refresh_token" in ok.json()
    bad = client.post("/api/v1/auth/login", json={"email": "u@x.com", "password": "wrong"})
    assert bad.status_code == 401


def test_login_without_membership_403(client, db):
    from app.models import TenantUser

    client.post("/api/v1/auth/register", json={"email": "u@x.com", "password": "secret123"})
    db.query(TenantUser).delete()
    db.commit()
    r = client.post("/api/v1/auth/login", json={"email": "u@x.com", "password": "secret123"})
    assert r.status_code == 403


def test_refresh(client):
    client.post("/api/v1/auth/register", json={"email": "u@x.com", "password": "secret123"})
    login = client.post("/api/v1/auth/login", json={"email": "u@x.com", "password": "secret123"}).json()
    r = client.post("/api/v1/auth/refresh", json={"refresh_token": login["refresh_token"]})
    assert r.status_code == 200
    assert "access_token" in r.json()
    assert "refresh_token" in r.json()


def test_refresh_rejects_access_token(client):
    client.post("/api/v1/auth/register", json={"email": "u@x.com", "password": "secret123"})
    login = client.post("/api/v1/auth/login", json={"email": "u@x.com", "password": "secret123"}).json()
    r = client.post("/api/v1/auth/refresh", json={"refresh_token": login["access_token"]})
    assert r.status_code == 401


def test_unified_error_format(client):
    r = client.get("/api/v1/auth/me")
    assert r.status_code == 401
    assert r.json() == {"error": {"code": 401, "message": "缺少登录凭证"}}


def test_me_requires_auth(client):
    r = client.get("/api/v1/auth/me")
    assert r.status_code == 401


def test_validation_error_unified_format(client):
    # N1:422 校验错误必须走统一错误格式 {"error": {...}},不得泄漏内部细节
    r = client.post("/api/v1/auth/register", json={"password": "secret123"})
    assert r.status_code == 422
    body = r.json()
    assert "error" in body
    assert body["error"]["code"] == 422
    # 422 message 需指明失败字段(修复:用户侧可定位 email 格式问题)
    assert "email" in body["error"]["message"]


def test_refresh_token_rejected_as_access(client):
    # N2:refresh token(type=refresh)不得通过 access 认证访问业务端点
    client.post("/api/v1/auth/register", json={"email": "u@x.com", "password": "secret123"})
    login = client.post("/api/v1/auth/login", json={"email": "u@x.com", "password": "secret123"}).json()
    r = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {login['refresh_token']}"})
    assert r.status_code == 401


def test_admin_member_management(client):
    """内网形态:admin 创建成员(同租户)、成员登录继承租户配置、成员写设置被拒。"""
    admin_token = register_and_login(client, "boss@x.com")
    headers = {"Authorization": f"Bearer {admin_token}"}
    # 创建成员
    r = client.post("/api/v1/admin/users", json={"email": "staff@x.com", "password": "staffpass123", "full_name": "小张", "role": "member"}, headers=headers)
    assert r.status_code == 200
    assert r.json()["role"] == "member"
    # 列成员
    members = client.get("/api/v1/admin/users", headers=headers).json()
    assert {m["email"] for m in members} == {"boss@x.com", "staff@x.com"}
    # 成员登录(同租户)
    login = client.post("/api/v1/auth/login", json={"email": "staff@x.com", "password": "staffpass123"})
    assert login.status_code == 200
    staff_token = login.json()["access_token"]
    staff_headers = {"Authorization": f"Bearer {staff_token}"}
    # 成员可见租户配置(settings 读开放)
    s = client.get("/api/v1/settings", headers=staff_headers)
    assert s.status_code == 200
    # 成员写设置被拒(仅 admin)
    w = client.put("/api/v1/settings", json={"provider": "mock"}, headers=staff_headers)
    assert w.status_code == 403
    # 成员可正常对话（chat 已从 Pod Cloud 移除）
    # 成员不能管理成员
    um = client.get("/api/v1/admin/users", headers=staff_headers)
    assert um.status_code == 403
    # 重置密码后旧密码失效
    rp = client.post("/api/v1/admin/users/2/reset-password", json={"password": "newpass12345"}, headers=headers)
    assert rp.status_code == 200
    old = client.post("/api/v1/auth/login", json={"email": "staff@x.com", "password": "staffpass123"})
    assert old.status_code == 401
    new = client.post("/api/v1/auth/login", json={"email": "staff@x.com", "password": "newpass12345"})
    assert new.status_code == 200


def test_internal_token_never_expires(client):
    """回归:内部服务令牌(注入 Fluvia → 网关回调)不得携带 exp,永不过期;登录 token 必须保留 exp。

    之前租户注入 token 复用 create_access_token(12h),而 Fluvia 全局变量兜底存的是
    过期 JWT → 网关 401 → 「信息来自知识库样本数据」。内部通道改用 create_internal_token。
    """
    from app.security import create_access_token as _cat, create_internal_token as _cit, decode_token

    internal = _cit(1, 1)
    payload = decode_token(internal)
    assert payload["tenant_id"] == 1
    assert payload["client"] == "internal"
    assert "exp" not in payload, "内部令牌不得有过期声明"

    login = _cat(1, 1)
    login_payload = decode_token(login)
    assert "exp" in login_payload, "登录令牌必须保留过期声明(12h)"


# ─────────────────────────────────────────────────────────────────
# 个人资料:本人改密 + 本人改姓名
# ─────────────────────────────────────────────────────────────────


def _two_sessions(client, email="u@x.com", password="secret123"):
    """同一账号开两个会话(两台设备),返回两次登录的响应体。"""
    client.post("/api/v1/auth/register", json={"email": email, "password": password, "full_name": "U"})
    a = client.post("/api/v1/auth/login", json={"email": email, "password": password}).json()
    b = client.post("/api/v1/auth/login", json={"email": email, "password": password}).json()
    return a, b


def test_change_password_wrong_old_password_is_400_not_401(client):
    """旧密码错是「输入错」,不是「登录态失效」。返回 401 会被前端拦截器
    当成过期登录态,清 token 并跳登录页——输错一次就把人踹出去。"""
    token = register_and_login(client)
    r = client.post(
        "/api/v1/auth/me/password",
        json={"old_password": "wrong-pass", "new_password": "newpass123"},
        headers=_h(token),
    )
    assert r.status_code == 400
    assert r.json()["error"]["message"] == "当前密码不正确"


def test_change_password_revokes_other_sessions(client):
    """改密踢掉其它会话,但发起改密的这次会话必须活着(否则自己把自己踢了)。"""
    session_a, session_b = _two_sessions(client)

    r = client.post(
        "/api/v1/auth/me/password",
        json={"old_password": "secret123", "new_password": "newpass123"},
        headers=_h(session_a["access_token"]),
    )
    assert r.status_code == 200
    fresh = r.json()["access_token"]
    # 改密时间带时区回传:不带的话前端会按本地时间解析,东八区差 8 小时
    assert r.json()["user"]["password_changed_at"].endswith("+00:00")

    # 本次会话:换发的新 token 可用
    assert client.get("/api/v1/auth/me", headers=_h(fresh)).status_code == 200
    # 另一个会话:access 与 refresh 双通道都被挡
    assert client.get("/api/v1/auth/me", headers=_h(session_b["access_token"])).status_code == 401
    assert (
        client.post("/api/v1/auth/refresh", json={"refresh_token": session_b["refresh_token"]}).status_code
        == 401
    )
    # 新旧密码的登录结果
    assert client.post("/api/v1/auth/login", json={"email": "u@x.com", "password": "secret123"}).status_code == 401
    assert client.post("/api/v1/auth/login", json={"email": "u@x.com", "password": "newpass123"}).status_code == 200


def test_change_password_allows_keeping_old_password(client):
    """产品选择:允许新密码与旧密码相同(此时只有「踢掉其它会话」在生效)。"""
    token = register_and_login(client)
    r = client.post(
        "/api/v1/auth/me/password",
        json={"old_password": "secret123", "new_password": "secret123"},
        headers=_h(token),
    )
    assert r.status_code == 200
    assert client.post("/api/v1/auth/login", json={"email": "a@b.com", "password": "secret123"}).status_code == 200


def test_change_password_enforces_complexity(client):
    """≥8 位 + 同时含字母与数字。三条都该被拒。"""
    token = register_and_login(client)
    for weak in ["ab1", "abcdefgh", "12345678"]:
        r = client.post(
            "/api/v1/auth/me/password",
            json={"old_password": "secret123", "new_password": weak},
            headers=_h(token),
        )
        assert r.status_code == 400, weak
        assert "密码" in r.json()["error"]["message"]


def test_register_and_admin_create_share_the_same_policy(client):
    """复杂度要求只在 security.validate_password_strength 一处实现;
    注册与后台建成员都不能绕过它。"""
    r = client.post("/api/v1/auth/register", json={"email": "w@x.com", "password": "12345678"})
    assert r.status_code == 400
    admin_token = register_and_login(client, "boss@x.com")
    m = client.post(
        "/api/v1/admin/users",
        json={"email": "staff@x.com", "password": "12345678", "role": "member"},
        headers=_h(admin_token),
    )
    assert m.status_code == 400


def test_update_profile_full_name(client):
    token = register_and_login(client)
    r = client.put("/api/v1/auth/me", json={"full_name": "  张三  "}, headers=_h(token))
    assert r.status_code == 200
    assert r.json()["full_name"] == "张三"
    assert client.get("/api/v1/auth/me", headers=_h(token)).json()["full_name"] == "张三"


def test_profile_endpoints_require_auth(client):
    assert client.put("/api/v1/auth/me", json={"full_name": "x"}).status_code == 401
    assert (
        client.post("/api/v1/auth/me/password", json={"old_password": "a", "new_password": "b"}).status_code
        == 401
    )


def _admin_and_member(client):
    """建一个 admin 和一个 member,返回 (admin 头, 成员行, 成员的登录响应)。"""
    headers = _h(register_and_login(client, "boss@x.com"))
    member = client.post(
        "/api/v1/admin/users",
        json={"email": "staff@x.com", "password": "staffpass123", "role": "member"},
        headers=headers,
    ).json()
    login = client.post("/api/v1/auth/login", json={"email": "staff@x.com", "password": "staffpass123"}).json()
    assert client.get("/api/v1/auth/me", headers=_h(login["access_token"])).status_code == 200
    return headers, member, login


def test_admin_reset_password_revokes_member_sessions(client):
    """管理员重置成员密码,必须同时踢掉该成员的会话——被盗号时这是唯一
    能立刻止血的动作。管理员自己不受影响。"""
    headers, member, member_login = _admin_and_member(client)

    r = client.post(
        f"/api/v1/admin/users/{member['id']}/reset-password",
        json={"password": "newpass12345"},
        headers=headers,
    )
    assert r.status_code == 200

    # 成员:access 与 refresh 都失效
    assert client.get("/api/v1/auth/me", headers=_h(member_login["access_token"])).status_code == 401
    assert (
        client.post("/api/v1/auth/refresh", json={"refresh_token": member_login["refresh_token"]}).status_code
        == 401
    )
    # 管理员自己的会话不受牵连
    assert client.get("/api/v1/auth/me", headers=headers).status_code == 200
    # 新密码可用
    assert client.post("/api/v1/auth/login", json={"email": "staff@x.com", "password": "newpass12345"}).status_code == 200


def test_admin_patch_password_also_revokes_target_sessions(client):
    """另一条改密入口(/users/{id} PATCH)走同一个 set_password,行为必须一致。"""
    headers, member, member_login = _admin_and_member(client)

    r = client.patch(f"/api/v1/users/{member['id']}", json={"password": "another12345"}, headers=headers)
    assert r.status_code == 200
    assert client.get("/api/v1/auth/me", headers=_h(member_login["access_token"])).status_code == 401
