import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from app.security import create_access_token, get_current_tenant_id, get_current_user, hash_password, verify_password


def test_password_hash_roundtrip():
    h = hash_password("secret123")
    assert h != "secret123"
    assert verify_password("secret123", h)
    assert not verify_password("wrong", h)


def test_jwt_roundtrip():
    token = create_access_token(user_id=7, tenant_id=3)
    from app.security import decode_token

    payload = decode_token(token)
    assert payload["sub"] == 7
    assert payload["tenant_id"] == 3


def test_dependency_rejects_missing_token():
    app = FastAPI()

    @app.get("/me")
    def me(user=Depends(get_current_user)):
        return {"id": user["id"]}

    with TestClient(app) as client:
        r = client.get("/me")
    assert r.status_code == 401


def test_dependency_rejects_bad_token():
    app = FastAPI()

    @app.get("/me")
    def me(user=Depends(get_current_user)):
        return {"id": user["id"]}

    with TestClient(app) as client:
        r = client.get("/me", headers={"Authorization": "Bearer nonsense"})
    assert r.status_code == 401


def test_dependency_accepts_valid_token():
    app = FastAPI()

    @app.get("/me")
    def me(user=Depends(get_current_user)):
        return {"id": user["id"]}

    token = create_access_token(user_id=7, tenant_id=3)
    with TestClient(app) as client:
        r = client.get("/me", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    assert r.json() == {"id": 7}
