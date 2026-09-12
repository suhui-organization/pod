import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base, get_db
from app.main import app

engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
TestingSession = sessionmaker(bind=engine, autoflush=False, autocommit=False)


@pytest.fixture()
def db():
    Base.metadata.create_all(engine)
    s = TestingSession()
    yield s
    s.close()
    Base.metadata.drop_all(engine)


@pytest.fixture()
def client(db):
    def override():
        yield db

    app.dependency_overrides[get_db] = override
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


def register_and_login(client, email="a@b.com", password="secret123"):
    client.post("/api/v1/auth/register", json={"email": email, "password": password, "full_name": "Tester"})
    r = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    return r.json()["access_token"]
