import os
import tempfile

import bcrypt

# Must be set before any app module is imported: settings are read at import time.
_tmpdir = tempfile.mkdtemp()
os.environ["SECRET_KEY"] = "test-secret-key-that-is-long-enough-000"
os.environ["DATABASE_URL"] = os.environ.get("TEST_DATABASE_URL", f"sqlite:///{_tmpdir}/test.db")
os.environ["ENVIRONMENT"] = "development"
os.environ["TRUSTED_PROXIES"] = ""

# Cheap hashes keep the suite fast; production uses the bcrypt default cost.
_real_gensalt = bcrypt.gensalt
bcrypt.gensalt = lambda rounds=4, prefix=b"2b": _real_gensalt(4, prefix)

import pytest
from fastapi.testclient import TestClient

from app.db.database import Base, SessionLocal, engine
from app.main import app
from app.services import auth_service

PASSWORD = "correct-horse-battery"


@pytest.fixture(autouse=True)
def fresh_db():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    with SessionLocal() as db:
        auth_service.create_user(db, "alice", PASSWORD)
        auth_service.create_user(db, "root", PASSWORD, role="admin")
        disabled = auth_service.create_user(db, "disabled", PASSWORD)
        disabled.is_disabled = True
        db.commit()
    yield


@pytest.fixture
def db():
    with SessionLocal() as session:
        yield session


@pytest.fixture
def client():
    return TestClient(app)


def login(client, username="alice", password=PASSWORD):
    return client.post("/api/login", json={"username": username, "password": password})


def auth_header(token):
    return {"Authorization": f"Bearer {token}"}


def token_for(client, username="alice"):
    res = login(client, username)
    assert res.status_code == 200, res.text
    return res.json()["access_token"]


@pytest.fixture
def admin_headers(client):
    return auth_header(token_for(client, "root"))


@pytest.fixture
def user_headers(client):
    return auth_header(token_for(client, "alice"))
