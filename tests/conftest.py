import os
import tempfile

# Must be set before any app module is imported: settings are read at import time.
_tmpdir = tempfile.mkdtemp()
os.environ["SECRET_KEY"] = "test-secret-key"
os.environ["DATABASE_URL"] = f"sqlite:///{_tmpdir}/test.db"

import pytest
from fastapi.testclient import TestClient

from app.core.security import hash_password
from app.db.database import Base, SessionLocal, engine
from app.db.models import User
from app.main import app
from app.services import security_service

PASSWORD = "correct-horse-battery"


@pytest.fixture(autouse=True)
def fresh_state():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    db.add(User(username="alice", hashed_password=hash_password(PASSWORD)))
    db.add(User(username="disabled", hashed_password=hash_password(PASSWORD), is_locked=True))
    db.commit()
    db.close()
    security_service.reset_state()
    yield
    security_service.reset_state()


@pytest.fixture
def client():
    return TestClient(app)


def login(client, username="alice", password=PASSWORD):
    return client.post("/api/login", json={"username": username, "password": password})
