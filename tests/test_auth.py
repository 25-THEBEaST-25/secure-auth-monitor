from datetime import UTC, datetime, timedelta

import jwt
from sqlalchemy import select

from app.core.config import settings
from app.core.security import create_access_token
from app.db.models import SecurityEvent, User
from app.services import security_service
from app.services.security_service import ACCOUNT, IP
from tests.conftest import auth_header, login, token_for


def user_id(db, username):
    return db.scalar(select(User.id).where(User.username == username))


def events(db, event):
    return list(db.scalars(select(SecurityEvent).where(SecurityEvent.event == event)))


def fail_as_ip(db, ip, username, times):
    for _ in range(times):
        security_service.record_failure(db, ip, username)
    db.commit()


# --- legitimate flow ---

def test_login_returns_token_that_opens_me(client):
    res = login(client)
    assert res.status_code == 200
    body = res.json()
    assert body["expires_in"] == settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60

    me = client.get("/api/me", headers=auth_header(body["access_token"]))
    assert me.status_code == 200
    assert me.json()["username"] == "alice"
    assert me.json()["role"] == "user"
    assert "hashed_password" not in me.json()


def test_successful_login_is_audited(client, db):
    login(client)
    [event] = events(db, "login_success")
    assert event.username == "alice"
    assert event.ip == "testclient"


# --- failed logins ---

def test_wrong_password_is_401_not_200(client, db):
    # Regression: failures used to return 200 with access_token="INVALID".
    res = login(client, password="wrong")
    assert res.status_code == 401
    assert "access_token" not in res.json()
    assert len(events(db, "login_failed")) == 1


def test_unknown_user_gets_same_response_as_wrong_password(client):
    wrong_pw = login(client, password="wrong")
    unknown = login(client, username="nobody", password="wrong")
    assert unknown.status_code == wrong_pw.status_code == 401
    assert unknown.json() == wrong_pw.json()


def test_password_over_bcrypt_limit_is_401_not_500(client):
    assert login(client, password="x" * 200).status_code == 401


def test_disabled_account_is_rejected(client):
    assert login(client, username="disabled").status_code == 403


def test_disabled_account_not_revealed_without_password(client):
    assert login(client, username="disabled", password="wrong").status_code == 401


def test_malformed_body_is_422(client):
    assert client.post("/api/login", json={"username": "alice"}).status_code == 422
    assert client.post("/api/login", content="not json").status_code == 422
    assert client.post("/api/login", json={"username": "", "password": "x"}).status_code == 422


# --- token validation ---

def test_me_requires_token(client):
    assert client.get("/api/me").status_code == 401


def test_rejects_garbage_token(client):
    assert client.get("/api/me", headers=auth_header("not.a.jwt")).status_code == 401


def test_rejects_expired_token(client, db):
    token = create_access_token(user_id(db, "alice"), 0, expires_delta=timedelta(seconds=-1))
    assert client.get("/api/me", headers=auth_header(token)).status_code == 401


def test_rejects_token_signed_with_other_key(client, db):
    now = datetime.now(UTC)
    forged = jwt.encode(
        {"sub": str(user_id(db, "root")), "tv": 0, "iat": now, "exp": now + timedelta(minutes=5)},
        "attacker-key-attacker-key-attacker-key",
        algorithm="HS256",
    )
    assert client.get("/api/me", headers=auth_header(forged)).status_code == 401


def test_rejects_unsigned_none_alg_token(client):
    # header {"alg":"none"} . payload {"sub":"1","tv":0} . empty signature
    forged = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIiwidHYiOjB9."
    assert client.get("/api/me", headers=auth_header(forged)).status_code == 401


def test_rejects_token_missing_claims(client):
    token = jwt.encode({"sub": "1"}, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    assert client.get("/api/me", headers=auth_header(token)).status_code == 401


def test_rejects_token_for_deleted_user(client, db):
    token = create_access_token(99999, 0)
    assert client.get("/api/me", headers=auth_header(token)).status_code == 401


# --- logout ---

def test_logout_revokes_all_existing_tokens(client):
    first = token_for(client)
    second = token_for(client)
    assert client.post("/api/logout", headers=auth_header(first)).status_code == 204
    assert client.get("/api/me", headers=auth_header(first)).status_code == 401
    assert client.get("/api/me", headers=auth_header(second)).status_code == 401
    # A fresh login still works.
    assert client.get("/api/me", headers=auth_header(token_for(client))).status_code == 200


# --- brute force: IP blocking ---

def test_ip_blocked_after_max_failures_even_with_correct_password(client, db):
    for i in range(settings.IP_MAX_FAILURES):
        # Different usernames so this exercises the IP limit, not account lockout.
        assert login(client, username=f"spray{i}", password="wrong").status_code == 401

    res = login(client)
    assert res.status_code == 429
    assert int(res.headers["Retry-After"]) > 0
    assert len(events(db, "ip_blocked")) == 1
    assert len(events(db, "login_blocked_ip")) == 1


def test_ip_block_expires(client, monkeypatch):
    for i in range(settings.IP_MAX_FAILURES):
        login(client, username=f"spray{i}", password="wrong")
    assert login(client).status_code == 429

    later = security_service.now() + settings.IP_BLOCK_SECONDS + 1
    monkeypatch.setattr(security_service, "now", lambda: later)
    assert login(client).status_code == 200


def test_old_failures_fall_out_of_the_window(db, monkeypatch):
    fail_as_ip(db, "10.0.0.1", "u", settings.IP_MAX_FAILURES - 1)
    later = security_service.now() + settings.FAILURE_WINDOW_SECONDS + 1
    monkeypatch.setattr(security_service, "now", lambda: later)
    fail_as_ip(db, "10.0.0.1", "v", 1)
    assert security_service.blocked_seconds(db, IP, "10.0.0.1") is None


def test_block_state_is_in_the_database(db):
    # Regression: counters used to be in process memory, so every worker
    # (and every restart) had its own, empty copy.
    fail_as_ip(db, "10.0.0.9", "someone", settings.IP_MAX_FAILURES)
    from app.db.database import SessionLocal
    with SessionLocal() as other_worker:
        assert security_service.blocked_seconds(other_worker, IP, "10.0.0.9") is not None


# --- credential stuffing: account lockout across IPs ---

def test_account_locks_after_failures_from_many_ips(db):
    for i in range(settings.ACCOUNT_MAX_FAILURES):
        fail_as_ip(db, f"10.0.0.{i}", "alice", 1)
    assert security_service.blocked_seconds(db, ACCOUNT, "alice") is not None
    assert security_service.blocked_seconds(db, ACCOUNT, "bob") is None


def test_locked_account_rejects_correct_password(client, db):
    for i in range(settings.ACCOUNT_MAX_FAILURES):
        fail_as_ip(db, f"10.0.0.{i}", "alice", 1)
    assert login(client).status_code == 423


def test_lockout_does_not_reveal_whether_user_exists(client, db):
    for i in range(settings.ACCOUNT_MAX_FAILURES):
        fail_as_ip(db, f"10.0.0.{i}", "alice", 1)
        fail_as_ip(db, f"10.0.1.{i}", "ghost", 1)
    real = login(client, username="alice")
    fake = login(client, username="ghost")
    assert real.status_code == fake.status_code == 423
    assert real.json() == fake.json()


def test_account_lock_expires(client, db, monkeypatch):
    for i in range(settings.ACCOUNT_MAX_FAILURES):
        fail_as_ip(db, f"10.0.0.{i}", "alice", 1)
    later = security_service.now() + settings.ACCOUNT_LOCK_SECONDS + 1
    monkeypatch.setattr(security_service, "now", lambda: later)
    assert login(client).status_code == 200


def test_successful_login_resets_account_failure_count(client, db):
    fail_as_ip(db, "10.0.0.1", "alice", settings.ACCOUNT_MAX_FAILURES - 1)
    assert login(client).status_code == 200
    fail_as_ip(db, "10.0.0.2", "alice", 1)
    assert security_service.blocked_seconds(db, ACCOUNT, "alice") is None


def test_successful_login_does_not_reset_ip_counter(client):
    for i in range(settings.IP_MAX_FAILURES - 1):
        login(client, username=f"spray{i}", password="wrong")
    assert login(client).status_code == 200
    login(client, username="one-more", password="wrong")
    assert login(client).status_code == 429
