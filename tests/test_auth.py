from datetime import timedelta

from jose import jwt

from app.core.security import create_access_token
from app.services import security_service
from tests.conftest import PASSWORD, login


def auth_header(token):
    return {"Authorization": f"Bearer {token}"}


# --- legitimate flow ---

def test_login_returns_token_that_opens_protected_route(client):
    res = login(client)
    assert res.status_code == 200
    token = res.json()["access_token"]

    res = client.get("/api/protected", headers=auth_header(token))
    assert res.status_code == 200
    assert "alice" in res.json()["message"]


# --- failed logins must not look like success ---

def test_wrong_password_is_401_not_200(client):
    # Regression: failures used to return 200 with access_token="INVALID".
    res = login(client, password="wrong")
    assert res.status_code == 401
    assert "access_token" not in res.json()


def test_unknown_user_gets_same_response_as_wrong_password(client):
    wrong_pw = login(client, password="wrong")
    unknown = login(client, username="nobody", password="wrong")
    assert unknown.status_code == wrong_pw.status_code == 401
    assert unknown.json() == wrong_pw.json()


def test_disabled_account_is_rejected(client):
    assert login(client, username="disabled").status_code == 403


def test_disabled_account_not_revealed_without_password(client):
    assert login(client, username="disabled", password="wrong").status_code == 401


# --- token validation ---

def test_protected_requires_token(client):
    assert client.get("/api/protected").status_code == 401


def test_protected_rejects_garbage_token(client):
    assert client.get("/api/protected", headers=auth_header("not.a.jwt")).status_code == 401


def test_protected_rejects_expired_token(client):
    token = create_access_token({"sub": "alice"}, expires_delta=timedelta(seconds=-1))
    assert client.get("/api/protected", headers=auth_header(token)).status_code == 401


def test_protected_rejects_token_signed_with_other_key(client):
    forged = jwt.encode({"sub": "alice"}, "attacker-key", algorithm="HS256")
    assert client.get("/api/protected", headers=auth_header(forged)).status_code == 401


def test_protected_rejects_unsigned_none_alg_token(client):
    # header {"alg":"none"} . payload {"sub":"alice"} . empty signature
    forged = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhbGljZSJ9."
    assert client.get("/api/protected", headers=auth_header(forged)).status_code == 401


def test_protected_rejects_token_without_subject(client):
    token = create_access_token({"role": "admin"})
    assert client.get("/api/protected", headers=auth_header(token)).status_code == 401


# --- brute force: IP blocking ---

def test_ip_blocked_after_max_failures_even_with_correct_password(client):
    for i in range(security_service.MAX_ATTEMPTS):
        # Different usernames so this exercises the IP limit, not account lockout.
        assert login(client, username=f"spray{i}", password="wrong").status_code == 401

    res = login(client)
    assert res.status_code == 429
    assert int(res.headers["Retry-After"]) > 0


def test_ip_block_expires(client, monkeypatch):
    for i in range(security_service.MAX_ATTEMPTS):
        login(client, username=f"spray{i}", password="wrong")
    assert login(client).status_code == 429

    later = security_service.now() + security_service.BLOCK_TIME + 1
    monkeypatch.setattr(security_service, "now", lambda: later)
    assert login(client).status_code == 200


# --- credential stuffing: account lockout across IPs ---

def test_account_locks_after_failures_from_many_ips():
    for i in range(security_service.MAX_ACCOUNT_FAILURES):
        security_service.record_failure(f"10.0.0.{i}", "alice")
    assert security_service.is_account_locked("alice")
    assert not security_service.is_account_locked("bob")


def test_locked_account_rejects_correct_password(client):
    for i in range(security_service.MAX_ACCOUNT_FAILURES):
        security_service.record_failure(f"10.0.0.{i}", "alice")
    assert login(client).status_code == 423


def test_lockout_does_not_reveal_whether_user_exists(client):
    for i in range(security_service.MAX_ACCOUNT_FAILURES):
        security_service.record_failure(f"10.0.0.{i}", "alice")
        security_service.record_failure(f"10.0.1.{i}", "ghost")
    real = login(client, username="alice")
    fake = login(client, username="ghost")
    assert real.status_code == fake.status_code == 423
    assert real.json() == fake.json()


def test_account_lock_expires(client, monkeypatch):
    for i in range(security_service.MAX_ACCOUNT_FAILURES):
        security_service.record_failure(f"10.0.0.{i}", "alice")

    later = security_service.now() + security_service.ACCOUNT_LOCK_TIME + 1
    monkeypatch.setattr(security_service, "now", lambda: later)
    assert login(client).status_code == 200


def test_successful_login_resets_account_failure_count(client):
    for _ in range(security_service.MAX_ACCOUNT_FAILURES - 1):
        security_service.record_failure("10.0.0.1", "alice")
    assert login(client).status_code == 200

    security_service.record_failure("10.0.0.2", "alice")
    assert not security_service.is_account_locked("alice")


# --- input validation ---

def test_malformed_body_is_422(client):
    assert client.post("/api/login", json={"username": "alice"}).status_code == 422
    assert client.post("/api/login", content="not json").status_code == 422
