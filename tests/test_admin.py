import pytest
from sqlalchemy import select

from app.core.config import settings
from app.db.models import User
from app.services import security_service
from app.services.security_service import ACCOUNT, IP
from tests.conftest import PASSWORD, auth_header, login, token_for

ADMIN_GETS = ["/api/admin/users", "/api/admin/blocks", "/api/admin/events", "/api/admin/stats"]


def uid(db, username):
    return db.scalar(select(User.id).where(User.username == username))


# --- RBAC boundaries ---

@pytest.mark.parametrize("path", ADMIN_GETS)
def test_admin_routes_need_a_token(client, path):
    assert client.get(path).status_code == 401


@pytest.mark.parametrize("path", ADMIN_GETS)
def test_admin_routes_reject_normal_users(client, user_headers, path):
    assert client.get(path, headers=user_headers).status_code == 403


@pytest.mark.parametrize("path", ADMIN_GETS)
def test_admin_routes_allow_admins(client, admin_headers, path):
    assert client.get(path, headers=admin_headers).status_code == 200


def test_user_cannot_escalate_via_admin_endpoints(client, user_headers, db):
    res = client.patch(f"/api/admin/users/{uid(db, 'alice')}", json={"role": "admin"}, headers=user_headers)
    assert res.status_code == 403
    res = client.post("/api/admin/users", json={"username": "evil", "password": "12345678", "role": "admin"},
                      headers=user_headers)
    assert res.status_code == 403


# --- user management ---

def test_admin_creates_user_who_can_log_in(client, admin_headers):
    res = client.post("/api/admin/users", json={"username": "bob", "password": "long-enough-pw"},
                      headers=admin_headers)
    assert res.status_code == 201
    assert res.json()["role"] == "user"
    assert login(client, "bob", "long-enough-pw").status_code == 200


def test_create_user_rejects_duplicates(client, admin_headers):
    res = client.post("/api/admin/users", json={"username": "alice", "password": "long-enough-pw"},
                      headers=admin_headers)
    assert res.status_code == 409


@pytest.mark.parametrize("body", [
    {"username": "bob", "password": "short"},
    {"username": "b", "password": "long-enough-pw"},
    {"username": "bad name<script>", "password": "long-enough-pw"},
    {"username": "bob", "password": "é" * 40},  # 80 bytes > bcrypt's 72
    {"username": "bob", "password": "long-enough-pw", "role": "superuser"},
])
def test_create_user_validates_input(client, admin_headers, body):
    assert client.post("/api/admin/users", json=body, headers=admin_headers).status_code == 422


def test_disabling_user_kills_their_existing_token(client, admin_headers, db):
    alice = auth_header(token_for(client, "alice"))
    res = client.patch(f"/api/admin/users/{uid(db, 'alice')}", json={"is_disabled": True}, headers=admin_headers)
    assert res.status_code == 200
    assert client.get("/api/me", headers=alice).status_code == 401
    assert login(client).status_code == 403


def test_demoting_admin_takes_effect_immediately(client, admin_headers, db):
    client.post("/api/admin/users", json={"username": "admin2", "password": PASSWORD, "role": "admin"},
                headers=admin_headers)
    admin2 = auth_header(token_for(client, "admin2"))
    assert client.get("/api/admin/users", headers=admin2).status_code == 200

    client.patch(f"/api/admin/users/{uid(db, 'admin2')}", json={"role": "user"}, headers=admin_headers)
    assert client.get("/api/admin/users", headers=admin2).status_code == 401
    fresh = auth_header(token_for(client, "admin2"))
    assert client.get("/api/admin/users", headers=fresh).status_code == 403


def test_admin_cannot_change_own_role_or_status(client, admin_headers, db):
    res = client.patch(f"/api/admin/users/{uid(db, 'root')}", json={"is_disabled": True}, headers=admin_headers)
    assert res.status_code == 400
    res = client.patch(f"/api/admin/users/{uid(db, 'root')}", json={"role": "user"}, headers=admin_headers)
    assert res.status_code == 400


def test_update_unknown_user_is_404(client, admin_headers):
    assert client.patch("/api/admin/users/9999", json={"role": "user"}, headers=admin_headers).status_code == 404


# --- blocks, bans and unlocks ---

def test_admin_unlocks_locked_account(client, admin_headers, db):
    for i in range(settings.ACCOUNT_MAX_FAILURES):
        security_service.record_failure(db, f"10.0.0.{i}", "alice")
    db.commit()
    assert login(client).status_code == 423

    assert client.post(f"/api/admin/users/{uid(db, 'alice')}/unlock", headers=admin_headers).status_code == 204
    assert login(client).status_code == 200


def test_admin_clears_lock_on_nonexistent_username(client, admin_headers, db):
    for i in range(settings.ACCOUNT_MAX_FAILURES):
        security_service.record_failure(db, f"10.0.0.{i}", "ghost")
    db.commit()
    assert client.delete("/api/admin/account-locks/ghost", headers=admin_headers).status_code == 204
    assert client.delete("/api/admin/account-locks/ghost", headers=admin_headers).status_code == 404


def test_permanent_ip_ban_and_unban(client, admin_headers, db):
    res = client.post("/api/admin/ip-bans", json={"ip": "203.0.113.7"}, headers=admin_headers)
    assert res.status_code == 204
    assert security_service.blocked_seconds(db, IP, "203.0.113.7") == -1

    blocks = client.get("/api/admin/blocks", headers=admin_headers).json()
    assert {"kind": "ip", "key": "203.0.113.7", "permanent": True, "blocked_until": None} in blocks

    assert client.delete("/api/admin/ip-bans/203.0.113.7", headers=admin_headers).status_code == 204
    assert security_service.blocked_seconds(db, IP, "203.0.113.7") is None


def test_banned_ip_cannot_log_in_and_has_no_retry_after(client, admin_headers, db):
    security_service.ban_ip(db, "testclient")
    db.commit()
    res = login(client)
    assert res.status_code == 429
    assert "Retry-After" not in res.headers


def test_ban_rejects_invalid_ip(client, admin_headers):
    assert client.post("/api/admin/ip-bans", json={"ip": "not-an-ip"}, headers=admin_headers).status_code == 422


def test_blocks_lists_temporary_blocks(client, admin_headers, db):
    for i in range(settings.ACCOUNT_MAX_FAILURES):
        security_service.record_failure(db, f"10.0.0.{i}", "alice")
    db.commit()
    blocks = client.get("/api/admin/blocks", headers=admin_headers).json()
    assert any(b["kind"] == ACCOUNT and b["key"] == "alice" and not b["permanent"] for b in blocks)


# --- audit log and stats ---

def test_events_are_newest_first_and_paginate(client, admin_headers):
    for i in range(5):
        login(client, username=f"u{i}", password="wrong")
    page1 = client.get("/api/admin/events?limit=3&event=login_failed", headers=admin_headers).json()
    assert [e["username"] for e in page1] == ["u4", "u3", "u2"]
    page2 = client.get(f"/api/admin/events?limit=3&event=login_failed&before_id={page1[-1]['id']}",
                       headers=admin_headers).json()
    assert [e["username"] for e in page2] == ["u1", "u0"]


def test_events_filter_by_username(client, admin_headers):
    login(client, username="target", password="wrong")
    login(client, username="other", password="wrong")
    events = client.get("/api/admin/events?username=target", headers=admin_headers).json()
    assert {e["username"] for e in events} == {"target"}


def test_events_limit_is_capped(client, admin_headers):
    assert client.get("/api/admin/events?limit=100000", headers=admin_headers).status_code == 422


def test_admin_actions_are_audited(client, admin_headers, db):
    client.patch(f"/api/admin/users/{uid(db, 'alice')}", json={"is_disabled": True}, headers=admin_headers)
    events = client.get("/api/admin/events?event=admin_action", headers=admin_headers).json()
    assert events[0]["username"] == "root"
    assert "alice" in events[0]["detail"] and "disabled" in events[0]["detail"]


def test_attacker_controlled_username_is_stored_verbatim_not_interpreted(client, admin_headers):
    # The dashboard renders this with textContent; the API must just return it as data.
    payload = '<img src=x onerror=alert(1)>\n{"level":"forged"}'
    login(client, username=payload, password="wrong")
    [event] = client.get("/api/admin/events?event=login_failed", headers=admin_headers).json()
    assert event["username"] == payload


def test_stats(client, admin_headers):
    login(client, password="wrong")
    login(client, username="x", password="wrong")
    stats = client.get("/api/admin/stats", headers=admin_headers).json()
    assert stats["event_counts"]["login_failed"] == 2
    assert stats["top_failed_ips"] == [["testclient", 2]]
    assert stats["users"] == 3
    assert stats["disabled_users"] == 1
