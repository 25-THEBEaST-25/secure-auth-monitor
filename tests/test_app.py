import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.core.config import Settings
from app.main import create_app

STRONG_KEY = "k" * 40


def test_health(client):
    assert client.get("/health").json() == {"status": "ok"}


def test_security_headers(client):
    res = client.get("/")
    assert res.status_code == 200
    assert "default-src 'self'" in res.headers["Content-Security-Policy"]
    assert res.headers["X-Frame-Options"] == "DENY"
    assert res.headers["X-Content-Type-Options"] == "nosniff"


def test_api_responses_are_not_cached(client):
    assert client.post("/api/login", json={"username": "a", "password": "b"}).headers["Cache-Control"] == "no-store"


def test_dashboard_has_no_inline_script(client):
    # The CSP forbids inline scripts, so the page must load its JS from a file.
    html = client.get("/").text
    assert '<script src="/static/dashboard.js"' in html
    assert "<script>" not in html
    assert client.get("/static/dashboard.js").status_code == 200


def test_production_refuses_weak_secret_key():
    for weak in ["change-me", "supersecretkey123", "short"]:
        with pytest.raises(ValidationError):
            Settings(ENVIRONMENT="production", SECRET_KEY=weak, _env_file=None)
    Settings(ENVIRONMENT="production", SECRET_KEY=STRONG_KEY, _env_file=None)


def test_development_allows_weak_key():
    Settings(ENVIRONMENT="development", SECRET_KEY="change-me", _env_file=None)


def test_production_hides_api_docs_and_sets_hsts():
    prod = TestClient(create_app(Settings(ENVIRONMENT="production", SECRET_KEY=STRONG_KEY, _env_file=None)))
    assert prod.get("/docs").status_code == 404
    assert prod.get("/openapi.json").status_code == 404
    assert "max-age" in prod.get("/health").headers["Strict-Transport-Security"]


def test_development_serves_docs(client):
    assert client.get("/docs").status_code == 200


def test_unhandled_errors_do_not_leak_details(monkeypatch):
    from app.services import auth_service

    def boom(*args, **kwargs):
        raise RuntimeError("secret internal detail")

    monkeypatch.setattr(auth_service, "authenticate_user", boom)
    res = TestClient(create_app(), raise_server_exceptions=False).post(
        "/api/login", json={"username": "a", "password": "b"})
    assert res.status_code == 500
    assert "secret internal detail" not in res.text
