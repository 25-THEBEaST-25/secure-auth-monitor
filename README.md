![Python](https://img.shields.io/badge/Python-3.11+-blue?logo=python)
![FastAPI](https://img.shields.io/badge/FastAPI-0.136-009688?logo=fastapi)
![Security](https://img.shields.io/badge/Security-Authentication-red)
![License](https://img.shields.io/badge/License-MIT-green)
# Secure Auth Monitor

A FastAPI authentication service that defends its login endpoint against brute force, credential stuffing and username enumeration. It records every security event and gives admins a dashboard to watch attacks and respond to them.

## Features

- bcrypt password hashing. Passwords over bcrypt's 72-byte limit are rejected, not silently truncated.
- JWT access tokens with a pinned algorithm and required claims. Tokens are revoked on logout, when a user is disabled, and when their role changes.
- **Rate limiting per IP.** 10 failures within 15 min blocks that IP for 5 min.
- **Lockout per account.** 5 failures within 15 min locks that username for 5 min, even when the attempts come from many IPs (credential stuffing).
- **Enumeration resistance.** Unknown users and wrong passwords get the same response and cost the same bcrypt time. Lockouts apply to made-up usernames too.
- **Permanent IP bans** set by admins.
- **RBAC** with `user` and `admin` roles. Role and status are read from the database on every request, so changes apply immediately.
- **Audit log.** Every login, failure, block and admin action is stored in the database and written to stdout as JSON logs.
- **Admin dashboard** at `/`: 24h stats, top failing IPs, active blocks, user management and a filterable event log.
- Correct client IP behind reverse proxies. `X-Forwarded-For` is only trusted from configured proxies.
- Production hardening: config validated at startup (weak keys are refused), security headers with a strict CSP, HSTS, API docs disabled in production, no stack traces in error responses, and a `/health` endpoint that checks the database.

All blocking state is stored in the database, so it's shared by every worker process and survives restarts.

## Architecture

```
            ┌────────────── FastAPI app (N workers) ──────────────┐
client ──►  │ client_ip ─► /api/login ─► security_service ─► auth │
 (proxy)    │                   │         (throttles)     service │
            │                   └─► audit_service (events + log)  │
            │ /api/admin/* ── require_admin ── same services      │
            └───────────────────────┬─────────────────────────────┘
                                    ▼
                     SQLite (dev) / Postgres (prod)
                 users · throttles · security_events
```

More detail in [docs/security.md](docs/security.md).

## Running locally

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
cp .env.example .env                    # set a real SECRET_KEY
alembic upgrade head
python create_user.py admin --admin     # prompts for a password
uvicorn app.main:app --reload --no-proxy-headers
```

Open http://localhost:8000 for the dashboard, or http://localhost:8000/docs for the API.

## Running with Docker (app + Postgres)

```bash
export SECRET_KEY=$(python -c "import secrets; print(secrets.token_urlsafe(32))")
docker compose up --build
docker compose exec app python create_user.py admin --admin
```

The container runs migrations on start, runs as a non-root user and has a health check.

## Configuration

| Variable | Default | Notes |
|---|---|---|
| `SECRET_KEY` | *required* | 32+ random characters; production refuses to start otherwise |
| `ENVIRONMENT` | `development` | `production` disables `/docs` and enables HSTS |
| `DATABASE_URL` | `sqlite:///./auth.db` | Postgres: `postgresql+psycopg2://user:pw@host/db` |
| `TRUSTED_PROXIES` | *(empty)* | Comma-separated IPs/CIDRs of your reverse proxies |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `30` | |
| `IP_MAX_FAILURES` / `IP_BLOCK_SECONDS` | `10` / `300` | |
| `ACCOUNT_MAX_FAILURES` / `ACCOUNT_LOCK_SECONDS` | `5` / `300` | |
| `FAILURE_WINDOW_SECONDS` | `900` | Older failures stop counting |

## API

| Method | Path | Auth | Result |
|---|---|---|---|
| POST | `/api/login` | – | 200 + token · 401 bad credentials · 403 disabled · 423 account locked · 429 IP blocked |
| POST | `/api/logout` | user | 204, revokes all of the user's tokens |
| GET | `/api/me` | user | current user |
| GET/POST | `/api/admin/users` | admin | list / create users |
| PATCH | `/api/admin/users/{id}` | admin | change role or disable (admins can't change themselves) |
| POST | `/api/admin/users/{id}/unlock` | admin | clear an account lockout |
| DELETE | `/api/admin/account-locks/{username}` | admin | clear a lockout by name |
| GET | `/api/admin/blocks` | admin | active IP blocks and account locks |
| POST / DELETE | `/api/admin/ip-bans` · `/api/admin/ip-bans/{ip}` | admin | permanent ban / lift any IP block |
| GET | `/api/admin/events` | admin | audit log with filters and `before_id` pagination |
| GET | `/api/admin/stats` | admin | counts for the dashboard |
| GET | `/health` | – | 200 when the database is reachable, 503 otherwise |

## Testing

```bash
python -m pytest                     # SQLite
TEST_DATABASE_URL=postgresql+psycopg2://... python -m pytest   # Postgres
ruff check . && pip-audit -r requirements.txt
```

82 tests cover the normal flows and the attacks: forged, expired and `alg: none` tokens, revoked tokens, privilege escalation, brute force, credential stuffing, lock expiry, failure windows, `X-Forwarded-For` spoofing, enumeration, validation, security headers, config validation and migrations (including upgrading a database from before migrations existed). CI runs lint, the suite on both SQLite and Postgres, a dependency vulnerability scan and a Docker build.

## Limitations

- An attacker can deliberately lock a real user out for 5 minutes. That's the usual tradeoff with account lockout, which is why locks are temporary and admins can lift them.
- Only login is rate-limited. Other endpoints need a valid token but aren't throttled.
- There are no refresh tokens. Users sign in again when the access token expires (30 min by default).
- The audit log grows without limit. A production deployment should archive or prune old events.
- There's no password reset or self-service signup. Admins create users.
