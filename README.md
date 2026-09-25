![Python](https://img.shields.io/badge/Python-3.11-blue?logo=python)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688?logo=fastapi)
![Security](https://img.shields.io/badge/Security-Authentication-red)
![License](https://img.shields.io/badge/License-MIT-green)
![Made with Love](https://img.shields.io/badge/Made%20With-%E2%9D%A4-red)
# Secure Auth Monitor

Production-inspired authentication security system built in Python.

## Features

Implemented and covered by tests:

- Secure password hashing (bcrypt)
- JWT access tokens with expiry, pinned signing algorithm
- Rate limiting: an IP is blocked for 60s after 5 failed logins
- Account lockout: a username is locked for 5 min after 5 failed logins, from any IP
- Enumeration resistance: unknown users and wrong passwords get the same response and the same bcrypt cost
- Auth event logging (success, failure, blocked, locked). Passwords are never logged.
- FastAPI backend

Planned (not built yet):

- Role-Based Access Control (RBAC)
- Permanent IP banning
- Progressive login delays
- Risk scoring
- Monitoring dashboard

## Running locally

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env        # then set a real SECRET_KEY
python create_user.py alice # prompts for a password
uvicorn app.main:app --reload
```

## API

| Method | Path | Result |
|---|---|---|
| POST | `/api/login` `{"username", "password"}` | 200 + token, 401 bad credentials, 423 account locked, 429 IP blocked (with `Retry-After`) |
| GET | `/api/protected` | 200 with a valid `Authorization: Bearer <token>`, otherwise 401 |

## Testing

```bash
python -m pytest
```

The tests check both normal logins and attacks: forged, expired and `alg: none` tokens, brute force from one IP, credential stuffing across many IPs, lock expiry, and username enumeration.

## Threats Mitigated

| Threat | Protection |
|----------|----------|
| Brute Force | IP rate limiting |
| Credential Stuffing | Per-account lockout across IPs |
| Username Enumeration | Identical responses and timing for unknown users |
| Token Forgery | Signature check with a fixed algorithm list |

## Limitations

- Blocking and lockout state lives in memory. It resets on restart and isn't shared across multiple workers.
- Account lockout can be abused to lock out a real user for 5 minutes. That's the usual tradeoff of lockout, and it's why the lock is temporary.
- Behind a reverse proxy, every request comes from the proxy's IP. Trusted `X-Forwarded-For` handling isn't implemented.
