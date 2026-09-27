# Deployment

Concrete steps for running this service somewhere other than a laptop.
Everything here reflects what's actually in the repo — the `Dockerfile`,
`docker-compose.yml`, `alembic.ini`/`migrations/`, and `app/core/config.py`.

## 1. Docker Compose (app + Postgres)

The included `docker-compose.yml` runs the app against a Postgres 16
container, which is the closest thing this repo has to a production stack.

```bash
export SECRET_KEY=$(python -c "import secrets; print(secrets.token_urlsafe(32))")
docker compose up --build
```

This starts two services:

- `db`: `postgres:16-alpine`, with a named volume (`pgdata`) so data survives
  restarts, and a `pg_isready` healthcheck the `app` service waits on.
- `app`: built from the repo's `Dockerfile`, with `ENVIRONMENT=production`
  and `DATABASE_URL` pointed at the `db` service. `SECRET_KEY` is required
  (`${SECRET_KEY:?set SECRET_KEY}`) — compose refuses to start without it.

Create the first admin user once the stack is up:

```bash
docker compose exec app python create_user.py admin --admin
```

`POSTGRES_PASSWORD` defaults to `auth` in `docker-compose.yml`; override it
in a real deployment (`POSTGRES_PASSWORD=<something-else> docker compose up`).

## 2. What the container does on start

The `Dockerfile`'s `CMD` is:

```sh
alembic upgrade head && exec uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers ${WEB_CONCURRENCY:-2} --no-proxy-headers
```

- **Migrations run automatically** on every container start, before the app
  starts serving traffic. There's no separate migration step to remember.
- **`WEB_CONCURRENCY`** controls the number of uvicorn worker processes
  (default 2). All blocking/lockout/audit state lives in the database, not
  in process memory, so it's safe to run multiple workers or replicas —
  counters are updated with atomic `UPDATE … RETURNING` statements (see
  [security.md](security.md)).
- **`--no-proxy-headers`** is intentional: uvicorn does not trust
  `X-Forwarded-*` headers itself. The app resolves the real client IP from
  `TRUSTED_PROXIES` (see below), which is the only place that decision is
  made.
- The container runs as a non-root user (`app`, uid 10001) and defines a
  `HEALTHCHECK` against `GET /health`, which checks database connectivity.

## 3. Required environment variables

See [`.env.example`](../.env.example) for the full, commented list. At
minimum, production needs:

| Variable | Notes |
|---|---|
| `SECRET_KEY` | Required. 32+ random characters. The app (`app/core/config.py`) refuses to start in production with a short or known-weak key. |
| `ENVIRONMENT` | Set to `production`. Disables `/docs` and `/openapi.json`, enables `Strict-Transport-Security`. |
| `DATABASE_URL` | `postgresql+psycopg2://user:pass@host/db` for Postgres. SQLite (`sqlite:///./auth.db`) is fine for local dev only. |
| `TRUSTED_PROXIES` | Comma-separated IPs/CIDRs of your reverse proxy or load balancer. Required if you sit behind one — otherwise `X-Forwarded-For` is ignored and every request looks like it comes from the proxy's IP, which breaks per-IP throttling. |

The throttle/lockout tuning variables (`IP_MAX_FAILURES`, `IP_BLOCK_SECONDS`,
`ACCOUNT_MAX_FAILURES`, `ACCOUNT_LOCK_SECONDS`, `FAILURE_WINDOW_SECONDS`) all
have sane defaults and don't need to be set unless you want different
thresholds.

## 4. Database setup and migrations (Alembic)

Migrations live in `migrations/versions/` and are applied with Alembic,
configured by `alembic.ini` (script location `migrations`) and
`migrations/env.py`, which reads `DATABASE_URL` from the app's settings —
there's no separate Alembic database URL to keep in sync.

- In Docker, migrations run automatically on every container start (see
  above) — nothing extra to do.
- Outside Docker (bare metal / VM), run migrations explicitly before
  starting the app:

  ```bash
  alembic upgrade head
  ```

- The migration history includes an upgrade path from databases created
  before Alembic was introduced (`0001_initial.py`,
  `0002_rbac_throttles_audit.py`); this is covered by the test suite, so
  upgrading an existing pre-migrations database is expected to work.
- Postgres is exercised in CI (see below) against the same test suite that
  runs on SQLite, so both backends are verified, not just assumed compatible.

## 5. Reverse proxy / HTTPS

This service does not terminate TLS itself — `uvicorn` is run over plain
HTTP inside the container. In production, put it behind a reverse proxy
(nginx, Caddy, an ALB/ELB, Cloudflare, etc.) that:

- Terminates HTTPS and forwards plain HTTP to the app.
- Sets `X-Forwarded-For` correctly, and whose own IP (or CIDR range) you add
  to `TRUSTED_PROXIES` — otherwise the app can't tell real client IPs apart
  from the proxy's, and per-IP rate limiting/blocking won't work correctly.
- Is included in `--no-proxy-headers` on the uvicorn side (already set in
  the Dockerfile `CMD`) so uvicorn itself never trusts forwarded headers —
  only the app's own `TRUSTED_PROXIES` logic does (see
  `app/core/client_ip.py` and [security.md](security.md)).

The app already sends `Strict-Transport-Security` when `ENVIRONMENT=production`,
so once the proxy is serving HTTPS, browsers will be told to keep using it.
It does not redirect HTTP to HTTPS itself — that redirect belongs at the
proxy/load-balancer layer.

## 6. CI as a deployment gate

`.github/workflows/tests.yml` runs on every push/PR:

- `test`: lint (`ruff check .`), the full test suite against SQLite, and a
  dependency vulnerability scan (`pip-audit`).
- `postgres`: the same test suite against a real Postgres 16 service
  container — the same engine `docker-compose.yml` runs.
- `docker`: builds the production image (`docker build .`) to catch
  Dockerfile breakage.

A green run on all three jobs is a reasonable bar for "safe to deploy";
there's no separate deployment pipeline in this repo, so promoting a build
is a manual step (rebuild the image from a commit that passed CI, then
`docker compose up --build` / redeploy that image).

## 7. Operational notes

- **Logs**: the app writes structured JSON log lines (see
  [security.md](security.md)) to stdout — capture these with whatever log
  aggregation your platform provides (container runtime, `docker logs`, a
  log shipper, etc.). There's no built-in log rotation or shipping.
- **Audit log growth**: the `security_events` table grows without bound
  (documented in the README's Limitations section). Plan to archive or
  prune it periodically in a long-running production deployment; there is
  no built-in retention job.
- **First admin user**: there's no self-service signup. Create the first
  admin with `create_user.py` (locally or via `docker compose exec app
  python create_user.py <username> --admin`) after migrations have run.
