# Production Readiness Checklist

Status: **Complete**

| Requirement | Status |
|---|---|
| `.env.example` documenting all required env vars | Done |
| `docs/deployment.md` — how to run in production (Docker, env vars, Postgres) | Done |
| `docs/security.md` — what attacks it defends against and how | Done |
| Edge case tests: token expiry | Done — `test_rejects_expired_token` |
| Edge case tests: concurrent lockout | Done — `test_concurrent_failures_are_all_counted_not_lost_to_a_race`, `test_concurrent_logins_lock_the_account_exactly_once` |
| Edge case tests: admin privilege escalation | Done — `test_user_cannot_escalate_via_admin_endpoints`, `test_admin_cannot_change_own_role_or_status` |
| CI workflow actually passes | Verified — `tests` workflow, all 3 jobs (sqlite, postgres, docker) green on `main` |
| Architecture notes | Done — "Architecture" section in `README.md` |
| `LICENSE` matching the license badge in `README.md` | Done — MIT |

## Verification performed

- Ran the full pytest suite locally (84 tests, up from 82 after adding the concurrent-lockout tests), 3 consecutive runs, all green with no flakiness.
- Added two new regression tests proving the `security_service` atomic `UPDATE ... RETURNING` failure counter does not lose updates under real thread-level concurrency: one exercising `record_failure` directly across parallel DB sessions, one end-to-end through the HTTP login endpoint with one `TestClient` per worker thread.
- Confirmed via the GitHub API that the real CI run on `main` (commit `0bfd3c3`) passed all three jobs: `test` (sqlite), `postgres`, and `docker build`.
- Added the missing `LICENSE` file to back the MIT badge already in `README.md`.

No further action is required for this repo's production-readiness bar unless new attack surfaces or features are added.
