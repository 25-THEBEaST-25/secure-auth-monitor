# Security design

## Login decision order

```
request ─► client IP (see "Client IP" below)
        ─► IP blocked or banned?        → 429 (Retry-After unless permanent)
        ─► username locked?             → 423
        ─► bcrypt check (dummy hash if the user doesn't exist)
              fail → count failure for IP and username → 401
        ─► admin-disabled?              → 403 (only reached with the right password)
        ─► reset username counter, issue JWT → 200
```

Every branch writes a `security_events` row and a JSON log line.

## Brute force and credential stuffing

| Attack | Signal | Response |
|---|---|---|
| One IP guessing one password | IP failures | IP blocked after `IP_MAX_FAILURES` |
| One IP spraying many usernames | IP failures | same IP block |
| Many IPs attacking one account (botnet stuffing) | per-username failures | account locked after `ACCOUNT_MAX_FAILURES` |
| Known-bad IP | admin decision | permanent ban |

Counters live in the `throttles` table. Each failure is one atomic
`UPDATE … SET failures = failures + 1 … RETURNING`, so parallel requests
across workers can't lose counts. This was verified with 30 simultaneous
failures against 2 workers. Failures older than `FAILURE_WINDOW_SECONDS`
reset the counter, so a few typos a week never add up to a block.

A successful login resets the **account** counter only. Resetting the IP
counter would let an attacker who owns one valid account wipe their budget
before spraying the others.

## Enumeration

- Unknown usernames are checked against a dummy bcrypt hash, so response time doesn't reveal whether an account exists.
- Wrong password and unknown user return the same 401 body.
- Lockout counters exist for any username, real or not, so a 423 doesn't confirm an account exists.
- The "disabled" 403 is only returned after a correct password.

## Tokens

- HS256/384/512 only, fixed by config. `alg: none` and algorithm switching are rejected.
- `sub`, `exp`, `iat` and `tv` claims are required.
- `tv` (token version) is compared with `users.token_version` on every request. Logout, disabling a user and changing a role all bump it, which revokes every existing token for that user.
- Role and disabled status are read from the database, never trusted from the token.

## Client IP

`X-Forwarded-For` is ignored unless the direct peer is listed in
`TRUSTED_PROXIES`. Without that check, any client could send a new fake IP
with every request and never get blocked. The header is read right to left,
skipping our own proxies. The first address that isn't one of ours is the
client, so anything the client put in the header itself is ignored. Run
uvicorn with `--no-proxy-headers` so this is the only place the IP is worked
out.

## Dashboard

Usernames in the event log are whatever attackers typed into the login form.
The dashboard only ever inserts them with `textContent`, and the CSP
(`default-src 'self'`, no inline script) blocks injected scripts as a second
layer. The token is kept in page memory only (not `localStorage`).

## Known gaps

See "Limitations" in the README.
