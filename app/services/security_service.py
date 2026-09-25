import time

# Indirection so tests can move the clock without patching time globally.
now = time.monotonic

# In-memory state: resets on restart and is not shared between worker
# processes. Fine for a single-process demo; a real deployment would need
# a shared store.
FAILED_ATTEMPTS = {}
BLOCKED_IPS = {}
ACCOUNT_FAILURES = {}
LOCKED_ACCOUNTS = {}

MAX_ATTEMPTS = 5
BLOCK_TIME = 60

MAX_ACCOUNT_FAILURES = 5
ACCOUNT_LOCK_TIME = 300


def _still_blocked(table: dict, key: str) -> bool:
    until = table.get(key)
    if until is None:
        return False
    if now() < until:
        return True
    del table[key]
    return False


def is_ip_allowed(ip: str):
    return not _still_blocked(BLOCKED_IPS, ip)


def ip_retry_after(ip: str) -> int:
    return max(1, int(BLOCKED_IPS.get(ip, 0) - now()))


def is_account_locked(username: str):
    return _still_blocked(LOCKED_ACCOUNTS, username)


def record_failure(ip: str, username: str):
    FAILED_ATTEMPTS[ip] = FAILED_ATTEMPTS.get(ip, 0) + 1
    if FAILED_ATTEMPTS[ip] >= MAX_ATTEMPTS:
        BLOCKED_IPS[ip] = now() + BLOCK_TIME
        FAILED_ATTEMPTS[ip] = 0

    # Tracked per username whether or not the account exists, so a lockout
    # response doesn't reveal which usernames are real. This catches
    # credential stuffing spread across many IPs.
    ACCOUNT_FAILURES[username] = ACCOUNT_FAILURES.get(username, 0) + 1
    if ACCOUNT_FAILURES[username] >= MAX_ACCOUNT_FAILURES:
        LOCKED_ACCOUNTS[username] = now() + ACCOUNT_LOCK_TIME
        ACCOUNT_FAILURES[username] = 0


def record_success(username: str):
    # Only the account counter is cleared. Clearing the IP counter would let
    # an attacker with one valid login reset their budget for spraying others.
    ACCOUNT_FAILURES.pop(username, None)


def reset_state():
    for table in (FAILED_ATTEMPTS, BLOCKED_IPS, ACCOUNT_FAILURES, LOCKED_ACCOUNTS):
        table.clear()
