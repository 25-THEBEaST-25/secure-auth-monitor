"""Brute-force protection: per-IP blocking and per-account lockout.

State lives in the `throttles` table so every worker sees the same counters
and blocks survive restarts. Counter updates are single atomic UPDATEs, so
concurrent failures from parallel requests are all counted.
"""
import time

from sqlalchemy import case, delete, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.models import Throttle

IP = "ip"
ACCOUNT = "account"

# Indirection so tests can move the clock without patching time globally.
now = time.time


def _limits(kind: str) -> tuple[int, int]:
    if kind == IP:
        return settings.IP_MAX_FAILURES, settings.IP_BLOCK_SECONDS
    return settings.ACCOUNT_MAX_FAILURES, settings.ACCOUNT_LOCK_SECONDS


def _ensure_row(db: Session, kind: str, key: str) -> None:
    exists = db.scalar(select(Throttle.id).where(Throttle.kind == kind, Throttle.key == key))
    if exists:
        return
    try:
        with db.begin_nested():
            db.add(Throttle(kind=kind, key=key, failures=0, window_start=now()))
    except IntegrityError:
        pass  # another request created it first


def blocked_seconds(db: Session, kind: str, key: str) -> int | None:
    """Seconds left on a block, or None if not blocked. Permanent bans return -1."""
    row = db.scalar(select(Throttle).where(Throttle.kind == kind, Throttle.key == key))
    if row is None:
        return None
    if row.permanent:
        return -1
    if row.blocked_until and row.blocked_until > now():
        return max(1, int(row.blocked_until - now()))
    return None


def _count_failure(db: Session, kind: str, key: str) -> bool:
    """Count one failure. Returns True if this failure triggered a new block."""
    max_failures, block_seconds = _limits(kind)
    t = now()
    _ensure_row(db, kind, key)

    stale = Throttle.window_start < t - settings.FAILURE_WINDOW_SECONDS
    failures = db.scalar(
        update(Throttle)
        .where(Throttle.kind == kind, Throttle.key == key)
        .values(
            failures=case((stale, 1), else_=Throttle.failures + 1),
            window_start=case((stale, t), else_=Throttle.window_start),
        )
        .returning(Throttle.failures)
    )
    if failures >= max_failures:
        db.execute(
            update(Throttle)
            .where(Throttle.kind == kind, Throttle.key == key)
            .values(failures=0, window_start=t, blocked_until=t + block_seconds)
        )
        return True
    return False


def record_failure(db: Session, ip: str, username: str) -> list[str]:
    """Returns which blocks were newly triggered: "ip" and/or "account"."""
    triggered = []
    if _count_failure(db, IP, ip):
        triggered.append(IP)
    # Tracked per username whether or not the account exists, so a lockout
    # response doesn't reveal which usernames are real. This catches
    # credential stuffing spread across many IPs.
    if _count_failure(db, ACCOUNT, username):
        triggered.append(ACCOUNT)
    return triggered


def record_success(db: Session, username: str) -> None:
    # Only the account counter is cleared. Clearing the IP counter would let
    # an attacker with one valid login reset their budget for spraying others.
    db.execute(
        update(Throttle)
        .where(Throttle.kind == ACCOUNT, Throttle.key == username)
        .values(failures=0)
    )


def ban_ip(db: Session, ip: str) -> None:
    _ensure_row(db, IP, ip)
    db.execute(update(Throttle).where(Throttle.kind == IP, Throttle.key == ip).values(permanent=True))


def clear(db: Session, kind: str, key: str) -> bool:
    """Lift any block or ban. Returns False if there was nothing to clear."""
    result = db.execute(delete(Throttle).where(Throttle.kind == kind, Throttle.key == key))
    return result.rowcount > 0


def active_blocks(db: Session) -> list[Throttle]:
    return list(
        db.scalars(
            select(Throttle)
            .where((Throttle.permanent.is_(True)) | (Throttle.blocked_until > now()))
            .order_by(Throttle.kind, Throttle.key)
        )
    )
