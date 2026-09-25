from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.logging import logger
from app.db.models import SecurityEvent

LOGIN_SUCCESS = "login_success"
LOGIN_FAILED = "login_failed"
LOGIN_BLOCKED_IP = "login_blocked_ip"
LOGIN_LOCKED_ACCOUNT = "login_locked_account"
LOGIN_DISABLED = "login_disabled_account"
IP_BLOCKED = "ip_blocked"
ACCOUNT_LOCKED = "account_locked"
LOGOUT = "logout"
ADMIN_ACTION = "admin_action"

WARNING_EVENTS = {LOGIN_BLOCKED_IP, LOGIN_LOCKED_ACCOUNT, LOGIN_DISABLED, IP_BLOCKED, ACCOUNT_LOCKED}


def record(db: Session, event: str, username: str | None = None, ip: str | None = None,
           detail: str | None = None) -> None:
    """Add an audit event to the session (committed with the caller's transaction) and log it."""
    db.add(SecurityEvent(
        event=event,
        username=username[:255] if username else None,
        ip=ip,
        detail=detail[:255] if detail else None,
    ))
    level = "warning" if event in WARNING_EVENTS else "info"
    getattr(logger, level)(event, extra={"fields": {"event": event, "user": username, "ip": ip, "detail": detail}})


def recent(db: Session, limit: int, before_id: int | None = None, event: str | None = None,
           username: str | None = None, ip: str | None = None) -> list[SecurityEvent]:
    query = select(SecurityEvent).order_by(SecurityEvent.id.desc()).limit(limit)
    if before_id is not None:
        query = query.where(SecurityEvent.id < before_id)
    if event:
        query = query.where(SecurityEvent.event == event)
    if username:
        query = query.where(SecurityEvent.username == username)
    if ip:
        query = query.where(SecurityEvent.ip == ip)
    return list(db.scalars(query))


def counts_since(db: Session, hours: int) -> dict[str, int]:
    since = datetime.now(UTC) - timedelta(hours=hours)
    rows = db.execute(
        select(SecurityEvent.event, func.count())
        .where(SecurityEvent.created_at >= since)
        .group_by(SecurityEvent.event)
    )
    return dict(rows.all())


def top_failed_ips(db: Session, hours: int, limit: int = 5) -> list[tuple[str, int]]:
    since = datetime.now(UTC) - timedelta(hours=hours)
    rows = db.execute(
        select(SecurityEvent.ip, func.count().label("n"))
        .where(SecurityEvent.event == LOGIN_FAILED, SecurityEvent.created_at >= since)
        .group_by(SecurityEvent.ip)
        .order_by(func.count().desc())
        .limit(limit)
    )
    return [(ip, n) for ip, n in rows.all()]
