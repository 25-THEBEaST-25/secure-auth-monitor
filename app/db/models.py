from datetime import UTC, datetime

from sqlalchemy import Boolean, Column, DateTime, Float, Integer, String, UniqueConstraint

from app.db.database import Base

ROLES = ("user", "admin")


def utcnow():
    return datetime.now(UTC)


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    # Set by an admin; unrelated to the automatic, temporary lockout in Throttle.
    is_disabled = Column(Boolean, nullable=False, default=False, server_default="0")
    role = Column(String(16), nullable=False, default="user", server_default="user")
    token_version = Column(Integer, nullable=False, default=0, server_default="0")
    created_at = Column(DateTime(timezone=True), default=utcnow)

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"


class Throttle(Base):
    """Failure counter and block for one IP ("ip") or one username ("account").

    Kept in the database so blocks survive restarts and are shared by all workers.
    Times are epoch seconds (float) so every process compares the same clock.
    """

    __tablename__ = "throttles"
    __table_args__ = (UniqueConstraint("kind", "key", name="uq_throttles_kind_key"),)

    id = Column(Integer, primary_key=True)
    kind = Column(String(16), nullable=False)
    key = Column(String(255), nullable=False)
    failures = Column(Integer, nullable=False, default=0, server_default="0")
    window_start = Column(Float, nullable=False, default=0.0, server_default="0")
    blocked_until = Column(Float, nullable=True)
    permanent = Column(Boolean, nullable=False, default=False, server_default="0")


class SecurityEvent(Base):
    __tablename__ = "security_events"

    id = Column(Integer, primary_key=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utcnow, index=True)
    event = Column(String(32), nullable=False, index=True)
    username = Column(String(255), nullable=True, index=True)
    ip = Column(String(64), nullable=True, index=True)
    detail = Column(String(255), nullable=True)
