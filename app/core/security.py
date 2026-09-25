from datetime import UTC, datetime, timedelta

import bcrypt
import jwt

from app.core.config import settings

BCRYPT_MAX_BYTES = 72


def hash_password(password: str) -> str:
    raw = password.encode()
    if len(raw) > BCRYPT_MAX_BYTES:
        # bcrypt ignores everything after 72 bytes; refuse instead of silently truncating.
        raise ValueError(f"password longer than {BCRYPT_MAX_BYTES} bytes")
    return bcrypt.hashpw(raw, bcrypt.gensalt()).decode()


def verify_password(password: str, hashed: str) -> bool:
    raw = password.encode()
    if len(raw) > BCRYPT_MAX_BYTES:
        # Can never match a stored hash; still pay the bcrypt cost for uniform timing.
        bcrypt.checkpw(b"x", DUMMY_HASH.encode())
        return False
    return bcrypt.checkpw(raw, hashed.encode())


# Verified against when the username does not exist, so an unknown user
# costs the same bcrypt work as a wrong password (no timing-based enumeration).
DUMMY_HASH = hash_password("dummy-password-for-timing")


def create_access_token(user_id: int, token_version: int, expires_delta: timedelta | None = None) -> str:
    now = datetime.now(UTC)
    payload = {
        "sub": str(user_id),
        # Bumped on logout, disable and role change; older tokens stop working.
        "tv": token_version,
        "iat": now,
        "exp": now + (expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)),
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def decode_access_token(token: str) -> dict:
    """Raises jwt.PyJWTError on any invalid token."""
    # Pin the algorithm list so a token can't pick its own (e.g. "none").
    return jwt.decode(
        token,
        settings.SECRET_KEY,
        algorithms=[settings.ALGORITHM],
        options={"require": ["sub", "exp", "iat", "tv"]},
    )
