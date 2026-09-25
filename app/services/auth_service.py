from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import DUMMY_HASH, hash_password, verify_password
from app.db.models import User


def get_by_username(db: Session, username: str) -> User | None:
    return db.scalar(select(User).where(User.username == username))


def authenticate_user(db: Session, username: str, password: str) -> User | None:
    user = get_by_username(db, username)

    if not user:
        verify_password(password, DUMMY_HASH)
        return None

    if not verify_password(password, user.hashed_password):
        return None

    return user


def create_user(db: Session, username: str, password: str, role: str = "user") -> User:
    user = User(username=username, hashed_password=hash_password(password), role=role)
    db.add(user)
    db.flush()
    return user


def invalidate_tokens(user: User) -> None:
    user.token_version = (user.token_version or 0) + 1
