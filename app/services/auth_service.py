from sqlalchemy.orm import Session
from app.db.models import User
from app.core.security import DUMMY_HASH, verify_password


def authenticate_user(db: Session, username: str, password: str):
    user = db.query(User).filter(User.username == username).first()

    if not user:
        verify_password(password, DUMMY_HASH)
        return None

    if not verify_password(password, user.hashed_password):
        return None

    return user
