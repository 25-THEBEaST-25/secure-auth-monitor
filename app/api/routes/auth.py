from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_db
from app.core.client_ip import get_client_ip
from app.core.config import settings
from app.core.security import create_access_token
from app.db.models import User
from app.schemas.auth import LoginRequest, TokenResponse
from app.schemas.user import UserOut
from app.services import audit_service as audit
from app.services import auth_service, security_service
from app.services.security_service import ACCOUNT, IP

router = APIRouter()


@router.post("/login", response_model=TokenResponse)
def login(data: LoginRequest, request: Request, db: Session = Depends(get_db)):
    ip = get_client_ip(request)

    remaining = security_service.blocked_seconds(db, IP, ip)
    if remaining is not None:
        audit.record(db, audit.LOGIN_BLOCKED_IP, data.username, ip)
        db.commit()
        headers = {"Retry-After": str(remaining)} if remaining > 0 else {}
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed attempts. Try again later.",
            headers=headers,
        )

    if security_service.blocked_seconds(db, ACCOUNT, data.username) is not None:
        audit.record(db, audit.LOGIN_LOCKED_ACCOUNT, data.username, ip)
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail="Account temporarily locked. Try again later.",
        )

    user = auth_service.authenticate_user(db, data.username, data.password)

    if not user:
        triggered = security_service.record_failure(db, ip, data.username)
        audit.record(db, audit.LOGIN_FAILED, data.username, ip)
        if IP in triggered:
            audit.record(db, audit.IP_BLOCKED, data.username, ip,
                         f"{settings.IP_MAX_FAILURES} failures, blocked {settings.IP_BLOCK_SECONDS}s")
        if ACCOUNT in triggered:
            audit.record(db, audit.ACCOUNT_LOCKED, data.username, ip,
                         f"{settings.ACCOUNT_MAX_FAILURES} failures, locked {settings.ACCOUNT_LOCK_SECONDS}s")
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    # Admin-disabled accounts. Only revealed after a correct password.
    if user.is_disabled:
        audit.record(db, audit.LOGIN_DISABLED, data.username, ip)
        db.commit()
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account disabled")

    security_service.record_success(db, user.username)
    audit.record(db, audit.LOGIN_SUCCESS, user.username, ip)
    db.commit()
    return TokenResponse(
        access_token=create_access_token(user.id, user.token_version),
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(request: Request, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    # JWTs can't be deleted, so bump the version: every token issued so far
    # (on all devices) stops working.
    db_user = db.get(User, user.id)
    auth_service.invalidate_tokens(db_user)
    audit.record(db, audit.LOGOUT, db_user.username, get_client_ip(request))
    db.commit()


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(get_current_user)):
    return user
