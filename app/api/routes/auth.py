from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session
from app.schemas.auth import LoginRequest, TokenResponse
from app.services.auth_service import authenticate_user
from app.services.security_service import (
    ip_retry_after,
    is_account_locked,
    is_ip_allowed,
    record_failure,
    record_success,
)
from app.api.deps import get_db
from app.core.logging import logger
from app.core.security import create_access_token

router = APIRouter()


@router.post("/login", response_model=TokenResponse)
def login(data: LoginRequest, request: Request, db: Session = Depends(get_db)):
    ip = request.client.host if request.client else "unknown"

    if not is_ip_allowed(ip):
        logger.warning("login_blocked_ip ip=%s user=%s", ip, data.username)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed attempts. Try again later.",
            headers={"Retry-After": str(ip_retry_after(ip))},
        )

    if is_account_locked(data.username):
        logger.warning("login_locked_account ip=%s user=%s", ip, data.username)
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail="Account temporarily locked. Try again later.",
        )

    user = authenticate_user(db, data.username, data.password)

    if not user:
        record_failure(ip, data.username)
        logger.info("login_failed ip=%s user=%s", ip, data.username)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    # Admin-disabled accounts. Only revealed after a correct password.
    if user.is_locked:
        logger.warning("login_disabled_account ip=%s user=%s", ip, data.username)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account disabled",
        )

    record_success(user.username)
    logger.info("login_success ip=%s user=%s", ip, user.username)
    token = create_access_token({"sub": user.username})
    return {"access_token": token}
