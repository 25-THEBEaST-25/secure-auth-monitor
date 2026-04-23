from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session
from app.schemas.auth import LoginRequest, TokenResponse
from app.services.auth_service import authenticate_user
from app.services.security_service import is_ip_allowed, record_failure
from app.api.deps import get_db
from app.core.security import create_access_token

router = APIRouter()

@router.post("/login", response_model=TokenResponse)
def login(data: LoginRequest, request: Request, db: Session = Depends(get_db)):
    ip = request.client.host

    if not is_ip_allowed(ip):
        return {"access_token": "IP BLOCKED"}

    user = authenticate_user(db, data.username, data.password)

    if user == "LOCKED":
        return {"access_token": "ACCOUNT LOCKED"}

    if not user:
        record_failure(ip)
        return {"access_token": "INVALID"}

    token = create_access_token({"sub": user.username})
    return {"access_token": token}