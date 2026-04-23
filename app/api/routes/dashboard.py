from fastapi import APIRouter
from app.services.security_service import FAILED_ATTEMPTS, BLOCKED_IPS

router = APIRouter()

@router.get("/dashboard")
def dashboard():
    return {
        "failed_attempts": FAILED_ATTEMPTS,
        "blocked_ips": BLOCKED_IPS
    }