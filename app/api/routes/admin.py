from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_admin
from app.core.client_ip import get_client_ip
from app.db.models import User
from app.schemas.user import (
    BlockOut,
    EventOut,
    IpBanRequest,
    StatsOut,
    UserCreate,
    UserOut,
    UserUpdate,
)
from app.services import audit_service as audit
from app.services import auth_service, security_service
from app.services.security_service import ACCOUNT, IP

router = APIRouter(prefix="/admin", tags=["admin"])


def _admin_action(db: Session, request: Request, admin: User, detail: str) -> None:
    audit.record(db, audit.ADMIN_ACTION, admin.username, get_client_ip(request), detail)


def _get_user(db: Session, user_id: int) -> User:
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return user


@router.get("/users", response_model=list[UserOut])
def list_users(db: Session = Depends(get_db), _: User = Depends(require_admin)):
    return list(db.scalars(select(User).order_by(User.id)))


@router.post("/users", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def create_user(data: UserCreate, request: Request, db: Session = Depends(get_db),
                admin: User = Depends(require_admin)):
    if auth_service.get_by_username(db, data.username):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Username already exists")
    user = auth_service.create_user(db, data.username, data.password, data.role)
    _admin_action(db, request, admin, f"created user {user.username} role={user.role}")
    db.commit()
    return user


@router.patch("/users/{user_id}", response_model=UserOut)
def update_user(user_id: int, data: UserUpdate, request: Request, db: Session = Depends(get_db),
                admin: User = Depends(require_admin)):
    user = _get_user(db, user_id)
    if user.id == admin.id:
        # Stops an admin from locking the last admin out by accident.
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="Admins cannot change their own role or status")

    changes = []
    if data.role is not None and data.role != user.role:
        changes.append(f"role {user.role}->{data.role}")
        user.role = data.role
    if data.is_disabled is not None and data.is_disabled != user.is_disabled:
        changes.append("disabled" if data.is_disabled else "enabled")
        user.is_disabled = data.is_disabled

    if changes:
        # Existing tokens were issued under the old role/status.
        auth_service.invalidate_tokens(user)
        _admin_action(db, request, admin, f"user {user.username}: {', '.join(changes)}")
        db.commit()
    return user


@router.post("/users/{user_id}/unlock", status_code=status.HTTP_204_NO_CONTENT)
def unlock_user(user_id: int, request: Request, db: Session = Depends(get_db),
                admin: User = Depends(require_admin)):
    user = _get_user(db, user_id)
    security_service.clear(db, ACCOUNT, user.username)
    _admin_action(db, request, admin, f"unlocked account {user.username}")
    db.commit()


@router.delete("/account-locks/{username}", status_code=status.HTTP_204_NO_CONTENT)
def clear_account_lock(username: str, request: Request, db: Session = Depends(get_db),
                       admin: User = Depends(require_admin)):
    # By username rather than user id: lockouts also exist for names that
    # aren't real accounts (see security_service.record_failure).
    if not security_service.clear(db, ACCOUNT, username):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No lock for that username")
    _admin_action(db, request, admin, f"unlocked account {username}")
    db.commit()


@router.get("/blocks", response_model=list[BlockOut])
def list_blocks(db: Session = Depends(get_db), _: User = Depends(require_admin)):
    return security_service.active_blocks(db)


@router.post("/ip-bans", status_code=status.HTTP_204_NO_CONTENT)
def ban_ip(data: IpBanRequest, request: Request, db: Session = Depends(get_db),
           admin: User = Depends(require_admin)):
    ip = str(data.ip)
    if ip == get_client_ip(request):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Refusing to ban your own IP")
    security_service.ban_ip(db, ip)
    _admin_action(db, request, admin, f"banned ip {ip}")
    db.commit()


@router.delete("/ip-bans/{ip}", status_code=status.HTTP_204_NO_CONTENT)
def unban_ip(ip: str, request: Request, db: Session = Depends(get_db),
             admin: User = Depends(require_admin)):
    if not security_service.clear(db, IP, ip):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No block for that IP")
    _admin_action(db, request, admin, f"unblocked ip {ip}")
    db.commit()


@router.get("/events", response_model=list[EventOut])
def list_events(
    limit: int = Query(50, ge=1, le=500),
    before_id: int | None = Query(None, ge=1, description="Pagination cursor: id of the last event seen"),
    event: str | None = Query(None, max_length=32),
    username: str | None = Query(None, max_length=255),
    ip: str | None = Query(None, max_length=64),
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),
):
    return audit.recent(db, limit, before_id, event, username, ip)


@router.get("/stats", response_model=StatsOut)
def stats(hours: int = Query(24, ge=1, le=24 * 30), db: Session = Depends(get_db),
          _: User = Depends(require_admin)):
    return StatsOut(
        window_hours=hours,
        event_counts=audit.counts_since(db, hours),
        top_failed_ips=audit.top_failed_ips(db, hours),
        active_blocks=len(security_service.active_blocks(db)),
        users=db.scalar(select(func.count()).select_from(User)),
        disabled_users=db.scalar(select(func.count()).select_from(User).where(User.is_disabled.is_(True))),
    )
