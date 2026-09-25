from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress, field_validator

from app.core.security import BCRYPT_MAX_BYTES

Role = Literal["user", "admin"]


class UserCreate(BaseModel):
    username: str = Field(pattern=r"^[A-Za-z0-9_.-]{3,64}$")
    password: str = Field(min_length=8)
    role: Role = "user"

    @field_validator("password")
    @classmethod
    def fits_bcrypt(cls, value: str) -> str:
        if len(value.encode()) > BCRYPT_MAX_BYTES:
            raise ValueError(f"password must be at most {BCRYPT_MAX_BYTES} bytes")
        return value


class UserUpdate(BaseModel):
    role: Role | None = None
    is_disabled: bool | None = None


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    role: str
    is_disabled: bool
    created_at: datetime | None


class EventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    created_at: datetime
    event: str
    username: str | None
    ip: str | None
    detail: str | None


class BlockOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    kind: str
    key: str
    permanent: bool
    blocked_until: float | None


class IpBanRequest(BaseModel):
    ip: IPvAnyAddress


class StatsOut(BaseModel):
    window_hours: int
    event_counts: dict[str, int]
    top_failed_ips: list[tuple[str | None, int]]
    active_blocks: int
    users: int
    disabled_users: int
