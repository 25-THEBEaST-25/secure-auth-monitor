import ipaddress
import logging
from functools import cached_property
from typing import Literal

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

KNOWN_WEAK_KEYS = {"change-me", "supersecretkey123", "secret", "changeme"}
MIN_KEY_LENGTH = 32


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    ENVIRONMENT: Literal["development", "production"] = "development"

    # No default on purpose: the app must refuse to start without a key.
    SECRET_KEY: str
    ALGORITHM: Literal["HS256", "HS384", "HS512"] = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    DATABASE_URL: str = "sqlite:///./auth.db"

    # Comma-separated IPs/CIDRs of reverse proxies whose X-Forwarded-For
    # header is trusted. Empty means use the direct peer address only.
    TRUSTED_PROXIES: str = ""

    IP_MAX_FAILURES: int = 10
    IP_BLOCK_SECONDS: int = 300
    ACCOUNT_MAX_FAILURES: int = 5
    ACCOUNT_LOCK_SECONDS: int = 300
    # Failures older than this stop counting toward a block.
    FAILURE_WINDOW_SECONDS: int = 900

    @model_validator(mode="after")
    def _check_secret_key(self):
        weak = len(self.SECRET_KEY) < MIN_KEY_LENGTH or self.SECRET_KEY in KNOWN_WEAK_KEYS
        if weak and self.ENVIRONMENT == "production":
            raise ValueError(
                f"SECRET_KEY must be at least {MIN_KEY_LENGTH} random characters in production"
            )
        if weak:
            logging.getLogger("auth").warning(
                "weak SECRET_KEY: fine for local development, refused in production"
            )
        return self

    @cached_property
    def trusted_proxy_networks(self) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
        return [
            ipaddress.ip_network(part.strip(), strict=False)
            for part in self.TRUSTED_PROXIES.split(",")
            if part.strip()
        ]

    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT == "production"


settings = Settings()
