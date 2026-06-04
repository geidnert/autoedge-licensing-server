from __future__ import annotations

import os
from dataclasses import dataclass


def _bool_env(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _int_env(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    return int(raw)


@dataclass(frozen=True)
class Settings:
    database_path: str
    bind_host: str
    bind_port: int
    public_base_url: str
    whop_webhook_secret: str | None
    whop_bearer_token: str | None
    admin_cookie_secret: str
    cookie_secure: bool
    session_hours: int
    license_check_interval_seconds: int
    grace_period_seconds: int
    rate_limit_per_minute: int
    release_artifact_dir: str
    release_download_token_seconds: int

    @staticmethod
    def from_env() -> "Settings":
        return Settings(
            database_path=os.environ.get("AUTOEDGE_DATABASE_PATH", "data/autoedge.db"),
            bind_host=os.environ.get("AUTOEDGE_BIND_HOST", "127.0.0.1"),
            bind_port=_int_env("AUTOEDGE_BIND_PORT", 8788),
            public_base_url=os.environ.get("AUTOEDGE_PUBLIC_BASE_URL", "https://licenses.example.com"),
            whop_webhook_secret=os.environ.get("WHOP_WEBHOOK_SECRET"),
            whop_bearer_token=os.environ.get("AUTOEDGE_WHOP_BEARER_TOKEN"),
            admin_cookie_secret=os.environ.get("AUTOEDGE_ADMIN_COOKIE_SECRET", ""),
            cookie_secure=_bool_env("AUTOEDGE_COOKIE_SECURE", True),
            session_hours=_int_env("AUTOEDGE_ADMIN_SESSION_HOURS", 12),
            license_check_interval_seconds=_int_env("AUTOEDGE_LICENSE_CHECK_INTERVAL_SECONDS", 21600),
            grace_period_seconds=_int_env("AUTOEDGE_GRACE_PERIOD_SECONDS", 259200),
            rate_limit_per_minute=_int_env("AUTOEDGE_RATE_LIMIT_PER_MINUTE", 60),
            release_artifact_dir=os.environ.get("AUTOEDGE_RELEASE_ARTIFACT_DIR", "data/artifacts"),
            release_download_token_seconds=_int_env("AUTOEDGE_RELEASE_DOWNLOAD_TOKEN_SECONDS", 600),
        )

    def validate_runtime(self) -> None:
        if not self.admin_cookie_secret or len(self.admin_cookie_secret) < 32:
            raise ValueError("AUTOEDGE_ADMIN_COOKIE_SECRET must be set to at least 32 characters.")
        if not self.whop_webhook_secret and not self.whop_bearer_token:
            raise ValueError("Set WHOP_WEBHOOK_SECRET or AUTOEDGE_WHOP_BEARER_TOKEN before accepting webhook updates.")
