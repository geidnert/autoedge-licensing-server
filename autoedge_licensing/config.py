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
    trader_max_devices: int
    rate_limit_per_minute: int
    release_artifact_dir: str
    release_download_token_seconds: int
    license_lease_secret: str
    tradovate_oauth_client_id: str | None = None
    tradovate_oauth_client_secret: str | None = None
    tradovate_oauth_redirect_uri: str | None = None
    tradovate_oauth_authorize_url: str = "https://trader.tradovate.com/oauth"
    tradovate_oauth_token_url: str = "https://live.tradovateapi.com/auth/oauthtoken"
    tradovate_oauth_demo_authorize_url: str | None = None
    tradovate_oauth_demo_token_url: str | None = None
    tradovate_oauth_scopes: str | None = None
    tradovate_oauth_state_seconds: int = 600
    tradovate_live_api_base_url: str = "https://live.tradovateapi.com/v1"
    tradovate_demo_api_base_url: str = "https://demo.tradovateapi.com/v1"
    tradovate_oauth_token_secret: str | None = None

    @staticmethod
    def from_env() -> "Settings":
        admin_cookie_secret = os.environ.get("AUTOEDGE_ADMIN_COOKIE_SECRET", "")
        tradovate_token_secret = os.environ.get("TRADOVATE_OAUTH_TOKEN_SECRET") or admin_cookie_secret
        return Settings(
            database_path=os.environ.get("AUTOEDGE_DATABASE_PATH", "data/autoedge.db"),
            bind_host=os.environ.get("AUTOEDGE_BIND_HOST", "127.0.0.1"),
            bind_port=_int_env("AUTOEDGE_BIND_PORT", 8788),
            public_base_url=os.environ.get("AUTOEDGE_PUBLIC_BASE_URL", "https://licenses.example.com"),
            whop_webhook_secret=os.environ.get("WHOP_WEBHOOK_SECRET"),
            whop_bearer_token=os.environ.get("AUTOEDGE_WHOP_BEARER_TOKEN"),
            admin_cookie_secret=admin_cookie_secret,
            cookie_secure=_bool_env("AUTOEDGE_COOKIE_SECURE", True),
            session_hours=_int_env("AUTOEDGE_ADMIN_SESSION_HOURS", 12),
            license_check_interval_seconds=_int_env("AUTOEDGE_LICENSE_CHECK_INTERVAL_SECONDS", 21600),
            grace_period_seconds=_int_env("AUTOEDGE_GRACE_PERIOD_SECONDS", 259200),
            trader_max_devices=max(1, _int_env("AUTOEDGE_TRADER_MAX_DEVICES", 1)),
            rate_limit_per_minute=_int_env("AUTOEDGE_RATE_LIMIT_PER_MINUTE", 60),
            release_artifact_dir=os.environ.get("AUTOEDGE_RELEASE_ARTIFACT_DIR", "data/artifacts"),
            release_download_token_seconds=_int_env("AUTOEDGE_RELEASE_DOWNLOAD_TOKEN_SECONDS", 600),
            license_lease_secret=os.environ.get("AUTOEDGE_LICENSE_LEASE_SECRET") or admin_cookie_secret,
            tradovate_oauth_client_id=os.environ.get("TRADOVATE_OAUTH_CLIENT_ID"),
            tradovate_oauth_client_secret=os.environ.get("TRADOVATE_OAUTH_CLIENT_SECRET"),
            tradovate_oauth_redirect_uri=os.environ.get("TRADOVATE_OAUTH_REDIRECT_URI"),
            tradovate_oauth_authorize_url=os.environ.get("TRADOVATE_OAUTH_AUTHORIZE_URL", "https://trader.tradovate.com/oauth"),
            tradovate_oauth_token_url=os.environ.get("TRADOVATE_OAUTH_TOKEN_URL", "https://live.tradovateapi.com/auth/oauthtoken"),
            tradovate_oauth_demo_authorize_url=os.environ.get("TRADOVATE_OAUTH_DEMO_AUTHORIZE_URL"),
            tradovate_oauth_demo_token_url=os.environ.get("TRADOVATE_OAUTH_DEMO_TOKEN_URL"),
            tradovate_oauth_scopes=os.environ.get("TRADOVATE_OAUTH_SCOPES"),
            tradovate_oauth_state_seconds=_int_env("TRADOVATE_OAUTH_STATE_SECONDS", 600),
            tradovate_live_api_base_url=os.environ.get("TRADOVATE_LIVE_API_BASE_URL", "https://live.tradovateapi.com/v1"),
            tradovate_demo_api_base_url=os.environ.get("TRADOVATE_DEMO_API_BASE_URL", "https://demo.tradovateapi.com/v1"),
            tradovate_oauth_token_secret=tradovate_token_secret,
        )

    def validate_runtime(self) -> None:
        if not self.admin_cookie_secret or len(self.admin_cookie_secret) < 32:
            raise ValueError("AUTOEDGE_ADMIN_COOKIE_SECRET must be set to at least 32 characters.")
        if not self.license_lease_secret or len(self.license_lease_secret) < 32:
            raise ValueError("AUTOEDGE_LICENSE_LEASE_SECRET must be set to at least 32 characters.")
        if not self.whop_webhook_secret and not self.whop_bearer_token:
            raise ValueError("Set WHOP_WEBHOOK_SECRET or AUTOEDGE_WHOP_BEARER_TOKEN before accepting webhook updates.")
        oauth_values = [
            self.tradovate_oauth_client_id,
            self.tradovate_oauth_client_secret,
            self.tradovate_oauth_redirect_uri,
        ]
        if any(oauth_values) and not all(oauth_values):
            raise ValueError(
                "Set TRADOVATE_OAUTH_CLIENT_ID, TRADOVATE_OAUTH_CLIENT_SECRET, "
                "and TRADOVATE_OAUTH_REDIRECT_URI together."
            )
        if all(oauth_values) and (
            not self.tradovate_oauth_token_secret or len(self.tradovate_oauth_token_secret) < 32
        ):
            raise ValueError("TRADOVATE_OAUTH_TOKEN_SECRET must be at least 32 characters when Tradovate OAuth is enabled.")

    def tradovate_oauth_enabled(self) -> bool:
        return bool(
            self.tradovate_oauth_client_id
            and self.tradovate_oauth_client_secret
            and self.tradovate_oauth_redirect_uri
        )
