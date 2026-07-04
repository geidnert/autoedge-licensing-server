from __future__ import annotations

import html
import json
import os
import sys
import time
from datetime import datetime, timezone
from http import HTTPStatus
from pathlib import Path
from typing import Any, Callable
from urllib.parse import parse_qs, parse_qsl, urlencode, urlsplit, urlunsplit
from wsgiref.simple_server import WSGIRequestHandler, make_server
from zoneinfo import ZoneInfo

from .config import Settings
from .db import Database, apply_migrations
from .security import (
    parse_cookie,
    random_token,
    sha256_hex,
    sign_value,
    unsign_value,
    verify_bearer,
    verify_standard_webhook,
)
from .service import DEFAULT_RELEASE_PLATFORM, SUPPORTED_RELEASE_PLATFORMS, LicensingService, parse_time, slugify
from .tradovate import (
    TradovateOAuthClient,
    TradovateOAuthError,
    build_authorization_url,
    normalize_tradovate_environment,
)


HeaderList = list[tuple[str, str]]
StartResponse = Callable[[str, HeaderList], None]
ADMIN_TIME_ZONE = ZoneInfo("America/New_York")
ADMIN_TIME_LABEL = "ET"
SENSITIVE_QUERY_PARAMS = {
    "access_token",
    "client_secret",
    "code",
    "id_token",
    "refresh_token",
    "state",
    "token",
}


def redact_http_request_line(request_line: str) -> str:
    parts = request_line.split(" ", 2)
    if len(parts) != 3:
        return request_line

    method, target, protocol = parts
    parsed = urlsplit(target)
    if not parsed.query:
        return request_line

    query = urlencode(
        [
            (key, "REDACTED" if key.lower() in SENSITIVE_QUERY_PARAMS else value)
            for key, value in parse_qsl(parsed.query, keep_blank_values=True)
        ]
    )
    redacted_target = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, parsed.fragment))
    return f"{method} {redacted_target} {protocol}"


class RedactingWSGIRequestHandler(WSGIRequestHandler):
    def log_message(self, format: str, *args: Any) -> None:
        if args and isinstance(args[0], str):
            args = (redact_http_request_line(args[0]),) + args[1:]
        super().log_message(format, *args)


class RateLimiter:
    def __init__(self, limit_per_minute: int):
        self.limit_per_minute = limit_per_minute
        self._hits: dict[str, list[float]] = {}

    def allow(self, key: str) -> bool:
        now = time.time()
        window_start = now - 60
        hits = [value for value in self._hits.get(key, []) if value >= window_start]
        if len(hits) >= self.limit_per_minute:
            self._hits[key] = hits
            return False
        hits.append(now)
        self._hits[key] = hits
        return True


class Request:
    def __init__(self, environ: dict[str, Any]):
        self.environ = environ
        self.method = environ.get("REQUEST_METHOD", "GET").upper()
        self.path = environ.get("PATH_INFO", "/")
        self.query = parse_qs(environ.get("QUERY_STRING", ""), keep_blank_values=True)
        self.ip = environ.get("HTTP_X_FORWARDED_FOR", environ.get("REMOTE_ADDR", "")).split(",")[0].strip()
        self.user_agent = environ.get("HTTP_USER_AGENT")
        self.headers = self._headers(environ)
        length = int(environ.get("CONTENT_LENGTH") or 0)
        self.body = environ["wsgi.input"].read(length) if length > 0 else b""

    def json(self) -> dict[str, Any]:
        if not self.body:
            return {}
        value = json.loads(self.body.decode("utf-8"))
        if not isinstance(value, dict):
            raise ValueError("JSON body must be an object.")
        return value

    def form(self) -> dict[str, str]:
        parsed = parse_qs(self.body.decode("utf-8"), keep_blank_values=True)
        return {key: values[-1] if values else "" for key, values in parsed.items()}

    def query_value(self, key: str, default: str = "") -> str:
        values = self.query.get(key)
        return values[-1] if values else default

    @staticmethod
    def _headers(environ: dict[str, Any]) -> dict[str, str]:
        headers: dict[str, str] = {}
        for key, value in environ.items():
            if key.startswith("HTTP_"):
                name = key[5:].replace("_", "-").lower()
                headers[name] = value
        if "CONTENT_TYPE" in environ:
            headers["content-type"] = environ["CONTENT_TYPE"]
        return headers


class Response:
    def __init__(self, status: HTTPStatus, body: bytes, headers: HeaderList | None = None):
        self.status = status
        self.body = body
        self.headers = headers or []

    def __call__(self, start_response: StartResponse) -> list[bytes]:
        headers = [("Content-Length", str(len(self.body))), *self.headers]
        start_response(f"{self.status.value} {self.status.phrase}", headers)
        return [self.body]


class FileResponse:
    def __init__(self, path: Path, filename: str, size_bytes: int):
        self.path = path
        self.filename = filename
        self.size_bytes = size_bytes

    def __call__(self, start_response: StartResponse):
        headers = [
            ("Content-Length", str(self.size_bytes)),
            ("Content-Type", "application/octet-stream"),
            ("Content-Disposition", f'attachment; filename="{download_filename(self.filename)}"'),
        ]
        start_response(f"{HTTPStatus.OK.value} {HTTPStatus.OK.phrase}", headers)
        return stream_file(self.path)


class AutoEdgeApp:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.database = Database(settings.database_path)
        apply_migrations(self.database)
        self.service = LicensingService(self.database)
        self.rate_limiter = RateLimiter(settings.rate_limit_per_minute)
        self.tradovate_oauth = TradovateOAuthClient()

    def __call__(self, environ: dict[str, Any], start_response: StartResponse) -> list[bytes]:
        request = Request(environ)
        try:
            response = self.route(request)
        except Exception as exc:
            response = self.error_response(exc)
        return response(start_response)

    def route(self, request: Request) -> Response:
        if request.path == "/healthz":
            return json_response({"status": "ok"})
        if request.path in {"/privacy", "/privacy/"} and request.method == "GET":
            return html_response(public_privacy_page())
        if request.path in {"/terms", "/terms/"} and request.method == "GET":
            return html_response(public_terms_page())
        if request.path in {"/api/trader/license/check", "/api/trader/license/activate"} and request.method == "POST":
            return self.trader_license_check(request)
        if request.path == "/api/nt8/license/check":
            if request.method == "POST":
                return self.nt8_license_check(request)
            return json_response(
                self.nt8_block_response("invalid_request", "Method not allowed.", None),
                HTTPStatus.METHOD_NOT_ALLOWED,
            )
        if request.path == "/api/trader/releases/manifest" and request.method == "POST":
            return self.trader_release_manifest(request)
        if request.path == "/api/trader/releases/download-token" and request.method == "POST":
            return self.trader_release_download_token(request)
        if request.path.startswith("/api/trader/releases/download/") and request.method == "GET":
            return self.trader_release_download(request)
        if request.path == "/api/trader/tradovate/oauth/start" and request.method == "POST":
            return self.tradovate_oauth_start(request)
        if request.path == "/api/trader/tradovate/oauth/callback" and request.method == "GET":
            return self.tradovate_oauth_callback(request)
        if request.path == "/api/trader/tradovate/oauth/complete" and request.method == "POST":
            return self.tradovate_oauth_complete(request)
        if request.path == "/api/trader/tradovate/oauth/refresh" and request.method == "POST":
            return self.tradovate_oauth_refresh(request)
        if request.path == "/api/whop/entitlements" and request.method == "POST":
            return self.whop_entitlement_update(request)

        if request.path == "/admin/login":
            return self.admin_login(request)
        if request.path == "/admin/logout":
            return self.admin_logout(request)
        if request.path == "/admin":
            return redirect("/admin/customers")
        if request.path == "/admin/password":
            return self.with_admin(request, self.admin_password)
        if request.path == "/admin/customers":
            return self.with_admin(request, self.admin_customers)
        if request.path == "/admin/products":
            return self.with_admin(request, self.admin_products)
        if request.path == "/admin/packages":
            return self.with_admin(request, self.admin_packages)
        if request.path == "/admin/releases":
            return self.with_admin(request, self.admin_releases)
        if request.path.startswith("/admin/customers/"):
            return self.with_admin(request, self.admin_customer_detail)
        if request.path.startswith("/admin/devices/"):
            return self.with_admin(request, self.admin_device_action)
        return text_response(HTTPStatus.NOT_FOUND, "Not found")

    def trader_license_check(self, request: Request) -> Response:
        if not self.rate_limiter.allow(f"license:{request.ip}"):
            return json_response({"status": "rate_limited", "message": "Too many license checks."}, HTTPStatus.TOO_MANY_REQUESTS)
        payload = request.json()
        response = self.service.check_license(
            license_key=payload.get("license_key"),
            email=payload.get("email"),
            customer_id=payload.get("customer_id"),
            whop_user_id=payload.get("whop_user_id"),
            machine_fingerprint=payload.get("machine_fingerprint") or "",
            app_version=payload.get("app_version"),
            ip_address=request.ip,
            user_agent=request.user_agent,
            check_interval_seconds=self.settings.license_check_interval_seconds,
            grace_period_seconds=self.settings.grace_period_seconds,
            max_devices=self.settings.trader_max_devices,
        )
        return json_response(response)

    def nt8_license_check(self, request: Request) -> Response:
        if not self.rate_limiter.allow(f"nt8-license:{request.ip}"):
            return json_response(
                self.nt8_block_response("rate_limited", "Too many NT8 license checks.", None),
                HTTPStatus.TOO_MANY_REQUESTS,
            )
        try:
            payload = request.json()
        except ValueError:
            return json_response(
                self.nt8_block_response("invalid_request", "Request body must be a JSON object.", None),
                HTTPStatus.BAD_REQUEST,
            )
        response = self.service.check_nt8_license(
            license_key=payload.get("license_key"),
            email=payload.get("email"),
            customer_id=payload.get("customer_id"),
            whop_user_id=payload.get("whop_user_id"),
            machine_fingerprint=payload.get("machine_fingerprint") or "",
            nt8_version=payload.get("nt8_version"),
            strategy=payload.get("strategy"),
            ip_address=request.ip,
            user_agent=request.user_agent,
            check_interval_seconds=self.settings.license_check_interval_seconds,
            grace_period_seconds=self.settings.grace_period_seconds,
            max_devices=self.settings.trader_max_devices,
            lease_secret=self.settings.license_lease_secret,
        )
        return json_response(response)

    def nt8_block_response(self, status: str, message: str, requested_strategy: str | None) -> dict[str, Any]:
        return {
            "status": status,
            "licensed": False,
            "message": message,
            "strategy_keys": [],
            "requested_strategy": requested_strategy,
            "next_check_seconds": 300,
            "grace_period_seconds": 0,
            "lease": None,
        }

    def trader_release_manifest(self, request: Request) -> Response:
        if not self.rate_limiter.allow(f"release-manifest:{request.ip}"):
            return json_response({"status": "rate_limited", "message": "Too many release manifest requests."}, HTTPStatus.TOO_MANY_REQUESTS)
        payload = request.json()
        include_types = payload.get("include_types") if isinstance(payload.get("include_types"), list) else None
        installed_packages = payload.get("installed_packages") if isinstance(payload.get("installed_packages"), list) else None
        response = self.service.release_manifest(
            license_key=payload.get("license_key"),
            email=payload.get("email"),
            customer_id=payload.get("customer_id"),
            whop_user_id=payload.get("whop_user_id"),
            machine_fingerprint=payload.get("machine_fingerprint") or "",
            app_version=payload.get("app_version"),
            channel=payload.get("channel") or "stable",
            platform=payload.get("platform") or DEFAULT_RELEASE_PLATFORM,
            include_types=include_types,
            installed_packages=installed_packages,
            ip_address=request.ip,
            user_agent=request.user_agent,
            check_interval_seconds=self.settings.license_check_interval_seconds,
            grace_period_seconds=self.settings.grace_period_seconds,
            max_devices=self.settings.trader_max_devices,
        )
        return json_response(response)

    def trader_release_download_token(self, request: Request) -> Response:
        if not self.rate_limiter.allow(f"release-token:{request.ip}"):
            return json_response({"status": "rate_limited", "message": "Too many download token requests."}, HTTPStatus.TOO_MANY_REQUESTS)
        payload = request.json()
        installed_packages = payload.get("installed_packages") if isinstance(payload.get("installed_packages"), list) else None
        result = self.service.create_release_download_token(
            release_id=payload.get("release_id") or "",
            license_key=payload.get("license_key"),
            email=payload.get("email"),
            customer_id=payload.get("customer_id"),
            whop_user_id=payload.get("whop_user_id"),
            machine_fingerprint=payload.get("machine_fingerprint") or "",
            app_version=payload.get("app_version"),
            channel=payload.get("channel") or "stable",
            platform=payload.get("platform") or DEFAULT_RELEASE_PLATFORM,
            installed_packages=installed_packages,
            ip_address=request.ip,
            user_agent=request.user_agent,
            check_interval_seconds=self.settings.license_check_interval_seconds,
            grace_period_seconds=self.settings.grace_period_seconds,
            token_seconds=self.settings.release_download_token_seconds,
            max_devices=self.settings.trader_max_devices,
        )
        if result.get("token"):
            result["download_url"] = f"{self.settings.public_base_url.rstrip('/')}/api/trader/releases/download/{result['token']}"
        status = HTTPStatus.OK if result["status"] == "ok" else HTTPStatus.FORBIDDEN
        if result["status"] == "not_found":
            status = HTTPStatus.NOT_FOUND
        if result["status"] in {"invalid_request", "device_blocked", "unknown_customer"}:
            status = HTTPStatus.BAD_REQUEST
        return json_response(result, status)

    def trader_release_download(self, request: Request) -> Response:
        if not self.rate_limiter.allow(f"release-download:{request.ip}"):
            return json_response({"status": "rate_limited", "message": "Too many download requests."}, HTTPStatus.TOO_MANY_REQUESTS)
        token = request.path.rsplit("/", 1)[-1]
        result = self.service.resolve_release_download(
            token=token,
            artifact_dir=self.settings.release_artifact_dir,
            ip_address=request.ip,
            user_agent=request.user_agent,
        )
        if result["status"] != "ok":
            status = HTTPStatus.FORBIDDEN
            if result["status"] == "artifact_missing":
                status = HTTPStatus.NOT_FOUND
            return json_response({"status": result["status"], "message": result["message"]}, status)
        artifact_path = result["artifact_path"]
        return file_response(
            artifact_path,
            result["artifact_filename"],
            size_bytes=result["size_bytes"],
        )

    def tradovate_oauth_start(self, request: Request) -> Response:
        if not self.rate_limiter.allow(f"tradovate-oauth-start:{request.ip}"):
            return json_response({"status": "rate_limited", "message": "Too many Tradovate OAuth requests."}, HTTPStatus.TOO_MANY_REQUESTS)
        if not self.settings.tradovate_oauth_enabled():
            return json_response(
                {"status": "unavailable", "message": "Tradovate OAuth is not configured on this server."},
                HTTPStatus.SERVICE_UNAVAILABLE,
            )
        payload = request.json()
        try:
            environment = normalize_tradovate_environment(payload.get("environment"))
        except ValueError as exc:
            return json_response({"status": "invalid_request", "message": str(exc)}, HTTPStatus.BAD_REQUEST)
        state = random_token()
        authorization_url = build_authorization_url(
            authorize_url=self.tradovate_authorize_url(environment),
            client_id=self.settings.tradovate_oauth_client_id or "",
            redirect_uri=self.tradovate_redirect_uri(),
            state=state,
            scopes=self.settings.tradovate_oauth_scopes,
        )
        result = self.service.start_tradovate_oauth(
            state=state,
            license_key=payload.get("license_key"),
            email=payload.get("email"),
            customer_id=payload.get("customer_id"),
            whop_user_id=payload.get("whop_user_id"),
            machine_fingerprint=payload.get("machine_fingerprint") or "",
            app_version=payload.get("app_version"),
            platform=payload.get("platform"),
            channel=payload.get("channel"),
            environment=environment,
            ip_address=request.ip,
            user_agent=request.user_agent,
            check_interval_seconds=self.settings.license_check_interval_seconds,
            grace_period_seconds=self.settings.grace_period_seconds,
            max_devices=self.settings.trader_max_devices,
            state_seconds=self.settings.tradovate_oauth_state_seconds,
        )
        status = HTTPStatus.OK if result["status"] == "ok" else HTTPStatus.FORBIDDEN
        if result["status"] in {"invalid_request", "unknown_customer"}:
            status = HTTPStatus.BAD_REQUEST
        response = {
            "status": result["status"],
            "message": result["message"],
            "authorization_url": authorization_url if result["status"] == "ok" else None,
            "state": result["state"],
            "expires_at": result["expires_at"],
            "environment": result.get("environment") or environment,
        }
        return json_response(response, status)

    def tradovate_oauth_callback(self, request: Request) -> Response:
        if not self.settings.tradovate_oauth_enabled():
            return html_response(tradovate_oauth_result_page("failed", "Tradovate OAuth is not configured."), HTTPStatus.SERVICE_UNAVAILABLE)
        state = request.query_value("state")
        error = request.query_value("error")
        code = request.query_value("code")
        context = self.service.tradovate_oauth_callback_context(state)
        if context["status"] != "pending":
            status = HTTPStatus.OK if context["status"] == "authorized" else HTTPStatus.BAD_REQUEST
            return html_response(tradovate_oauth_result_page(context["status"], context["message"]), status)
        if error:
            result = self.service.fail_tradovate_oauth(
                state=state,
                failure_code=error,
                failure_message=request.query_value("error_description") or "Tradovate OAuth was cancelled or failed.",
                ip_address=request.ip,
            )
            return html_response(tradovate_oauth_result_page(result["status"], result["message"]), HTTPStatus.BAD_REQUEST)
        if not code:
            result = self.service.fail_tradovate_oauth(
                state=state,
                failure_code="missing_code",
                failure_message="Tradovate did not return an authorization code.",
                ip_address=request.ip,
            )
            return html_response(tradovate_oauth_result_page(result["status"], result["message"]), HTTPStatus.BAD_REQUEST)

        environment = context["environment"]
        try:
            token_response = self.tradovate_oauth.exchange_code(
                token_url=self.tradovate_token_url(environment),
                client_id=self.settings.tradovate_oauth_client_id or "",
                client_secret=self.settings.tradovate_oauth_client_secret or "",
                redirect_uri=self.tradovate_redirect_uri(),
                code=code,
            )
            me_response = self.tradovate_oauth.me(
                api_base_url=self.tradovate_api_base_url(environment),
                access_token=token_response["access_token"],
            )
            result = self.service.authorize_tradovate_oauth(
                state=state,
                token_response=token_response,
                me_response=me_response,
                token_secret=self.tradovate_token_secret(),
                ip_address=request.ip,
            )
        except TradovateOAuthError as exc:
            result = self.service.fail_tradovate_oauth(
                state=state,
                failure_code=exc.code,
                failure_message=exc.message,
                ip_address=request.ip,
            )
            return html_response(tradovate_oauth_result_page(result["status"], result["message"]), HTTPStatus.BAD_REQUEST)

        status = HTTPStatus.OK if result["status"] == "authorized" else HTTPStatus.BAD_REQUEST
        return html_response(tradovate_oauth_result_page(result["status"], result["message"]), status)

    def tradovate_oauth_complete(self, request: Request) -> Response:
        if not self.rate_limiter.allow(f"tradovate-oauth-complete:{request.ip}"):
            return json_response({"status": "rate_limited", "message": "Too many Tradovate OAuth requests."}, HTTPStatus.TOO_MANY_REQUESTS)
        if not self.settings.tradovate_oauth_enabled():
            return json_response(
                {"status": "failed", "message": "Tradovate OAuth is not configured on this server."},
                HTTPStatus.SERVICE_UNAVAILABLE,
            )
        payload = request.json()
        result = self.service.complete_tradovate_oauth(
            state=payload.get("state") or "",
            license_key=payload.get("license_key"),
            email=payload.get("email"),
            customer_id=payload.get("customer_id"),
            whop_user_id=payload.get("whop_user_id"),
            machine_fingerprint=payload.get("machine_fingerprint") or "",
            app_version=payload.get("app_version"),
            ip_address=request.ip,
            user_agent=request.user_agent,
            check_interval_seconds=self.settings.license_check_interval_seconds,
            grace_period_seconds=self.settings.grace_period_seconds,
            max_devices=self.settings.trader_max_devices,
            token_secret=self.tradovate_token_secret(),
        )
        self.add_tradovate_public_api_fields(result)
        if result.get("status") != "authorized":
            result.pop("access_token", None)
            result.pop("oauth_session_id", None)
        return json_response(result)

    def tradovate_oauth_refresh(self, request: Request) -> Response:
        if not self.rate_limiter.allow(f"tradovate-oauth-refresh:{request.ip}"):
            return json_response({"status": "rate_limited", "message": "Too many Tradovate OAuth requests."}, HTTPStatus.TOO_MANY_REQUESTS)
        if not self.settings.tradovate_oauth_enabled():
            return json_response(
                {"status": "failed", "message": "Tradovate OAuth is not configured on this server."},
                HTTPStatus.SERVICE_UNAVAILABLE,
            )
        payload = request.json()
        oauth_session_id = payload.get("oauth_session_id") or payload.get("session_id")
        context = self.service.tradovate_oauth_refresh_context(
            oauth_session_id=oauth_session_id,
            state=payload.get("state") or "",
            license_key=payload.get("license_key"),
            email=payload.get("email"),
            customer_id=payload.get("customer_id"),
            whop_user_id=payload.get("whop_user_id"),
            machine_fingerprint=payload.get("machine_fingerprint") or "",
            app_version=payload.get("app_version"),
            ip_address=request.ip,
            user_agent=request.user_agent,
            check_interval_seconds=self.settings.license_check_interval_seconds,
            grace_period_seconds=self.settings.grace_period_seconds,
            max_devices=self.settings.trader_max_devices,
            token_secret=self.tradovate_token_secret(),
        )
        stored_access_token = context.pop("access_token", None)
        if context.get("status") != "authorized" or not stored_access_token:
            self.add_tradovate_public_api_fields(context)
            return json_response(context)
        try:
            token_response = self.tradovate_oauth.renew_access_token(
                api_base_url=self.tradovate_api_base_url(context["environment"]),
                access_token=stored_access_token,
            )
        except TradovateOAuthError as exc:
            return json_response({"status": "failed", "message": exc.message, "environment": context.get("environment")}, HTTPStatus.BAD_GATEWAY)
        result = self.service.store_tradovate_oauth_refresh(
            oauth_session_id=oauth_session_id,
            state=payload.get("state") or "",
            token_response=token_response,
            token_secret=self.tradovate_token_secret(),
        )
        self.add_tradovate_public_api_fields(result)
        if result.get("status") != "authorized":
            result.pop("access_token", None)
        return json_response(result)

    def whop_entitlement_update(self, request: Request) -> Response:
        if not self.rate_limiter.allow(f"whop:{request.ip}"):
            return json_response({"status": "rate_limited"}, HTTPStatus.TOO_MANY_REQUESTS)
        signature_valid = False
        signature_reason = "not checked"
        if self.settings.whop_webhook_secret and request.headers.get("webhook-signature"):
            signature_valid, signature_reason = verify_standard_webhook(
                request.body,
                request.headers,
                self.settings.whop_webhook_secret,
            )
        bearer_valid = verify_bearer(request.headers, self.settings.whop_bearer_token)
        if not signature_valid and not bearer_valid:
            return json_response({"status": "unauthorized", "message": signature_reason}, HTTPStatus.UNAUTHORIZED)
        payload = request.json()
        webhook_id = request.headers.get("webhook-id") or str(payload.get("id") or payload.get("event_id") or sha256_hex(request.body.decode("utf-8")))
        result = self.service.process_whop_event(payload, webhook_id, signature_valid=signature_valid or bearer_valid, ip_address=request.ip)
        return json_response(result)

    def admin_login(self, request: Request) -> Response:
        if request.method == "GET":
            notice = "Password changed. Sign in again." if request.query_value("password_changed") == "1" else None
            return html_response(self.page("Sign in", login_form(notice=notice)))
        if request.method != "POST":
            return text_response(HTTPStatus.METHOD_NOT_ALLOWED, "Method not allowed")
        form = request.form()
        result = self.service.authenticate_admin(
            form.get("username", ""),
            form.get("password", ""),
            session_hours=self.settings.session_hours,
            ip_address=request.ip,
            user_agent=request.user_agent,
        )
        if result is None:
            return html_response(self.page("Sign in", login_form("Invalid username or password.")), HTTPStatus.UNAUTHORIZED)
        _, token = result
        cookie = self.session_cookie(token)
        return redirect("/admin/customers", [("Set-Cookie", cookie)])

    def admin_logout(self, request: Request) -> Response:
        token = self.session_token(request)
        admin = self.service.admin_from_session(token)
        if token:
            self.service.revoke_session(token, admin["id"] if admin else None)
        return redirect("/admin/login", [("Set-Cookie", self.expired_session_cookie())])

    def with_admin(self, request: Request, handler: Callable[[Request, dict[str, Any]], Response]) -> Response:
        token = self.session_token(request)
        admin = self.service.admin_from_session(token)
        if admin is None:
            return redirect("/admin/login")
        if request.method == "POST" and request.form().get("csrf") != self.csrf_token(token or ""):
            return text_response(HTTPStatus.FORBIDDEN, "Invalid CSRF token.")
        return handler(request, admin)

    def admin_customers(self, request: Request, admin: dict[str, Any]) -> Response:
        if request.method == "POST":
            form = request.form()
            created = self.service.create_or_update_customer(
                email=form.get("email"),
                name=form.get("name"),
                whop_user_id=form.get("whop_user_id"),
                whop_member_id=form.get("whop_member_id"),
                actor_type="admin",
                actor_id=admin["id"],
                ip_address=request.ip,
            )
            suffix = f"?created_key={html.escape(created.license_key or '')}" if created.license_key else ""
            return redirect(f"/admin/customers/{created.customer['id']}{suffix}")
        query = request.query_value("q")
        customers = self.service.search_customers(query)
        csrf = self.csrf_token(self.session_token(request) or "")
        body = customer_search_page(customers, query, csrf)
        return html_response(self.page("Customers", body, admin))

    def admin_products(self, request: Request, admin: dict[str, Any]) -> Response:
        csrf = self.csrf_token(self.session_token(request) or "")
        if request.method == "POST":
            form = request.form()
            product_id = form.get("product_id", "").strip()
            name = form.get("name", "")
            internal_slug = form.get("slug") or name
            internal_feature_id = form.get("feature_id") or f"strategy.{slugify(internal_slug)}.runtime"
            if product_id:
                existing = self.service.get_product(product_id)
                self.service.update_product(
                    product_id=product_id,
                    slug=internal_slug,
                    name=name,
                    feature_id=internal_feature_id,
                    whop_product_id=existing.get("whop_product_id") if existing else None,
                    is_active=form.get("is_active") == "on",
                    nt8_strategy_key=form.get("nt8_strategy_key") or None,
                    trader_enabled=form.get("trader_enabled") == "on",
                    nt8_enabled=form.get("nt8_enabled") == "on",
                    actor_id=admin["id"],
                    ip_address=request.ip,
                )
            else:
                self.service.upsert_product(
                    slug=internal_slug,
                    name=name,
                    feature_id=internal_feature_id,
                    whop_product_id=form.get("whop_product_id") or None,
                    is_active=form.get("is_active") == "on",
                    nt8_strategy_key=form.get("nt8_strategy_key") or None,
                    trader_enabled=form.get("trader_enabled") == "on",
                    nt8_enabled=form.get("nt8_enabled") == "on",
                    actor_id=admin["id"],
                    ip_address=request.ip,
                )
            return redirect("/admin/products")
        products = self.service.list_products()
        edit_id = request.query_value("edit")
        selected_product = self.service.get_product(edit_id) if edit_id else None
        return html_response(self.page("Products", products_page(products, csrf, selected_product), admin))

    def admin_packages(self, request: Request, admin: dict[str, Any]) -> Response:
        csrf = self.csrf_token(self.session_token(request) or "")
        products = self.service.list_products()
        if request.method == "POST":
            form = request.form()
            default_days = parse_optional_int(form.get("default_days"))
            grants: list[dict[str, Any]] = []
            for product in products:
                product_id = product["id"]
                if form.get(f"grant_{product_id}") != "on":
                    continue
                grants.append(
                    {
                        "product_id": product_id,
                        "days": parse_optional_int(form.get(f"days_{product_id}")),
                    }
                )
            self.service.upsert_whop_package(
                package_id=form.get("package_id") or None,
                whop_id=form.get("whop_id", ""),
                whop_id_type=form.get("whop_id_type", "plan"),
                name=form.get("name", ""),
                default_days=default_days,
                is_active=form.get("is_active") == "on",
                is_ignored=form.get("is_ignored") == "on",
                grants=grants,
                actor_id=admin["id"],
                ip_address=request.ip,
            )
            return redirect("/admin/packages")
        packages = self.service.list_whop_packages()
        edit_id = request.query_value("edit")
        selected_package = self.service.get_whop_package(edit_id) if edit_id else None
        return html_response(self.page("Whop Packages", packages_page(packages, products, csrf, selected_package), admin))

    def admin_releases(self, request: Request, admin: dict[str, Any]) -> Response:
        csrf = self.csrf_token(self.session_token(request) or "")
        products = self.service.list_products(include_inactive=False)
        if request.method == "POST":
            form = request.form()
            release_type = form.get("release_type") or ("trader_desktop" if form.get("scope") == "app" else "strategy_package")
            scope = "app" if release_type == "trader_desktop" else "strategy"
            product_id = form.get("product_id") or None
            self.service.upsert_release(
                release_id=form.get("release_id") or None,
                scope=scope,
                release_type=release_type,
                product_key=form.get("product_key") or None,
                product_id=product_id if scope == "strategy" else None,
                channel=form.get("channel", "stable"),
                platform=form.get("platform", DEFAULT_RELEASE_PLATFORM),
                version=form.get("version", ""),
                min_supported_version=form.get("min_supported_version") or None,
                is_required=form.get("is_required") == "on",
                is_active=form.get("is_active") == "on",
                artifact_path=form.get("artifact_path", ""),
                artifact_filename=form.get("artifact_filename") or None,
                size_bytes=parse_optional_int(form.get("size_bytes")),
                sha256_value=form.get("sha256") or None,
                signature=form.get("signature") or None,
                signature_key_id=form.get("signature_key_id") or None,
                release_notes=form.get("release_notes") or None,
                artifact_dir=self.settings.release_artifact_dir,
                audience_mode=form.get("audience_mode") or "all",
                allowed_customer_ids=form.get("allowed_customer_ids") or None,
                allowed_emails=form.get("allowed_emails") or None,
                allowed_license_keys=form.get("allowed_license_keys") or None,
                required_tags=form.get("required_tags") or None,
                rollout_percent=parse_optional_int(form.get("rollout_percent")),
                rollback_reason=form.get("rollback_reason") or None,
                actor_id=admin["id"],
                ip_address=request.ip,
            )
            return redirect("/admin/releases")
        releases = self.service.list_releases()
        edit_id = request.query_value("edit")
        selected_release = self.service.get_release(edit_id) if edit_id else None
        return html_response(self.page("Releases", releases_page(releases, products, csrf, selected_release, self.settings.release_artifact_dir), admin))

    def admin_password(self, request: Request, admin: dict[str, Any]) -> Response:
        csrf = self.csrf_token(self.session_token(request) or "")
        if request.method == "GET":
            return html_response(self.page("Change Password", password_page(csrf), admin))
        if request.method != "POST":
            return text_response(HTTPStatus.METHOD_NOT_ALLOWED, "Method not allowed")
        form = request.form()
        new_password = form.get("new_password", "")
        if new_password != form.get("confirm_password", ""):
            return html_response(
                self.page("Change Password", password_page(csrf, "New password and confirmation do not match."), admin),
                HTTPStatus.BAD_REQUEST,
            )
        changed, message = self.service.change_admin_password(
            admin_id=admin["id"],
            current_password=form.get("current_password", ""),
            new_password=new_password,
            ip_address=request.ip,
        )
        if not changed:
            return html_response(self.page("Change Password", password_page(csrf, message), admin), HTTPStatus.BAD_REQUEST)
        return redirect("/admin/login?password_changed=1", [("Set-Cookie", self.expired_session_cookie())])

    def admin_customer_detail(self, request: Request, admin: dict[str, Any]) -> Response:
        parts = [part for part in request.path.split("/") if part]
        if len(parts) < 3:
            return text_response(HTTPStatus.NOT_FOUND, "Not found")
        customer_id = parts[2]
        if len(parts) == 4 and parts[3] == "entitlements" and request.method == "POST":
            form = request.form()
            self.service.manual_set_entitlement(
                customer_id=customer_id,
                product_id=form.get("product_id", ""),
                status=form.get("status", ""),
                expires_at=admin_time_input_to_utc(form.get("expires_at")),
                reason=form.get("reason") or None,
                actor_id=admin["id"],
                ip_address=request.ip,
            )
            return redirect(f"/admin/customers/{customer_id}")
        if len(parts) == 4 and parts[3] == "tags" and request.method == "POST":
            form = request.form()
            self.service.set_customer_tags(
                customer_id=customer_id,
                tags=form.get("tags") or "",
                actor_id=admin["id"],
                ip_address=request.ip,
            )
            return redirect(f"/admin/customers/{customer_id}")
        if len(parts) == 4 and parts[3] == "license-key" and request.method == "POST":
            new_key = self.service.rotate_customer_license_key(
                customer_id=customer_id,
                actor_id=admin["id"],
                ip_address=request.ip,
            )
            return redirect(f"/admin/customers/{customer_id}?created_key={new_key}")
        if len(parts) == 4 and parts[3] == "device-limit" and request.method == "POST":
            form = request.form()
            self.service.set_customer_max_devices(
                customer_id=customer_id,
                max_devices=parse_optional_int(form.get("max_devices")),
                actor_id=admin["id"],
                ip_address=request.ip,
            )
            return redirect(f"/admin/customers/{customer_id}")
        if len(parts) == 4 and parts[3] == "devices" and request.method == "POST":
            form = request.form()
            if form.get("action") == "block_all":
                self.service.block_all_customer_devices(
                    customer_id=customer_id,
                    note=form.get("note") or "Device reset",
                    actor_id=admin["id"],
                    ip_address=request.ip,
                )
            return redirect(f"/admin/customers/{customer_id}")
        detail = self.service.customer_detail(customer_id, default_max_devices=self.settings.trader_max_devices)
        if detail is None:
            return text_response(HTTPStatus.NOT_FOUND, "Customer not found")
        products = self.service.list_products(include_inactive=False)
        csrf = self.csrf_token(self.session_token(request) or "")
        created_key = request.query_value("created_key")
        body = customer_detail_page(detail, products, csrf, created_key)
        return html_response(self.page("Customer", body, admin))

    def admin_device_action(self, request: Request, admin: dict[str, Any]) -> Response:
        if request.method != "POST":
            return text_response(HTTPStatus.METHOD_NOT_ALLOWED, "Method not allowed")
        parts = [part for part in request.path.split("/") if part]
        if len(parts) != 4 or parts[3] not in {"block", "unblock"}:
            return text_response(HTTPStatus.NOT_FOUND, "Not found")
        form = request.form()
        self.service.set_device_blocked(
            device_id=parts[2],
            is_blocked=parts[3] == "block",
            note=form.get("note") or None,
            actor_id=admin["id"],
            ip_address=request.ip,
        )
        return redirect(form.get("return_to") or "/admin/customers")

    def tradovate_redirect_uri(self) -> str:
        return self.settings.tradovate_oauth_redirect_uri or (
            self.settings.public_base_url.rstrip("/") + "/api/trader/tradovate/oauth/callback"
        )

    def tradovate_authorize_url(self, environment: str) -> str:
        if environment == "demo" and self.settings.tradovate_oauth_demo_authorize_url:
            return self.settings.tradovate_oauth_demo_authorize_url
        return self.settings.tradovate_oauth_authorize_url

    def tradovate_token_url(self, environment: str) -> str:
        if environment == "demo" and self.settings.tradovate_oauth_demo_token_url:
            return self.settings.tradovate_oauth_demo_token_url
        return self.settings.tradovate_oauth_token_url

    def tradovate_api_base_url(self, environment: str) -> str:
        if environment == "demo":
            return self.settings.tradovate_demo_api_base_url
        return self.settings.tradovate_live_api_base_url

    def tradovate_token_secret(self) -> str:
        return self.settings.tradovate_oauth_token_secret or self.settings.admin_cookie_secret

    def add_tradovate_public_api_fields(self, result: dict[str, Any]) -> None:
        environment = result.get("environment")
        if environment in {"live", "demo"}:
            result["api_base_url"] = self.tradovate_api_base_url(environment)

    def session_token(self, request: Request) -> str | None:
        cookies = parse_cookie(request.headers.get("cookie"))
        signed = cookies.get("autoedge_admin")
        return unsign_value(self.settings.admin_cookie_secret, signed) if signed else None

    def session_cookie(self, token: str) -> str:
        value = sign_value(self.settings.admin_cookie_secret, token)
        cookie = f"autoedge_admin={value}; Path=/admin; Max-Age={self.settings.session_hours * 3600}; HttpOnly; SameSite=Strict"
        if self.settings.cookie_secure:
            cookie += "; Secure"
        return cookie

    def expired_session_cookie(self) -> str:
        cookie = "autoedge_admin=; Path=/admin; Max-Age=0; HttpOnly; SameSite=Strict"
        if self.settings.cookie_secure:
            cookie += "; Secure"
        return cookie

    def csrf_token(self, session_token: str) -> str:
        return sha256_hex(f"{session_token}:{self.settings.admin_cookie_secret}")

    def page(self, title: str, body: str, admin: dict[str, Any] | None = None) -> str:
        nav = ""
        if admin:
            nav = """
            <nav>
              <a href="/admin/customers">Customers</a>
              <a href="/admin/products">Products</a>
              <a href="/admin/packages">Whop Packages</a>
              <a href="/admin/releases">Releases</a>
              <span class="spacer"></span>
              <span class="admin-clock" data-admin-clock aria-label="Current Eastern time">Loading ET...</span>
              <span class="admin-user">{username}</span>
              <a href="/admin/password">Change password</a>
              <a href="/admin/logout">Sign out</a>
            </nav>
            """.format(username=e(admin["username"]))
        clock_script = ADMIN_CLOCK_SCRIPT if admin else ""
        return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{e(title)} · AutoEdge Licensing</title>
  <style>{STYLE}</style>
</head>
<body>
  {nav}
  <main>{body}</main>
  {clock_script}
</body>
</html>"""

    def error_response(self, exc: Exception) -> Response:
        if isinstance(exc, ValueError):
            return text_response(HTTPStatus.BAD_REQUEST, str(exc))
        return text_response(HTTPStatus.INTERNAL_SERVER_ERROR, "Internal server error")


def e(value: Any) -> str:
    return html.escape("" if value is None else str(value))


def display_product_name(value: str | None) -> str:
    if not value:
        return ""
    if value.endswith(" Runtime"):
        return value[: -len(" Runtime")]
    return value


def format_bool(value: Any) -> str:
    return "yes" if value else "no"


def format_json(value: str | None) -> str:
    if not value:
        return ""
    try:
        return json.dumps(json.loads(value), indent=2, sort_keys=True)
    except json.JSONDecodeError:
        return value


def format_list_field(value: str | None) -> str:
    if not value:
        return ""
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return value
    if not isinstance(parsed, list):
        return value
    return "\n".join(str(item) for item in parsed)


def info_tip(text: str) -> str:
    return f'<span class="info-tip" title="{e(text)}" aria-label="{e(text)}">i</span>'


def short_hash(value: str | None) -> str:
    return value[:12] + "..." if value and len(value) > 15 else (value or "")


def format_admin_time(value: Any) -> str:
    parsed = parse_time(value)
    if parsed is None:
        return ""
    local = parsed.astimezone(ADMIN_TIME_ZONE)
    return f"{local:%Y-%m-%d %H:%M:%S} {ADMIN_TIME_LABEL}"


def admin_time_input_to_utc(value: str | None) -> str | None:
    if value is None or not value.strip():
        return None
    cleaned = value.strip()
    if cleaned.endswith("Z"):
        cleaned = cleaned[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(cleaned)
    except ValueError as exc:
        raise ValueError("Invalid expiry date/time.") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=ADMIN_TIME_ZONE)
    return parsed.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def parse_optional_int(value: str | None) -> int | None:
    if value is None or not value.strip():
        return None
    return int(value)


def json_response(data: dict[str, Any], status: HTTPStatus = HTTPStatus.OK) -> Response:
    body = json.dumps(data, sort_keys=True).encode("utf-8")
    return Response(status, body, [("Content-Type", "application/json; charset=utf-8")])


def text_response(status: HTTPStatus, text: str) -> Response:
    return Response(status, text.encode("utf-8"), [("Content-Type", "text/plain; charset=utf-8")])


def html_response(html_body: str, status: HTTPStatus = HTTPStatus.OK) -> Response:
    return Response(status, html_body.encode("utf-8"), [("Content-Type", "text/html; charset=utf-8")])


def tradovate_oauth_result_page(status: str, message: str) -> str:
    title = "Tradovate Login Complete" if status == "authorized" else "Tradovate Login Failed"
    body_message = "You can return to Trader Desktop." if status == "authorized" else message
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{e(title)} · AutoEdge</title>
  <style>
    body {{ margin: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: #f6f7f8; color: #202428; }}
    main {{ width: min(520px, calc(100vw - 32px)); margin: 80px auto; padding: 24px; background: #fff; border: 1px solid #d8dee4; border-radius: 8px; }}
    h1 {{ margin: 0 0 10px; font-size: 24px; }}
    p {{ margin: 0; color: #64707d; line-height: 1.45; }}
  </style>
</head>
<body>
  <main>
    <h1>{e(title)}</h1>
    <p>{e(body_message)}</p>
  </main>
</body>
</html>"""


def public_legal_page(title: str, body: str) -> str:
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{e(title)} · AutoEdge Trader</title>
  <style>
    :root {{ color-scheme: light; }}
    body {{
      margin: 0;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: #f5f7fa;
      color: #1d252d;
    }}
    main {{
      width: min(820px, calc(100vw - 32px));
      margin: 48px auto;
      padding: 32px;
      background: #fff;
      border: 1px solid #d8dee4;
      border-radius: 8px;
      box-sizing: border-box;
    }}
    h1 {{ margin: 0 0 8px; font-size: 32px; line-height: 1.15; }}
    h2 {{ margin: 28px 0 8px; font-size: 19px; }}
    p, li {{ color: #394550; line-height: 1.55; }}
    p {{ margin: 0 0 12px; }}
    ul {{ margin: 0 0 12px; padding-left: 22px; }}
    .updated {{ color: #687684; margin-bottom: 24px; }}
    a {{ color: #0b68d8; }}
  </style>
</head>
<body>
  <main>
    <h1>{e(title)}</h1>
    <p class="updated">Last updated: July 4, 2026</p>
    {body}
  </main>
</body>
</html>"""


def public_privacy_page() -> str:
    body = """
    <p>AutoEdge Trader uses this service to provide licensing, release delivery, and Tradovate OAuth sign-in for the Trader Desktop application.</p>

    <h2>Information We Process</h2>
    <ul>
      <li>License and customer identifiers such as license key hashes, email address, customer id, and Whop user id when provided.</li>
      <li>Device information used for licensing, including a hashed machine fingerprint, app version, platform, channel, IP address, and user agent.</li>
      <li>Tradovate OAuth metadata needed to connect Trader Desktop, including OAuth state/session records, Tradovate user id, token expiry, and encrypted access-token material.</li>
      <li>Operational records such as license checks, release downloads, webhook events, and security audit entries.</li>
    </ul>

    <h2>How We Use Information</h2>
    <ul>
      <li>To verify licenses and enforce device limits.</li>
      <li>To complete Tradovate OAuth sign-in without putting the Tradovate client secret in Trader Desktop.</li>
      <li>To provide software releases, support, abuse prevention, and service diagnostics.</li>
    </ul>

    <h2>Security</h2>
    <p>License keys and machine fingerprints are stored as hashes. Tradovate token material is encrypted on the server. We do not intentionally log OAuth authorization codes, access tokens, refresh tokens, or client secrets.</p>

    <h2>Sharing</h2>
    <p>We do not sell personal information. We share data only as needed to operate AutoEdge Trader, integrate with licensing/payment providers, comply with law, or protect the service.</p>

    <h2>Retention</h2>
    <p>Licensing, entitlement, device, audit, and OAuth records are kept as long as needed for the service, security, accounting, support, and legal obligations. Unfinished OAuth state records expire automatically.</p>

    <h2>Contact</h2>
    <p>For privacy questions or requests, contact AutoEdge support at <a href="mailto:geidnert@gmail.com">geidnert@gmail.com</a>.</p>
    """
    return public_legal_page("AutoEdge Trader Privacy Policy", body)


def public_terms_page() -> str:
    body = """
    <p>These Terms apply to AutoEdge Trader, the AutoEdge licensing service, and related Tradovate OAuth connectivity.</p>

    <h2>Trading Risk</h2>
    <p>AutoEdge Trader is software for market analysis, automation, and order routing. Trading futures and other financial instruments involves substantial risk. You are responsible for all trading decisions, account configuration, broker permissions, exchange fees, and losses. AutoEdge does not provide financial, investment, tax, or legal advice.</p>

    <h2>Account Access</h2>
    <p>When you connect Tradovate through OAuth, you authorize AutoEdge to help Trader Desktop obtain and renew access tokens for the permissions you grant. You can revoke access through Tradovate/NinjaTrader account controls. Do not share your license, OAuth session, or access tokens with others.</p>

    <h2>License and Availability</h2>
    <p>Access to AutoEdge Trader may require an active license or subscription. We may suspend or revoke access for expired payment, abuse, security concerns, or violation of these Terms. The service is provided on an as-available basis and may be interrupted for maintenance, provider outages, market conditions, or technical issues.</p>

    <h2>User Responsibilities</h2>
    <ul>
      <li>Use the software only with accounts and data you are authorized to access.</li>
      <li>Review orders, risk settings, symbols, accounts, and strategy settings before live trading.</li>
      <li>Comply with exchange, broker, Tradovate/NinjaTrader, and applicable legal requirements.</li>
      <li>Do not attempt to bypass licensing, device limits, security controls, or rate limits.</li>
    </ul>

    <h2>No Warranty</h2>
    <p>To the maximum extent permitted by law, AutoEdge Trader and the licensing service are provided without warranties of profitability, uninterrupted operation, data accuracy, or fitness for a particular purpose.</p>

    <h2>Limitation of Liability</h2>
    <p>To the maximum extent permitted by law, AutoEdge is not liable for trading losses, missed trades, rejected orders, market data issues, broker/API outages, lost profits, or indirect damages.</p>

    <h2>Contact</h2>
    <p>For questions about these Terms, contact AutoEdge support at <a href="mailto:geidnert@gmail.com">geidnert@gmail.com</a>.</p>
    """
    return public_legal_page("AutoEdge Trader Terms & Conditions", body)


def file_response(path: Path, filename: str, size_bytes: int) -> FileResponse:
    return FileResponse(path, filename, size_bytes)


def stream_file(path: Path, chunk_size: int = 1024 * 1024):
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(chunk_size)
            if not chunk:
                break
            yield chunk


def download_filename(value: str) -> str:
    cleaned = "".join(char for char in value if char.isalnum() or char in {".", "-", "_", " "}).strip()
    return cleaned or "download.bin"


def redirect(location: str, headers: HeaderList | None = None) -> Response:
    return Response(HTTPStatus.SEE_OTHER, b"", [("Location", location), *(headers or [])])


def login_form(error: str | None = None, notice: str | None = None) -> str:
    message = f'<p class="error">{e(error)}</p>' if error else ""
    notice_message = f'<p class="notice">{e(notice)}</p>' if notice else ""
    return f"""
    <section class="auth">
      <h1>AutoEdge Licensing</h1>
      {notice_message}
      {message}
      <form method="post" action="/admin/login">
        <label>Username <input name="username" autocomplete="username" required></label>
        <label>Password <input name="password" type="password" autocomplete="current-password" required></label>
        <button type="submit">Sign in</button>
      </form>
    </section>
    """


def password_page(csrf: str, error: str | None = None) -> str:
    message = f'<p class="error">{e(error)}</p>' if error else ""
    return f"""
    <header class="title-row">
      <div>
        <h1>Change Password</h1>
        <p>Changing the password signs out all active admin sessions.</p>
      </div>
    </header>
    <section class="panel narrow-panel">
      {message}
      <form class="stack-form" method="post" action="/admin/password">
        <input type="hidden" name="csrf" value="{e(csrf)}">
        <label>Current password <input name="current_password" type="password" autocomplete="current-password" required></label>
        <label>New password <input name="new_password" type="password" autocomplete="new-password" minlength="12" required></label>
        <label>Confirm new password <input name="confirm_password" type="password" autocomplete="new-password" minlength="12" required></label>
        <button type="submit">Change password</button>
      </form>
    </section>
    """


def customer_search_page(customers: list[dict[str, Any]], query: str, csrf: str) -> str:
    rows = "\n".join(
        f"""
        <tr>
          <td><a href="/admin/customers/{e(customer['id'])}">{e(customer.get('email') or '(no email)')}</a><small>{e(customer.get('name'))}</small></td>
          <td>{e(customer.get('whop_user_id'))}<small>member {e(customer.get('whop_member_id'))}</small></td>
          <td>{e(customer.get('license_key_last4'))}</td>
          <td>{e(customer.get('entitlement_count'))}</td>
          <td>{e(customer.get('device_count'))}</td>
          <td>{e(format_admin_time(customer.get('updated_at')))}</td>
        </tr>
        """
        for customer in customers
    )
    return f"""
    <header class="title-row">
      <div>
        <h1>Customers</h1>
        <p>Search by email, Whop id, member id, name, or internal customer id.</p>
      </div>
    </header>
    <form class="search" method="get">
      <input name="q" value="{e(query)}" placeholder="Search customers">
      <button type="submit">Search</button>
    </form>
    <section class="panel">
      <h2>Create customer</h2>
      <form class="grid-form" method="post">
        <input type="hidden" name="csrf" value="{e(csrf)}">
        <label>Email <input name="email" type="email"></label>
        <label>Name <input name="name"></label>
        <label>Whop user id <input name="whop_user_id"></label>
        <label>Whop member id <input name="whop_member_id"></label>
        <button type="submit">Create</button>
      </form>
    </section>
    <section class="panel">
      <table>
        <thead><tr><th>Customer</th><th>Whop IDs</th><th>Key</th><th>Entitlements</th><th>Devices</th><th>Updated ET</th></tr></thead>
        <tbody>{rows or '<tr><td colspan="6">No customers found.</td></tr>'}</tbody>
      </table>
    </section>
    """


def products_page(products: list[dict[str, Any]], csrf: str, selected_product: dict[str, Any] | None = None) -> str:
    selected = selected_product or {}
    is_editing = selected_product is not None
    form_title = "Edit product" if is_editing else "Add or update product"
    button_text = "Save changes" if is_editing else "Save product"
    active_checked = "checked" if selected.get("is_active", 1) else ""
    trader_checked = "checked" if selected.get("trader_enabled", 1) else ""
    nt8_checked = "checked" if selected.get("nt8_enabled", 1) else ""
    cancel_link = '<a class="button secondary" href="/admin/products">Cancel</a>' if is_editing else ""
    selected_name = display_product_name(selected.get("name"))
    rows = "\n".join(
        f"""
        <tr>
          <td>{e(display_product_name(product.get('name')))}</td>
          <td>{e(product.get('nt8_strategy_key'))}</td>
          <td>{format_bool(product.get('trader_enabled', 1))}</td>
          <td>{format_bool(product.get('nt8_enabled', 1))}</td>
          <td>{format_bool(product.get('is_active'))}</td>
          <td>{e(format_admin_time(product.get('updated_at')))}</td>
          <td><a class="button small" href="/admin/products?edit={e(product['id'])}">Edit</a></td>
        </tr>
        """
        for product in products
    )
    return f"""
    <header class="title-row">
      <div>
        <h1>Products</h1>
        <p>Products define Trader strategies. Whop plan mappings are managed on the Whop Packages page.</p>
      </div>
    </header>
    <section class="panel">
      <h2>{form_title}</h2>
      <form class="grid-form" method="post">
        <input type="hidden" name="csrf" value="{e(csrf)}">
        <input type="hidden" name="product_id" value="{e(selected.get('id'))}">
        <input type="hidden" name="slug" value="{e(selected.get('slug'))}">
        <input type="hidden" name="feature_id" value="{e(selected.get('feature_id'))}">
        <label>Strategy <input name="name" required placeholder="DUO" value="{e(selected_name)}"></label>
        <label>NT8 key <input name="nt8_strategy_key" required placeholder="DUO" value="{e(selected.get('nt8_strategy_key') or selected_name)}"></label>
        <label class="checkbox"><input name="trader_enabled" type="checkbox" {trader_checked}> Trader</label>
        <label class="checkbox"><input name="nt8_enabled" type="checkbox" {nt8_checked}> NT8</label>
        <label class="checkbox"><input name="is_active" type="checkbox" {active_checked}> Active</label>
        <button type="submit">{button_text}</button>
        {cancel_link}
      </form>
    </section>
    <section class="panel">
      <table>
        <thead><tr><th>Strategy</th><th>NT8 key</th><th>Trader</th><th>NT8</th><th>Active</th><th>Updated ET</th><th></th></tr></thead>
        <tbody>{rows or '<tr><td colspan="7">No products configured.</td></tr>'}</tbody>
      </table>
    </section>
    """


def packages_page(
    packages: list[dict[str, Any]],
    products: list[dict[str, Any]],
    csrf: str,
    selected_package: dict[str, Any] | None = None,
) -> str:
    selected = selected_package or {}
    is_editing = selected_package is not None
    selected_grants = {grant["product_id"]: grant for grant in selected.get("grants", [])}
    type_options = "\n".join(
        f'<option value="{value}" {"selected" if selected.get("whop_id_type", "plan") == value else ""}>{label}</option>'
        for value, label in (("plan", "Plan"), ("product", "Product"), ("unknown", "Unknown"))
    )
    active_checked = "checked" if selected.get("is_active", 1) else ""
    ignored_checked = "checked" if selected.get("is_ignored", 0) else ""
    form_title = "Edit Whop package" if is_editing else "Add Whop package"
    button_text = "Save changes" if is_editing else "Save package"
    cancel_link = '<a class="button secondary" href="/admin/packages">Cancel</a>' if is_editing else ""

    grant_rows = "\n".join(
        f"""
        <tr>
          <td>
            <label class="checkbox">
              <input name="grant_{e(product['id'])}" type="checkbox" {'checked' if product['id'] in selected_grants else ''}>
              {e(display_product_name(product.get('name')))}
            </label>
          </td>
          <td><input name="days_{e(product['id'])}" type="number" min="0" placeholder="default" value="{e(selected_grants.get(product['id'], {}).get('days'))}"></td>
        </tr>
        """
        for product in products
    )

    def grant_summary(package: dict[str, Any]) -> str:
        grants = package.get("grants", [])
        if not grants:
            return '<span class="muted">No grants</span>'
        parts = []
        for grant in grants:
            days = grant.get("days") if grant.get("days") is not None else package.get("default_days")
            label = f"{display_product_name(grant.get('product_name'))} {days}d" if days is not None else display_product_name(grant.get("product_name"))
            parts.append(f"<span>{e(label)}</span>")
        return '<div class="grant-list">' + "".join(parts) + "</div>"

    rows = "\n".join(
        f"""
        <tr>
          <td><strong>{e(package.get('name'))}</strong><small>{e(package.get('whop_id'))}</small></td>
          <td>{e(package.get('whop_id_type'))}</td>
          <td>{e(package.get('default_days'))}</td>
          <td>{grant_summary(package)}</td>
          <td>{format_bool(package.get('is_ignored'))}</td>
          <td>{format_bool(package.get('is_active'))}</td>
          <td><a class="button small" href="/admin/packages?edit={e(package['id'])}">Edit</a></td>
        </tr>
        """
        for package in packages
    )
    return f"""
    <header class="title-row">
      <div>
        <h1>Whop Packages</h1>
        <p>Map Whop plans or products to Trader strategy access and day grants.</p>
      </div>
    </header>
    <section class="panel">
      <h2>{form_title}</h2>
      <form method="post">
        <input type="hidden" name="csrf" value="{e(csrf)}">
        <input type="hidden" name="package_id" value="{e(selected.get('id'))}">
        <div class="grid-form package-form">
          <label>Name <input name="name" required placeholder="DUO 30 days" value="{e(selected.get('name'))}"></label>
          <label>Whop id <input name="whop_id" required placeholder="plan_..." value="{e(selected.get('whop_id'))}"></label>
          <label>Type <select name="whop_id_type">{type_options}</select></label>
          <label>Default days <input name="default_days" type="number" min="0" placeholder="30" value="{e(selected.get('default_days'))}"></label>
          <label class="checkbox"><input name="is_active" type="checkbox" {active_checked}> Active</label>
          <label class="checkbox"><input name="is_ignored" type="checkbox" {ignored_checked}> Non-license</label>
        </div>
        <table class="grant-table">
          <thead><tr><th>Strategy</th><th>Days</th></tr></thead>
          <tbody>{grant_rows or '<tr><td colspan="2">No strategies configured.</td></tr>'}</tbody>
        </table>
        <div class="form-actions">
          <button type="submit">{button_text}</button>
          {cancel_link}
        </div>
      </form>
    </section>
    <section class="panel">
      <table>
        <thead><tr><th>Package</th><th>Type</th><th>Default days</th><th>Grants</th><th>Ignored</th><th>Active</th><th></th></tr></thead>
        <tbody>{rows or '<tr><td colspan="7">No Whop packages configured.</td></tr>'}</tbody>
      </table>
    </section>
    """


def releases_page(
    releases: list[dict[str, Any]],
    products: list[dict[str, Any]],
    csrf: str,
    selected_release: dict[str, Any] | None,
    artifact_dir: str,
) -> str:
    selected = selected_release or {}
    is_editing = selected_release is not None
    form_title = "Edit release" if is_editing else "Add release"
    editor_open = "open" if is_editing else ""
    button_text = "Save changes" if is_editing else "Save release"
    cancel_link = '<a class="button secondary" href="/admin/releases">Cancel</a>' if is_editing else ""
    selected_release_type = selected.get("release_type") or ("trader_desktop" if selected.get("scope") == "app" else "strategy_package")
    required_checked = "checked" if selected.get("is_required", 0) else ""
    active_checked = "checked" if selected.get("is_active", 1) else ""
    selected_audience_mode = selected.get("audience_mode") or "all"
    selected_rollout_percent = selected.get("rollout_percent")
    rollout_value = "100" if selected_rollout_percent is None else str(selected_rollout_percent)
    selected_platform = selected.get("platform", DEFAULT_RELEASE_PLATFORM)
    advanced_open = "open" if any(
        [
            selected.get("min_supported_version"),
            selected.get("signature"),
            selected.get("signature_key_id"),
            selected_platform != DEFAULT_RELEASE_PLATFORM,
            selected_audience_mode != "all",
            rollout_value != "100",
            format_list_field(selected.get("required_tags_json")),
            format_list_field(selected.get("allowed_customer_ids_json")),
            format_list_field(selected.get("allowed_emails_json")),
            selected.get("rollback_reason"),
        ]
    ) else ""
    product_options = ['<option value="">None</option>']
    for product in products:
        selected_attr = "selected" if selected.get("product_id") == product["id"] else ""
        product_options.append(f'<option value="{e(product["id"])}" {selected_attr}>{e(display_product_name(product.get("name")))}</option>')
    release_type_options = "\n".join(
        f'<option value="{value}" {"selected" if selected_release_type == value else ""}>{label}</option>'
        for value, label in (("strategy_package", "Strategy package"), ("trader_desktop", "Trader Desktop"))
    )
    channel_options = "\n".join(
        f'<option value="{value}" {"selected" if selected.get("channel", "stable") == value else ""}>{label}</option>'
        for value, label in (("stable", "Stable"), ("beta", "Beta"), ("canary", "Canary"), ("internal", "Internal"))
    )
    platform_values = list(SUPPORTED_RELEASE_PLATFORMS)
    if selected_platform and selected_platform not in platform_values:
        platform_values.append(selected_platform)
    platform_options = "\n".join(
        f'<option value="{e(value)}" {"selected" if selected_platform == value else ""}>{e(value)}</option>'
        for value in platform_values
    )
    audience_mode_options = "\n".join(
        f'<option value="{value}" {"selected" if selected_audience_mode == value else ""}>{label}</option>'
        for value, label in (("all", "All"), ("allowlist", "Allowlist"), ("roles", "Roles/tags"), ("percent", "Percent rollout"), ("disabled", "Disabled"))
    )

    rows = "\n".join(
        f"""
        <tr>
          <td><strong>{e(release.get('version'))}</strong><small>{e(release.get('release_notes'))}</small></td>
          <td>{e(release.get('release_type') or ('trader_desktop' if release.get('scope') == 'app' else 'strategy_package'))}<small>{e(display_product_name(release.get('product_name')) if release.get('product_name') else release.get('product_key') or 'trader-desktop')}</small></td>
          <td>{e(release.get('channel'))}</td>
          <td>{e(release.get('audience_mode') or 'all')}<small>{e(release.get('rollout_percent') if release.get('rollout_percent') is not None else 100)}%</small></td>
          <td>{format_bool(release.get('is_required'))}</td>
          <td>{format_bool(release.get('is_published') if release.get('is_published') is not None else release.get('is_active'))}</td>
          <td>{e(release.get('artifact_filename'))}<small>{e(release.get('size_bytes'))} bytes</small></td>
          <td><code>{e(short_hash(release.get('sha256')))}</code></td>
          <td>{e(format_admin_time(release.get('created_at')))}<small>{e(format_admin_time(release.get('published_at')))}</small></td>
          <td>{e(format_admin_time(release.get('updated_at')))}</td>
          <td><a class="button small" href="/admin/releases?edit={e(release['id'])}">Edit</a></td>
        </tr>
        """
        for release in releases
    )
    return f"""
    <header class="title-row">
      <div>
        <h1>Releases</h1>
        <p>Register Trader installers and strategy package artifacts. Files must live under <code>{e(artifact_dir)}</code>.</p>
      </div>
    </header>
    <section class="panel release-editor-panel">
      <details class="release-editor" {editor_open}>
      <summary>{form_title}<small>Create or edit releases only when publishing a new artifact.</small></summary>
      <form method="post">
        <input type="hidden" name="csrf" value="{e(csrf)}">
        <input type="hidden" name="release_id" value="{e(selected.get('id'))}">
        <div class="grid-form release-form">
          <label>Release type <select name="release_type">{release_type_options}</select></label>
          <label>Strategy <select name="product_id">{"".join(product_options)}</select></label>
          <label>Product id <input name="product_key" placeholder="trader-desktop" value="{e(selected.get('product_key') or ('trader-desktop' if selected_release_type == 'trader_desktop' else ''))}"></label>
          <label>Channel <select name="channel">{channel_options}</select></label>
          <label>Version <input name="version" required placeholder="1.0.0" value="{e(selected.get('version'))}"></label>
          <label class="checkbox"><input name="is_required" type="checkbox" {required_checked}> Required</label>
          <label class="checkbox"><input name="is_active" type="checkbox" {active_checked}> Published</label>
        </div>
        <div class="grid-form release-artifact-form">
          <label>Artifact path <input name="artifact_path" required placeholder="trader/AutoEdgeTrader-1.0.0.zip" value="{e(selected.get('artifact_path'))}"></label>
          <label>Download filename <input name="artifact_filename" placeholder="AutoEdgeTrader-1.0.0.zip" value="{e(selected.get('artifact_filename'))}"></label>
          <label>Size bytes <input name="size_bytes" type="number" min="0" placeholder="auto if file exists" value="{e(selected.get('size_bytes'))}"></label>
          <label>SHA-256 <input name="sha256" placeholder="auto if file exists" value="{e(selected.get('sha256'))}"></label>
        </div>
        <details class="advanced-release" {advanced_open}>
          <summary>Advanced options <small>Targeting, rollback, signatures, and compatibility gates.</small></summary>
          <div class="grid-form release-advanced-form">
            <label><span class="label-row">Platform {info_tip('Internal manifest selector. Current macOS Apple Silicon Trader builds use macos-arm64. Future Windows builds should use windows-x64.')}</span><select name="platform">{platform_options}</select></label>
            <label>Minimum supported <input name="min_supported_version" placeholder="optional" value="{e(selected.get('min_supported_version'))}"></label>
            <label>Signature <input name="signature" value="{e(selected.get('signature'))}"></label>
            <label>Signature key id <input name="signature_key_id" value="{e(selected.get('signature_key_id'))}"></label>
          </div>
          <div class="grid-form release-targeting-form">
            <label><span class="label-row">Audience {info_tip('all publishes to eligible stable customers; allowlist uses customer/email/license lists; roles uses tags; percent rolls out deterministically; disabled hides the release.')}</span><select name="audience_mode">{audience_mode_options}</select></label>
            <label><span class="label-row">Rollout percent {info_tip('0 blocks everyone, 100 allows everyone in the selected audience. Percent rollout is deterministic per customer and release.')}</span><input name="rollout_percent" type="number" min="0" max="100" value="{e(rollout_value)}"></label>
            <label><span class="label-row">Required tags {info_tip('One tag per line or comma-separated. Common values: internal, tester, desktop_beta, duo_beta, duorc_beta, early_access.')}</span><textarea name="required_tags" rows="3">{e(format_list_field(selected.get('required_tags_json')))}</textarea></label>
            <label><span class="label-row">Allowed customers {info_tip('Customer ids that may receive this release when audience is allowlist.')}</span><textarea name="allowed_customer_ids" rows="3">{e(format_list_field(selected.get('allowed_customer_ids_json')))}</textarea></label>
            <label><span class="label-row">Allowed emails {info_tip('Email addresses that may receive this release when audience is allowlist. One per line or comma-separated.')}</span><textarea name="allowed_emails" rows="3">{e(format_list_field(selected.get('allowed_emails_json')))}</textarea></label>
            <label><span class="label-row">Allowed license keys {info_tip('Paste full license keys only when needed. The server stores hashes, so existing keys cannot be shown again here.')}</span><textarea name="allowed_license_keys" rows="3"></textarea></label>
          </div>
          <label><span class="label-row">Rollback reason {info_tip('Set this when the target version is lower than the installed version and Trader should roll back.')}</span><input name="rollback_reason" value="{e(selected.get('rollback_reason'))}"></label>
        </details>
        <label>Release notes <input name="release_notes" value="{e(selected.get('release_notes'))}"></label>
        <div class="form-actions">
          <button type="submit">{button_text}</button>
          {cancel_link}
        </div>
      </form>
      </details>
    </section>
    <section class="panel">
      <table>
        <thead><tr><th>Version</th><th>Type</th><th>Channel</th><th>Audience</th><th>Required</th><th>Published</th><th>Artifact</th><th>SHA-256</th><th>Created ET</th><th>Updated ET</th><th></th></tr></thead>
        <tbody>{rows or '<tr><td colspan="11">No releases configured.</td></tr>'}</tbody>
      </table>
    </section>
    """


def customer_detail_page(detail: dict[str, Any], products: list[dict[str, Any]], csrf: str, created_key: str) -> str:
    customer = detail["customer"]
    tags = detail.get("tags") or []
    device_limit = detail.get("device_limit") or {}
    max_devices_value = "" if device_limit.get("customer_max_devices") is None else str(device_limit.get("customer_max_devices"))
    tags_value = "\n".join(str(tag) for tag in tags)
    product_options = "\n".join(f'<option value="{e(product["id"])}">{e(display_product_name(product.get("name")))}</option>' for product in products)
    key_notice = f'<p class="notice">New license key: <code>{e(created_key)}</code>. Store it now; only the last four characters are retained and the previous key no longer works.</p>' if created_key else ""
    entitlements = "\n".join(
        f"""
        <tr>
          <td>{e(display_product_name(entitlement.get('product_name')))}</td>
          <td><strong class="status {e(entitlement['status'])}">{e(entitlement['status'])}</strong><small>{e(entitlement['source'])}{' - ' + e(entitlement.get('whop_membership_id')) if entitlement.get('whop_membership_id') else ''}</small></td>
          <td>{e(format_admin_time(entitlement.get('expires_at')))}</td>
          <td>{e(entitlement.get('manual_reason'))}</td>
          <td>{e(format_admin_time(entitlement.get('updated_at')))}</td>
        </tr>
        """
        for entitlement in detail.get("effective_entitlements", detail["entitlements"])
    )
    entitlement_history = "\n".join(
        f"""
        <tr>
          <td>{e(display_product_name(entitlement.get('product_name')))}</td>
          <td>{e(entitlement.get('whop_membership_id'))}</td>
          <td><strong class="status {e(entitlement['status'])}">{e(entitlement['status'])}</strong><small>{e(entitlement['source'])}</small></td>
          <td>{e(format_admin_time(entitlement.get('expires_at')))}</td>
          <td>{e(entitlement.get('manual_reason'))}</td>
          <td>{e(format_admin_time(entitlement.get('updated_at')))}</td>
        </tr>
        """
        for entitlement in detail["entitlements"]
    )
    subscriptions = "\n".join(
        f"""
        <tr>
          <td>{e(subscription.get('whop_membership_id'))}</td>
          <td>{e(subscription.get('status'))}<small>{e(subscription.get('raw_status'))}</small></td>
          <td>{e(format_admin_time(subscription.get('current_period_end')))}</td>
          <td>{e(format_admin_time(subscription.get('updated_at')))}</td>
        </tr>
        """
        for subscription in detail["subscriptions"]
    )
    devices = "\n".join(
        f"""
        <tr>
          <td>{e(device.get('fingerprint_last8'))}<small>{e(device.get('id'))}</small></td>
          <td>{e(device.get('client_type'))}</td>
          <td>{e(device.get('app_version'))}</td>
          <td>{e(device.get('ip_last'))}</td>
          <td>{e(format_admin_time(device.get('first_seen_at')))}</td>
          <td>{e(format_admin_time(device.get('last_seen_at')))}</td>
          <td>{e(format_admin_time(device.get('first_licensed_at')))}<small>{e(format_admin_time(device.get('last_licensed_at')))}</small></td>
          <td>{format_bool(device.get('is_blocked'))}</td>
          <td>
            <form method="post" action="/admin/devices/{e(device['id'])}/{'unblock' if device.get('is_blocked') else 'block'}">
              <input type="hidden" name="csrf" value="{e(csrf)}">
              <input type="hidden" name="return_to" value="/admin/customers/{e(customer['id'])}">
              <button type="submit">{'Reauthorize' if device.get('is_blocked') else 'Deauthorize'}</button>
            </form>
          </td>
        </tr>
        """
        for device in detail["devices"]
    )
    checks = "\n".join(
        f"""
        <tr>
          <td>{e(format_admin_time(check.get('created_at')))}</td>
          <td>{e(check.get('client_type'))}</td>
          <td><strong class="status {e(check.get('status'))}">{e(check.get('status'))}</strong></td>
          <td>{e(check.get('app_version'))}</td>
          <td>{e(check.get('ip_address'))}</td>
          <td><details><summary>response</summary><pre>{e(format_json(check.get('response_json')))}</pre></details></td>
        </tr>
        """
        for check in detail["checks"]
    )
    audit_rows = "\n".join(
        f"""
        <tr>
          <td>{e(format_admin_time(audit.get('created_at')))}</td>
          <td>{e(audit.get('actor_type'))}</td>
          <td>{e(audit.get('action'))}</td>
          <td><pre>{e(format_json(audit.get('details_json')))}</pre></td>
        </tr>
        """
        for audit in detail["audit"]
    )
    return f"""
    <header class="title-row">
      <div>
        <h1>{e(customer.get('email') or customer['id'])}</h1>
        <p>{e(customer.get('name'))}</p>
      </div>
      <a class="button" href="/admin/customers">Back</a>
    </header>
    {key_notice}
    <section class="facts">
      <div><span>Customer ID</span><code>{e(customer['id'])}</code></div>
      <div><span>Whop user</span><code>{e(customer.get('whop_user_id'))}</code></div>
      <div><span>Whop member</span><code>{e(customer.get('whop_member_id'))}</code></div>
      <div class="license-key-fact">
        <span>License key</span>
        <code>•••• {e(customer.get('license_key_last4'))}</code>
        <form method="post" action="/admin/customers/{e(customer['id'])}/license-key">
          <input type="hidden" name="csrf" value="{e(csrf)}">
          <button class="button secondary small" type="submit" onclick="return confirm('Reissue this license key? The previous key will stop working.')">Reissue key</button>
        </form>
        <small>Shows the new key once.</small>
      </div>
      <div><span>Tags</span><code>{e(', '.join(tags) or 'none')}</code></div>
      <div><span>Devices</span><code>{e(device_limit.get('active_devices', 0))} / {e(device_limit.get('max_devices', 1))}</code></div>
    </section>
    <section class="panel">
      <h2>Release targeting tags</h2>
      <form class="grid-form customer-tags-form" method="post" action="/admin/customers/{e(customer['id'])}/tags">
        <input type="hidden" name="csrf" value="{e(csrf)}">
        <label><span class="label-row">Tags {info_tip('One tag per line or comma-separated. Common values: internal, tester, desktop_beta, duo_beta, duorc_beta, early_access.')}</span><textarea name="tags" rows="3">{e(tags_value)}</textarea></label>
        <button type="submit">Save tags</button>
      </form>
    </section>
    <section class="panel">
      <h2>Device limit</h2>
      <form class="grid-form device-limit-form" method="post" action="/admin/customers/{e(customer['id'])}/device-limit">
        <input type="hidden" name="csrf" value="{e(csrf)}">
        <label>Max devices <input name="max_devices" type="number" min="1" placeholder="{e(device_limit.get('default_max_devices', 1))}" value="{e(max_devices_value)}"></label>
        <button type="submit">Save limit</button>
      </form>
      <form class="form-actions" method="post" action="/admin/customers/{e(customer['id'])}/devices">
        <input type="hidden" name="csrf" value="{e(csrf)}">
        <input type="hidden" name="action" value="block_all">
        <input type="hidden" name="note" value="Device reset">
        <button class="button secondary" type="submit">Reset devices</button>
      </form>
    </section>
    <section class="panel">
      <h2>Manual strategy access</h2>
      <form class="grid-form" method="post" action="/admin/customers/{e(customer['id'])}/entitlements">
        <input type="hidden" name="csrf" value="{e(csrf)}">
        <label>Strategy <select name="product_id" required>{product_options}</select></label>
        <label>Status
          <select name="status">
            <option value="active">active</option>
            <option value="trialing">trialing</option>
            <option value="expired">expired</option>
            <option value="revoked">revoked</option>
            <option value="suspended">suspended</option>
          </select>
        </label>
        <label><span class="label-row">Expiry ET {info_tip('Select the expiry date and time in US Eastern trading time. Leave empty for no expiry.')}</span><input name="expires_at" type="datetime-local" step="1"></label>
        <label>Reason <input name="reason"></label>
        <button type="submit">Apply</button>
      </form>
    </section>
    <section class="panel">
      <h2>Entitlements</h2>
      <table><thead><tr><th>Strategy</th><th>Status</th><th>Expiry ET</th><th>Reason</th><th>Updated ET</th></tr></thead><tbody>{entitlements or '<tr><td colspan="5">No entitlements.</td></tr>'}</tbody></table>
      <details class="history-details">
        <summary>Entitlement history <small>Raw Whop/manual rows, including previous memberships.</small></summary>
        <table><thead><tr><th>Strategy</th><th>Whop membership</th><th>Status</th><th>Expiry ET</th><th>Reason</th><th>Updated ET</th></tr></thead><tbody>{entitlement_history or '<tr><td colspan="6">No entitlement history.</td></tr>'}</tbody></table>
      </details>
    </section>
    <section class="panel">
      <h2>Subscriptions</h2>
      <table><thead><tr><th>Whop membership</th><th>Status</th><th>Period end ET</th><th>Updated ET</th></tr></thead><tbody>{subscriptions or '<tr><td colspan="4">No subscriptions.</td></tr>'}</tbody></table>
    </section>
    <section class="panel">
      <h2>Devices</h2>
      <table><thead><tr><th>Fingerprint</th><th>Client</th><th>App</th><th>IP</th><th>First seen ET</th><th>Last seen ET</th><th>Licensed ET</th><th>Blocked</th><th></th></tr></thead><tbody>{devices or '<tr><td colspan="9">No devices.</td></tr>'}</tbody></table>
    </section>
    <section class="panel">
      <h2>License check-ins</h2>
      <table><thead><tr><th>Time ET</th><th>Client</th><th>Status</th><th>App</th><th>IP</th><th>Response</th></tr></thead><tbody>{checks or '<tr><td colspan="6">No check-ins.</td></tr>'}</tbody></table>
    </section>
    <section class="panel">
      <h2>Audit log</h2>
      <table><thead><tr><th>Time ET</th><th>Actor</th><th>Action</th><th>Details</th></tr></thead><tbody>{audit_rows or '<tr><td colspan="4">No audit events.</td></tr>'}</tbody></table>
    </section>
    """


STYLE = """
:root { color-scheme: light; --bg: #f6f7f8; --panel: #ffffff; --text: #202428; --muted: #64707d; --line: #d8dee4; --accent: #136f63; --danger: #b42318; --warn: #a15c00; }
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--text); font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; font-size: 14px; }
nav { height: 52px; display: flex; align-items: center; gap: 18px; padding: 0 24px; background: #17202a; color: #fff; }
nav a { color: #fff; text-decoration: none; font-weight: 600; }
nav .spacer { flex: 1; }
.admin-clock { color: #d7e3ea; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 13px; font-variant-numeric: tabular-nums; white-space: nowrap; }
.admin-user { color: #fff; font-weight: 650; white-space: nowrap; }
main { width: min(1180px, calc(100vw - 32px)); margin: 24px auto 48px; }
h1 { margin: 0; font-size: 26px; }
h2 { margin: 0 0 16px; font-size: 18px; }
p { margin: 6px 0 0; color: var(--muted); }
a { color: #0f5d53; }
button, .button { min-height: 36px; padding: 0 14px; border: 1px solid #0f5d53; border-radius: 6px; background: #136f63; color: #fff; font-weight: 650; text-decoration: none; cursor: pointer; display: inline-flex; align-items: center; justify-content: center; }
button:hover, .button:hover { background: #0f5d53; }
.button.secondary { background: #fff; color: #0f5d53; }
.button.secondary:hover { background: #eef9f6; }
.button.small { min-height: 30px; padding: 0 10px; font-size: 13px; }
input, select, textarea { min-height: 36px; width: 100%; padding: 7px 9px; border: 1px solid var(--line); border-radius: 6px; background: #fff; color: var(--text); }
textarea { resize: vertical; font: inherit; }
input::placeholder, textarea::placeholder { color: #9aa6b2; font-weight: 400; font-style: italic; opacity: 1; }
label { display: grid; gap: 6px; color: #34404c; font-weight: 600; }
.label-row { display: inline-flex; align-items: center; gap: 6px; }
.info-tip { display: inline-flex; align-items: center; justify-content: center; width: 16px; height: 16px; border: 1px solid #9aa6b2; border-radius: 50%; color: #64707d; font-size: 11px; font-weight: 700; line-height: 1; cursor: help; }
small { display: block; margin-top: 3px; color: var(--muted); font-weight: 400; }
.muted { color: var(--muted); }
table { width: 100%; border-collapse: collapse; }
th, td { padding: 10px 12px; border-bottom: 1px solid var(--line); text-align: left; vertical-align: top; }
th { color: #394652; font-size: 12px; text-transform: uppercase; letter-spacing: .04em; }
pre { margin: 0; max-width: 620px; overflow: auto; white-space: pre-wrap; font-size: 12px; }
code { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
.auth { width: min(420px, calc(100vw - 32px)); margin: 80px auto; padding: 26px; background: var(--panel); border: 1px solid var(--line); border-radius: 8px; }
.auth form { display: grid; gap: 14px; margin-top: 22px; }
.error { padding: 10px 12px; background: #fff0ef; color: var(--danger); border: 1px solid #ffd2cf; border-radius: 6px; }
.notice { padding: 12px 14px; background: #eef9f6; color: #0b4e45; border: 1px solid #b8ded6; border-radius: 6px; }
.title-row { display: flex; align-items: start; justify-content: space-between; gap: 16px; margin-bottom: 18px; }
.search { display: flex; gap: 8px; margin-bottom: 16px; }
.search input { max-width: 520px; }
.panel { background: var(--panel); border: 1px solid var(--line); border-radius: 8px; padding: 16px; margin-bottom: 16px; }
.narrow-panel { max-width: 520px; }
.stack-form { display: grid; gap: 14px; }
.grid-form { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)) auto; gap: 12px; align-items: end; }
.package-form { grid-template-columns: repeat(4, minmax(0, 1fr)) repeat(2, auto); margin-bottom: 14px; }
.release-editor-panel { padding: 0; }
.release-editor { padding: 16px; }
.release-editor summary { cursor: pointer; color: #202428; font-size: 18px; font-weight: 700; }
.release-editor summary small { display: inline; margin: 0 0 0 10px; color: var(--muted); font-size: 13px; font-weight: 400; }
.release-editor form { margin-top: 16px; }
.release-form { grid-template-columns: repeat(5, minmax(0, 1fr)) repeat(2, auto); margin-bottom: 12px; }
.release-artifact-form { grid-template-columns: 2fr 1fr 1fr 2fr; margin-bottom: 12px; }
.release-advanced-form { grid-template-columns: repeat(4, minmax(0, 1fr)); margin: 12px 0; }
.release-targeting-form { grid-template-columns: repeat(6, minmax(0, 1fr)); margin-bottom: 12px; }
.advanced-release { border: 1px solid var(--line); border-radius: 6px; padding: 10px 12px 12px; margin-bottom: 12px; background: #fbfcfd; }
.advanced-release summary { cursor: pointer; color: #34404c; font-weight: 700; }
.advanced-release summary small { display: inline; margin: 0 0 0 8px; font-weight: 400; }
.history-details { margin-top: 14px; }
.history-details summary { cursor: pointer; color: #34404c; font-weight: 700; }
.history-details summary small { display: inline; margin: 0 0 0 8px; color: var(--muted); font-weight: 400; }
.history-details table { margin-top: 10px; }
.device-limit-form { grid-template-columns: minmax(180px, 260px) auto; margin-bottom: 12px; }
.customer-tags-form { grid-template-columns: minmax(260px, 420px) auto; }
.checkbox { min-height: 36px; display: flex; align-items: center; gap: 8px; }
.checkbox input { width: auto; min-height: auto; }
.grant-table { margin: 8px 0 14px; }
.grant-table td:nth-child(2) { width: 180px; }
.grant-list { display: grid; gap: 6px; }
.grant-list span { display: block; }
.form-actions { display: flex; gap: 10px; align-items: center; }
.facts { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; margin-bottom: 16px; }
.facts div { background: var(--panel); border: 1px solid var(--line); border-radius: 8px; padding: 12px; min-width: 0; }
.facts span { display: block; color: var(--muted); margin-bottom: 6px; }
.facts code { overflow-wrap: anywhere; }
.license-key-fact form { margin-top: 10px; }
.status { color: var(--muted); }
.status.active, .status.trialing { color: var(--accent); }
.status.revoked, .status.device_blocked, .status.device_limit_exceeded { color: var(--danger); }
.status.expired, .status.suspended, .status.unlicensed { color: var(--warn); }
@media (max-width: 760px) {
  nav { padding: 0 12px; gap: 10px; overflow-x: auto; }
  main { width: calc(100vw - 18px); margin-top: 12px; }
  .title-row, .search { display: grid; }
  .grid-form, .package-form, .release-form, .release-artifact-form, .release-advanced-form, .release-targeting-form, .device-limit-form, .customer-tags-form, .facts { grid-template-columns: 1fr; }
  table { display: block; overflow-x: auto; }
}
"""


ADMIN_CLOCK_SCRIPT = """
<script>
(function () {
  const clock = document.querySelector("[data-admin-clock]");
  if (!clock) {
    return;
  }
  const formatter = new Intl.DateTimeFormat("sv-SE", {
    timeZone: "America/New_York",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false
  });
  function clockPartMap() {
    return formatter.formatToParts(new Date()).reduce(function (parts, part) {
      parts[part.type] = part.value;
      return parts;
    }, {});
  }
  function tick() {
    const parts = clockPartMap();
    clock.textContent = parts.year + "-" + parts.month + "-" + parts.day + " " +
      parts.hour + ":" + parts.minute + ":" + parts.second + " ET";
  }
  tick();
  window.setInterval(tick, 1000);
}());
</script>
"""


def create_app(settings: Settings | None = None) -> AutoEdgeApp:
    return AutoEdgeApp(settings or Settings.from_env())


def main() -> int:
    settings = Settings.from_env()
    if os.environ.get("AUTOEDGE_SKIP_RUNTIME_VALIDATION") != "1":
        settings.validate_runtime()
    app = create_app(settings)
    with make_server(settings.bind_host, settings.bind_port, app, handler_class=RedactingWSGIRequestHandler) as server:
        print(f"AutoEdge licensing server listening on http://{settings.bind_host}:{settings.bind_port}", flush=True)
        server.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
