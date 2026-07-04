from __future__ import annotations

import json
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse
from urllib.request import Request, urlopen


class TradovateOAuthError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def normalize_tradovate_environment(value: str | None) -> str:
    cleaned = (value or "live").strip().lower()
    if cleaned not in {"live", "demo"}:
        raise ValueError("environment must be live or demo.")
    return cleaned


def build_authorization_url(
    *,
    authorize_url: str,
    client_id: str,
    redirect_uri: str,
    state: str,
    scopes: str | None = None,
) -> str:
    parsed = urlparse(authorize_url)
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    query.update(
        {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "state": state,
        }
    )
    if scopes and scopes.strip():
        query["scope"] = scopes.strip()
    return urlunparse(parsed._replace(query=urlencode(query)))


class TradovateOAuthClient:
    def __init__(self, *, timeout_seconds: int = 15):
        self.timeout_seconds = timeout_seconds

    def exchange_code(
        self,
        *,
        token_url: str,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        code: str,
    ) -> dict[str, Any]:
        payload = {
            "grant_type": "authorization_code",
            "client_id": client_id,
            "client_secret": client_secret,
            "redirect_uri": redirect_uri,
            "code": code,
        }
        response = self._request_json(
            Request(
                token_url,
                data=urlencode(payload).encode("utf-8"),
                headers={
                    "Accept": "application/json",
                    "Content-Type": "application/x-www-form-urlencoded",
                },
                method="POST",
            )
        )
        if response.get("error"):
            raise TradovateOAuthError("token_exchange_failed", safe_tradovate_message(response))
        if not response.get("access_token"):
            raise TradovateOAuthError("token_exchange_failed", "Tradovate did not return an access token.")
        return response

    def me(self, *, api_base_url: str, access_token: str) -> dict[str, Any] | None:
        try:
            response = self._request_json(
                Request(
                    api_url(api_base_url, "/auth/me"),
                    headers={
                        "Accept": "application/json",
                        "Authorization": f"Bearer {access_token}",
                    },
                    method="GET",
                )
            )
        except TradovateOAuthError:
            return None
        if response.get("errorText"):
            return None
        return response

    def renew_access_token(self, *, api_base_url: str, access_token: str) -> dict[str, Any]:
        response = self._request_json(
            Request(
                api_url(api_base_url, "/auth/renewAccessToken"),
                headers={
                    "Accept": "application/json",
                    "Authorization": f"Bearer {access_token}",
                },
                method="GET",
            )
        )
        if response.get("errorText") or response.get("error"):
            raise TradovateOAuthError("token_renewal_failed", safe_tradovate_message(response))
        if not (response.get("accessToken") or response.get("access_token")):
            raise TradovateOAuthError("token_renewal_failed", "Tradovate did not return a renewed access token.")
        return response

    def _request_json(self, request: Request) -> dict[str, Any]:
        try:
            with urlopen(request, timeout=self.timeout_seconds) as response:
                body = response.read()
        except HTTPError as exc:
            body = exc.read()
            parsed = parse_json_body(body)
            raise TradovateOAuthError("tradovate_http_error", safe_tradovate_message(parsed)) from exc
        except URLError as exc:
            raise TradovateOAuthError("tradovate_unreachable", "Could not reach Tradovate OAuth service.") from exc
        parsed = parse_json_body(body)
        if not isinstance(parsed, dict):
            raise TradovateOAuthError("tradovate_bad_response", "Tradovate returned an invalid response.")
        return parsed


def api_url(base_url: str, path: str) -> str:
    return base_url.rstrip("/") + "/" + path.lstrip("/")


def parse_json_body(body: bytes) -> Any:
    try:
        return json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {}


def safe_tradovate_message(response: dict[str, Any]) -> str:
    for key in ("error_description", "errorText", "message", "error"):
        value = response.get(key)
        if value:
            text = str(value).strip()
            if text:
                return text[:300]
    return "Tradovate OAuth request failed."

