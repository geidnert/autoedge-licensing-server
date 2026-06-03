from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import string
import time
from http.cookies import SimpleCookie
from typing import Mapping


def random_token(bytes_count: int = 32) -> str:
    return secrets.token_urlsafe(bytes_count)


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def hash_license_key(value: str) -> str:
    return sha256_hex(value.strip().upper())


def hash_fingerprint(value: str) -> str:
    return sha256_hex(value.strip())


def generate_license_key() -> str:
    alphabet = string.ascii_uppercase + string.digits
    raw = "".join(secrets.choice(alphabet) for _ in range(20))
    chunks = [raw[i : i + 4] for i in range(0, len(raw), 4)]
    return "AE-" + "-".join(chunks)


def hash_password(password: str, iterations: int = 210_000) -> str:
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"pbkdf2_sha256${iterations}${base64.b64encode(salt).decode()}${base64.b64encode(digest).decode()}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, iterations_text, salt_text, digest_text = encoded.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        iterations = int(iterations_text)
        salt = base64.b64decode(salt_text.encode())
        expected = base64.b64decode(digest_text.encode())
    except (ValueError, TypeError):
        return False
    actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return hmac.compare_digest(actual, expected)


def sign_value(secret: str, value: str) -> str:
    digest = hmac.new(secret.encode("utf-8"), value.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{value}.{digest}"


def unsign_value(secret: str, signed_value: str) -> str | None:
    if "." not in signed_value:
        return None
    value, digest = signed_value.rsplit(".", 1)
    expected = hmac.new(secret.encode("utf-8"), value.encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, digest):
        return None
    return value


def parse_cookie(header_value: str | None) -> dict[str, str]:
    if not header_value:
        return {}
    cookie = SimpleCookie()
    cookie.load(header_value)
    return {key: morsel.value for key, morsel in cookie.items()}


def _candidate_webhook_keys(secret: str) -> list[bytes]:
    candidates = [secret.encode("utf-8")]
    encoded = secret
    if secret.startswith("whsec_"):
        encoded = secret[len("whsec_") :]
    padded = encoded + "=" * (-len(encoded) % 4)
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            decoded = decoder(padded.encode("utf-8"))
        except Exception:
            continue
        if decoded and decoded not in candidates:
            candidates.append(decoded)
    return candidates


def verify_standard_webhook(
    raw_body: bytes,
    headers: Mapping[str, str],
    secret: str,
    *,
    tolerance_seconds: int = 300,
    now_seconds: int | None = None,
) -> tuple[bool, str]:
    normalized = {key.lower(): value for key, value in headers.items()}
    webhook_id = normalized.get("webhook-id")
    timestamp_text = normalized.get("webhook-timestamp")
    signature_header = normalized.get("webhook-signature")
    if not webhook_id or not timestamp_text or not signature_header:
        return False, "missing standard webhook signature headers"

    try:
        timestamp = int(timestamp_text)
    except ValueError:
        return False, "invalid webhook timestamp"

    now = int(time.time()) if now_seconds is None else now_seconds
    if abs(now - timestamp) > tolerance_seconds:
        return False, "webhook timestamp outside tolerance"

    signed_payload = webhook_id.encode("utf-8") + b"." + timestamp_text.encode("utf-8") + b"." + raw_body
    signatures = [part for part in signature_header.split(" ") if part.strip()]
    for candidate_key in _candidate_webhook_keys(secret):
        expected = hmac.new(candidate_key, signed_payload, hashlib.sha256).digest()
        for signature in signatures:
            if "," not in signature:
                continue
            version, encoded_signature = signature.split(",", 1)
            if version != "v1":
                continue
            try:
                actual = base64.b64decode(encoded_signature.encode("utf-8"), validate=True)
            except Exception:
                continue
            if hmac.compare_digest(expected, actual):
                return True, "ok"
    return False, "signature mismatch"


def verify_bearer(headers: Mapping[str, str], expected_token: str | None) -> bool:
    if not expected_token:
        return False
    normalized = {key.lower(): value for key, value in headers.items()}
    authorization = normalized.get("authorization", "")
    prefix = "Bearer "
    if not authorization.startswith(prefix):
        return False
    supplied = authorization[len(prefix) :].strip()
    return hmac.compare_digest(supplied, expected_token)
