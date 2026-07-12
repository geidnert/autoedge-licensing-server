from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature


ES256_ALGORITHM = "ES256"
LICENSE_TOKEN_TYPE = "autoedge-license+jws"
LICENSE_PAYLOAD_KIND = "autoedge.trader-license"
RELEASE_TOKEN_TYPE = "autoedge-release+jws"
RELEASE_PAYLOAD_KIND = "autoedge.release"
RELEASE_TYPES = {"strategy_package", "extension_package", "trader_desktop"}

_BASE64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class SigningError(ValueError):
    """A safe, non-secret-bearing compact-token validation error."""


def canonical_json(value: Mapping[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def base64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def base64url_decode(value: str) -> bytes:
    if not isinstance(value, str) or not value or "=" in value or _BASE64URL_RE.fullmatch(value) is None:
        raise SigningError("Malformed base64url segment.")
    try:
        decoded = base64.b64decode(
            (value + "=" * (-len(value) % 4)).encode("ascii"),
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, TypeError) as exc:
        raise SigningError("Malformed base64url segment.") from exc
    if not hmac.compare_digest(base64url_encode(decoded), value):
        raise SigningError("Non-canonical base64url segment.")
    return decoded


def _json_object(segment: str, label: str) -> dict[str, Any]:
    try:
        parsed = json.loads(base64url_decode(segment).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SigningError(f"Malformed {label} JSON.") from exc
    if not isinstance(parsed, dict):
        raise SigningError(f"Malformed {label} JSON.")
    return parsed


def _require_p256_private_key(value: Any) -> ec.EllipticCurvePrivateKey:
    if not isinstance(value, ec.EllipticCurvePrivateKey) or not isinstance(value.curve, ec.SECP256R1):
        raise SigningError("Private key must be an ECDSA P-256 key.")
    return value


def _require_p256_public_key(value: Any) -> ec.EllipticCurvePublicKey:
    if not isinstance(value, ec.EllipticCurvePublicKey) or not isinstance(value.curve, ec.SECP256R1):
        raise SigningError("Public key must be an ECDSA P-256 key.")
    return value


def load_private_key(path: str | Path) -> ec.EllipticCurvePrivateKey:
    try:
        pem = Path(path).read_bytes()
        key = serialization.load_pem_private_key(pem, password=None)
    except (OSError, ValueError, TypeError) as exc:
        raise SigningError("Could not load the configured ES256 private key.") from exc
    return _require_p256_private_key(key)


def load_public_key(path: str | Path) -> ec.EllipticCurvePublicKey:
    try:
        pem = Path(path).read_bytes()
        key = serialization.load_pem_public_key(pem)
    except (OSError, ValueError, TypeError) as exc:
        raise SigningError("Could not load a configured ES256 public key.") from exc
    return _require_p256_public_key(key)


def public_key_pem(public_key: ec.EllipticCurvePublicKey) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def public_key_fingerprint(public_key: ec.EllipticCurvePublicKey) -> str:
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()


@dataclass(frozen=True)
class VerifiedToken:
    header: dict[str, Any]
    payload: dict[str, Any]


class CompactES256Signer:
    def __init__(self, private_key: ec.EllipticCurvePrivateKey, key_id: str):
        normalized_key_id = key_id.strip()
        if not normalized_key_id:
            raise SigningError("ES256 key ID is required.")
        self.private_key = _require_p256_private_key(private_key)
        self.key_id = normalized_key_id

    @classmethod
    def from_pem_path(cls, private_key_path: str | Path, key_id: str) -> "CompactES256Signer":
        return cls(load_private_key(private_key_path), key_id)

    def sign(self, payload: Mapping[str, Any], *, token_type: str) -> str:
        header = {"alg": ES256_ALGORITHM, "kid": self.key_id, "typ": token_type}
        header_segment = base64url_encode(canonical_json(header))
        payload_segment = base64url_encode(canonical_json(payload))
        signing_input = f"{header_segment}.{payload_segment}".encode("ascii")
        der_signature = self.private_key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
        r_value, s_value = decode_dss_signature(der_signature)
        raw_signature = r_value.to_bytes(32, "big") + s_value.to_bytes(32, "big")
        return f"{header_segment}.{payload_segment}.{base64url_encode(raw_signature)}"

    def public_key(self) -> ec.EllipticCurvePublicKey:
        return self.private_key.public_key()


def load_public_key_mapping(paths_by_key_id: Mapping[str, str]) -> dict[str, ec.EllipticCurvePublicKey]:
    keys: dict[str, ec.EllipticCurvePublicKey] = {}
    for key_id, path in paths_by_key_id.items():
        normalized_key_id = str(key_id).strip()
        normalized_path = str(path).strip()
        if not normalized_key_id or not normalized_path:
            raise SigningError("ES256 public-key mappings require non-empty key IDs and paths.")
        keys[normalized_key_id] = load_public_key(normalized_path)
    return keys


def verify_compact_token(
    token: str,
    public_keys: Mapping[str, ec.EllipticCurvePublicKey],
    *,
    expected_type: str,
    expected_kind: str,
    now_seconds: int | None = None,
    validate_lease_times: bool = False,
    expected_issuer: str | None = None,
    expected_audience: str | None = None,
) -> VerifiedToken:
    if not isinstance(token, str):
        raise SigningError("Malformed compact token.")
    segments = token.split(".")
    if len(segments) != 3:
        raise SigningError("Malformed compact token.")
    header_segment, payload_segment, signature_segment = segments
    header = _json_object(header_segment, "header")
    payload = _json_object(payload_segment, "payload")

    if header.get("alg") != ES256_ALGORITHM:
        raise SigningError("Unsupported compact-token algorithm.")
    if header.get("typ") != expected_type:
        raise SigningError("Wrong compact-token type.")
    key_id = header.get("kid")
    if not isinstance(key_id, str) or not key_id:
        raise SigningError("Compact token is missing a key ID.")
    public_key = public_keys.get(key_id)
    if public_key is None:
        raise SigningError("Unknown compact-token key ID.")

    raw_signature = base64url_decode(signature_segment)
    if len(raw_signature) != 64:
        raise SigningError("ES256 compact signature must be exactly 64 bytes.")
    r_value = int.from_bytes(raw_signature[:32], "big")
    s_value = int.from_bytes(raw_signature[32:], "big")
    der_signature = encode_dss_signature(r_value, s_value)
    signing_input = f"{header_segment}.{payload_segment}".encode("ascii")
    try:
        _require_p256_public_key(public_key).verify(der_signature, signing_input, ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError) as exc:
        raise SigningError("Invalid ES256 compact-token signature.") from exc

    if payload.get("kind") != expected_kind:
        raise SigningError("Wrong compact-token payload kind.")
    if payload.get("v") != 1:
        raise SigningError("Unsupported compact-token payload version.")
    if expected_issuer is not None and payload.get("iss") != expected_issuer:
        raise SigningError("Wrong compact-token issuer.")
    if expected_audience is not None and payload.get("aud") != expected_audience:
        raise SigningError("Wrong compact-token audience.")
    if validate_lease_times:
        import time

        now = int(time.time()) if now_seconds is None else int(now_seconds)
        for name in ("iat", "nbf", "exp"):
            value = payload.get(name)
            if isinstance(value, bool) or not isinstance(value, int):
                raise SigningError(f"Lease claim {name} must be an integer.")
        if payload["nbf"] > now:
            raise SigningError("License lease is not yet valid.")
        if payload["exp"] <= now:
            raise SigningError("License lease has expired.")
        if payload["iat"] > now or payload["nbf"] < payload["iat"] or payload["exp"] <= payload["nbf"]:
            raise SigningError("License lease time claims are inconsistent.")
    return VerifiedToken(header=header, payload=payload)


def release_envelope_payload(
    *,
    release_type: str,
    package_id: str,
    feature_id: str | None,
    channel: str,
    platform: str,
    version: str,
    minimum_trader_version: str | None,
    filename: str,
    size_bytes: int,
    sha256: str,
) -> dict[str, Any]:
    if release_type not in RELEASE_TYPES:
        raise SigningError("Unsupported release type.")
    required_text = {
        "package_id": package_id,
        "channel": channel,
        "platform": platform,
        "version": version,
        "filename": filename,
    }
    if any(not isinstance(value, str) or not value for value in required_text.values()):
        raise SigningError("Release envelope contains a missing or invalid text field.")
    if feature_id is not None and (not isinstance(feature_id, str) or not feature_id):
        raise SigningError("Release feature ID must be a non-empty string or null.")
    if minimum_trader_version is not None and (
        not isinstance(minimum_trader_version, str) or not minimum_trader_version
    ):
        raise SigningError("Minimum TraderPro version must be a non-empty string or null.")
    if not isinstance(sha256, str):
        raise SigningError("Release SHA-256 must be 64 lowercase hexadecimal characters.")
    normalized_sha256 = sha256.strip().lower()
    if _SHA256_RE.fullmatch(normalized_sha256) is None:
        raise SigningError("Release SHA-256 must be 64 lowercase hexadecimal characters.")
    if isinstance(size_bytes, bool) or not isinstance(size_bytes, int) or size_bytes < 0:
        raise SigningError("Release size must be a non-negative integer.")
    return {
        "v": 1,
        "kind": RELEASE_PAYLOAD_KIND,
        "release_type": release_type,
        "package_id": package_id,
        "feature_id": feature_id,
        "channel": channel,
        "platform": platform,
        "version": version,
        "minimum_trader_version": minimum_trader_version,
        "filename": filename,
        "size_bytes": size_bytes,
        "sha256": normalized_sha256,
    }


def verify_release_envelope(
    token: str,
    public_keys: Mapping[str, ec.EllipticCurvePublicKey],
    expected_payload: Mapping[str, Any] | None = None,
) -> VerifiedToken:
    verified = verify_compact_token(
        token,
        public_keys,
        expected_type=RELEASE_TOKEN_TYPE,
        expected_kind=RELEASE_PAYLOAD_KIND,
    )
    if expected_payload is not None:
        expected = dict(expected_payload)
        if set(verified.payload) != set(expected):
            raise SigningError("Signed release claims do not match release metadata.")
        for name, expected_value in expected.items():
            actual_value = verified.payload.get(name)
            if isinstance(actual_value, str) and isinstance(expected_value, str):
                if not hmac.compare_digest(actual_value, expected_value):
                    raise SigningError(f"Signed release claim does not match: {name}.")
            elif actual_value != expected_value:
                raise SigningError(f"Signed release claim does not match: {name}.")
    return verified
