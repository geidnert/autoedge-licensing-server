from __future__ import annotations

import json
import re
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any

from .db import Database
from .security import (
    generate_license_key,
    hash_fingerprint,
    hash_license_key,
    hash_password,
    random_token,
    sha256_hex,
    verify_password,
)


ACTIVE_ENTITLEMENT_STATUSES = {"active", "trialing"}
BLOCKING_ENTITLEMENT_STATUSES = {"expired", "revoked", "suspended"}


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime | None = None) -> str:
    value = dt or utc_now()
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def parse_time(value: Any) -> datetime | None:
    if value in (None, ""):
        return None
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value), tz=timezone.utc)
    if not isinstance(value, str):
        return None
    cleaned = value.strip()
    if not cleaned:
        return None
    if cleaned.isdigit():
        return datetime.fromtimestamp(float(cleaned), tz=timezone.utc)
    if cleaned.endswith("Z"):
        cleaned = cleaned[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(cleaned)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def normalize_email(value: str | None) -> str | None:
    if not value:
        return None
    cleaned = value.strip().lower()
    return cleaned or None


def slugify(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return slug or "product"


def row_to_dict(row: sqlite3.Row | None) -> dict[str, Any] | None:
    return dict(row) if row is not None else None


STRATEGY_RELEASE_TYPE = "strategy_package"
TRADER_DESKTOP_RELEASE_TYPE = "trader_desktop"
TRADER_DESKTOP_PRODUCT_ID = "trader-desktop"
RELEASE_TYPES = {STRATEGY_RELEASE_TYPE, TRADER_DESKTOP_RELEASE_TYPE}
DEFAULT_RELEASE_PLATFORM = "macos-arm64"
SUPPORTED_RELEASE_PLATFORMS = ("macos-arm64", "windows-x64")
CHANNEL_PRIORITY = {"stable": 0, "beta": 1, "canary": 2, "internal": 3}
AUDIENCE_MODES = {"all", "allowlist", "roles", "percent", "disabled"}


def display_strategy_name(value: str | None) -> str:
    if not value:
        return ""
    if value.endswith(" Runtime"):
        return value[: -len(" Runtime")]
    return value


def file_sha256(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def release_type_from_scope(scope: str | None) -> str:
    return TRADER_DESKTOP_RELEASE_TYPE if scope == "app" else STRATEGY_RELEASE_TYPE


def scope_from_release_type(release_type: str) -> str:
    return "app" if release_type == TRADER_DESKTOP_RELEASE_TYPE else "strategy"


def parse_version_parts(value: str | None) -> list[int]:
    if not value:
        return []
    parts: list[int] = []
    for token in value.strip().replace("-", ".").split("."):
        digits = "".join(char for char in token if char.isdigit())
        if digits == "":
            parts.append(0)
        else:
            parts.append(int(digits))
    return parts


def version_is_newer(available: str | None, current: str | None) -> bool:
    if not available:
        return False
    if not current or not current.strip():
        return True
    left = parse_version_parts(available)
    right = parse_version_parts(current)
    length = max(len(left), len(right))
    left.extend([0] * (length - len(left)))
    right.extend([0] * (length - len(right)))
    return left > right


def compare_versions(left_value: str | None, right_value: str | None) -> int:
    if not left_value and not right_value:
        return 0
    if left_value and not right_value:
        return 1
    if right_value and not left_value:
        return -1
    left = parse_version_parts(left_value)
    right = parse_version_parts(right_value)
    length = max(len(left), len(right))
    left.extend([0] * (length - len(left)))
    right.extend([0] * (length - len(right)))
    if left == right:
        return 0
    return 1 if left > right else -1


def release_action(target_version: str | None, current_version: str | None) -> str:
    comparison = compare_versions(target_version, current_version)
    if comparison > 0:
        return "update"
    if comparison < 0:
        return "rollback"
    return "current"


def release_action_for_row(release: dict[str, Any], current_version: str | None) -> str:
    action = release_action(release.get("version"), current_version)
    if action == "rollback" and not release.get("rollback_reason") and not release.get("is_required"):
        return "current"
    return action


def normalize_release_types(values: list[str] | None) -> set[str]:
    if not values:
        return {STRATEGY_RELEASE_TYPE, TRADER_DESKTOP_RELEASE_TYPE}
    normalized = {str(value).strip() for value in values if str(value).strip() in RELEASE_TYPES}
    return normalized or {STRATEGY_RELEASE_TYPE, TRADER_DESKTOP_RELEASE_TYPE}


def normalize_tag(value: str | None) -> str:
    if not value:
        return ""
    normalized = re.sub(r"[^a-z0-9_.:-]+", "_", value.strip().lower()).strip("_")
    return normalized


def normalize_tag_list(values: list[str] | str | None) -> list[str]:
    if values is None:
        return []
    if isinstance(values, str):
        raw_values = re.split(r"[\s,;]+", values)
    else:
        raw_values = [str(value) for value in values]
    normalized: list[str] = []
    seen: set[str] = set()
    for raw in raw_values:
        tag = normalize_tag(raw)
        if tag and tag not in seen:
            normalized.append(tag)
            seen.add(tag)
    return normalized


def normalize_identifier_list(values: list[str] | str | None, *, lower: bool = False) -> list[str]:
    if values is None:
        return []
    if isinstance(values, str):
        raw_values = re.split(r"[\s,;]+", values)
    else:
        raw_values = [str(value) for value in values]
    normalized: list[str] = []
    seen: set[str] = set()
    for raw in raw_values:
        value = raw.strip()
        if lower:
            value = value.lower()
        if value and value not in seen:
            normalized.append(value)
            seen.add(value)
    return normalized


def json_list(value: Any) -> list[str]:
    if value in (None, ""):
        return []
    if isinstance(value, list):
        return [str(item) for item in value if str(item).strip()]
    if not isinstance(value, str):
        return []
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return normalize_identifier_list(value)
    if not isinstance(parsed, list):
        return []
    return [str(item) for item in parsed if str(item).strip()]


def json_list_text(values: list[str]) -> str:
    return json.dumps(values, separators=(",", ":"))


def clamp_rollout_percent(value: int | None) -> int:
    if value is None:
        return 100
    return max(0, min(100, int(value)))


@dataclass(frozen=True)
class CreatedCustomer:
    customer: dict[str, Any]
    license_key: str | None


class LicensingService:
    def __init__(self, database: Database):
        self.database = database

    def create_admin_user(self, username: str, password: str) -> str:
        admin_id = uuid.uuid4().hex
        now = iso()
        with self.database.session() as connection:
            connection.execute(
                """
                INSERT INTO admin_users(id, username, password_hash, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (admin_id, username.strip(), hash_password(password), now),
            )
            self.audit(connection, "system", None, "admin_user.created", "admin_user", admin_id, {"username": username})
        return admin_id

    def authenticate_admin(
        self,
        username: str,
        password: str,
        *,
        session_hours: int,
        ip_address: str | None,
        user_agent: str | None,
    ) -> tuple[dict[str, Any], str] | None:
        with self.database.session() as connection:
            user = connection.execute(
                "SELECT * FROM admin_users WHERE username = ? AND is_active = 1",
                (username.strip(),),
            ).fetchone()
            if user is None or not verify_password(password, user["password_hash"]):
                return None
            token = random_token()
            session_id = uuid.uuid4().hex
            now = utc_now()
            expires = now + timedelta(hours=session_hours)
            connection.execute(
                """
                INSERT INTO admin_sessions(
                    id, admin_user_id, token_hash, created_at, expires_at, last_seen_at, ip_address, user_agent
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (session_id, user["id"], sha256_hex(token), iso(now), iso(expires), iso(now), ip_address, user_agent),
            )
            connection.execute("UPDATE admin_users SET last_login_at = ? WHERE id = ?", (iso(now), user["id"]))
            self.audit(connection, "admin", user["id"], "admin.login", "admin_user", user["id"], {"username": user["username"]}, ip_address)
            return dict(user), token

    def admin_from_session(self, token: str | None) -> dict[str, Any] | None:
        if not token:
            return None
        now = iso()
        with self.database.session() as connection:
            row = connection.execute(
                """
                SELECT admin_users.*
                FROM admin_sessions
                JOIN admin_users ON admin_users.id = admin_sessions.admin_user_id
                WHERE admin_sessions.token_hash = ?
                  AND admin_sessions.revoked_at IS NULL
                  AND admin_sessions.expires_at > ?
                  AND admin_users.is_active = 1
                """,
                (sha256_hex(token), now),
            ).fetchone()
            if row is None:
                return None
            connection.execute(
                "UPDATE admin_sessions SET last_seen_at = ? WHERE token_hash = ?",
                (now, sha256_hex(token)),
            )
            return dict(row)

    def revoke_session(self, token: str, admin_id: str | None = None) -> None:
        with self.database.session() as connection:
            connection.execute(
                "UPDATE admin_sessions SET revoked_at = ? WHERE token_hash = ?",
                (iso(), sha256_hex(token)),
            )
            if admin_id:
                self.audit(connection, "admin", admin_id, "admin.logout", "admin_user", admin_id, None)

    def change_admin_password(
        self,
        *,
        admin_id: str,
        current_password: str,
        new_password: str,
        ip_address: str | None,
    ) -> tuple[bool, str]:
        if len(new_password) < 12:
            return False, "New password must be at least 12 characters."
        now = iso()
        with self.database.session() as connection:
            user = connection.execute(
                "SELECT * FROM admin_users WHERE id = ? AND is_active = 1",
                (admin_id,),
            ).fetchone()
            if user is None:
                return False, "Admin user is not active."
            if not verify_password(current_password, user["password_hash"]):
                return False, "Current password is incorrect."
            connection.execute(
                "UPDATE admin_users SET password_hash = ? WHERE id = ?",
                (hash_password(new_password), admin_id),
            )
            connection.execute(
                "UPDATE admin_sessions SET revoked_at = ? WHERE admin_user_id = ? AND revoked_at IS NULL",
                (now, admin_id),
            )
            self.audit(
                connection,
                "admin",
                admin_id,
                "admin.password_changed",
                "admin_user",
                admin_id,
                {"username": user["username"]},
                ip_address,
            )
        return True, "Password changed. Sign in again."

    def list_products(self, include_inactive: bool = True) -> list[dict[str, Any]]:
        where = "" if include_inactive else "WHERE is_active = 1"
        with self.database.session() as connection:
            rows = connection.execute(
                f"SELECT * FROM products {where} ORDER BY is_active DESC, name ASC"
            ).fetchall()
        return [dict(row) for row in rows]

    def get_product(self, product_id: str) -> dict[str, Any] | None:
        with self.database.session() as connection:
            row = connection.execute("SELECT * FROM products WHERE id = ?", (product_id,)).fetchone()
        return dict(row) if row is not None else None

    def update_product(
        self,
        *,
        product_id: str,
        slug: str,
        name: str,
        feature_id: str,
        whop_product_id: str | None,
        is_active: bool,
        actor_id: str | None = None,
        ip_address: str | None = None,
    ) -> dict[str, Any]:
        now = iso()
        normalized_slug = slugify(slug)
        with self.database.session() as connection:
            existing = connection.execute("SELECT * FROM products WHERE id = ?", (product_id,)).fetchone()
            if existing is None:
                raise ValueError("Product not found.")
            connection.execute(
                """
                UPDATE products
                SET whop_product_id = ?,
                    slug = ?,
                    name = ?,
                    feature_id = ?,
                    is_active = ?,
                    updated_at = ?
                WHERE id = ?
                """,
                (
                    whop_product_id.strip() if whop_product_id else None,
                    normalized_slug,
                    name.strip(),
                    feature_id.strip(),
                    int(is_active),
                    now,
                    product_id,
                ),
            )
            self.audit(
                connection,
                "admin" if actor_id else "system",
                actor_id,
                "product.updated",
                "product",
                product_id,
                {"slug": normalized_slug, "whop_product_id": whop_product_id},
                ip_address,
            )
            product = connection.execute("SELECT * FROM products WHERE id = ?", (product_id,)).fetchone()
            return dict(product)

    def upsert_product(
        self,
        *,
        slug: str,
        name: str,
        feature_id: str,
        whop_product_id: str | None = None,
        is_active: bool = True,
        metadata: dict[str, Any] | None = None,
        actor_id: str | None = None,
        ip_address: str | None = None,
    ) -> dict[str, Any]:
        now = iso()
        normalized_slug = slugify(slug)
        metadata_json = json.dumps(metadata or {}, sort_keys=True)
        with self.database.session() as connection:
            row = connection.execute(
                "SELECT * FROM products WHERE slug = ? OR feature_id = ? OR (whop_product_id IS NOT NULL AND whop_product_id = ?)",
                (normalized_slug, feature_id, whop_product_id),
            ).fetchone()
            if row is None:
                product_id = uuid.uuid4().hex
                connection.execute(
                    """
                    INSERT INTO products(id, whop_product_id, slug, name, feature_id, is_active, metadata_json, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (product_id, whop_product_id, normalized_slug, name.strip(), feature_id.strip(), int(is_active), metadata_json, now, now),
                )
                action = "product.created"
            else:
                product_id = row["id"]
                connection.execute(
                    """
                    UPDATE products
                    SET whop_product_id = COALESCE(?, whop_product_id),
                        slug = ?,
                        name = ?,
                        feature_id = ?,
                        is_active = ?,
                        metadata_json = ?,
                        updated_at = ?
                    WHERE id = ?
                    """,
                    (whop_product_id, normalized_slug, name.strip(), feature_id.strip(), int(is_active), metadata_json, now, product_id),
                )
                action = "product.updated"
            self.audit(connection, "admin" if actor_id else "system", actor_id, action, "product", product_id, {"slug": normalized_slug}, ip_address)
            product = connection.execute("SELECT * FROM products WHERE id = ?", (product_id,)).fetchone()
            return dict(product)

    def list_whop_packages(self) -> list[dict[str, Any]]:
        with self.database.session() as connection:
            package_rows = connection.execute(
                "SELECT * FROM whop_packages ORDER BY is_active DESC, is_ignored ASC, name ASC"
            ).fetchall()
            packages = [dict(row) for row in package_rows]
            for package in packages:
                package["grants"] = self._package_grants(connection, package["id"])
        return packages

    def get_whop_package(self, package_id: str) -> dict[str, Any] | None:
        with self.database.session() as connection:
            row = connection.execute("SELECT * FROM whop_packages WHERE id = ?", (package_id,)).fetchone()
            if row is None:
                return None
            package = dict(row)
            package["grants"] = self._package_grants(connection, package_id)
            return package

    def upsert_whop_package(
        self,
        *,
        package_id: str | None,
        whop_id: str,
        whop_id_type: str,
        name: str,
        default_days: int | None,
        is_active: bool,
        is_ignored: bool,
        grants: list[dict[str, Any]],
        actor_id: str | None = None,
        ip_address: str | None = None,
    ) -> dict[str, Any]:
        normalized_whop_id = whop_id.strip()
        normalized_type = whop_id_type if whop_id_type in {"plan", "product", "unknown"} else "unknown"
        normalized_name = name.strip()
        if not normalized_whop_id:
            raise ValueError("Whop id is required.")
        if not normalized_name:
            raise ValueError("Package name is required.")
        if default_days is not None and default_days < 0:
            raise ValueError("Default days cannot be negative.")
        if not is_ignored and grants and default_days is None:
            for grant in grants:
                if grant.get("days") is None:
                    raise ValueError("Set default days or per-strategy days for every package grant.")

        now = iso()
        with self.database.session() as connection:
            existing = None
            if package_id:
                existing = connection.execute("SELECT * FROM whop_packages WHERE id = ?", (package_id,)).fetchone()
                if existing is None:
                    raise ValueError("Whop package not found.")
            if existing is None:
                existing = connection.execute("SELECT * FROM whop_packages WHERE whop_id = ?", (normalized_whop_id,)).fetchone()

            if existing is None:
                saved_package_id = uuid.uuid4().hex
                connection.execute(
                    """
                    INSERT INTO whop_packages(
                        id, whop_id, whop_id_type, name, default_days, is_active,
                        is_ignored, metadata_json, created_at, updated_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        saved_package_id,
                        normalized_whop_id,
                        normalized_type,
                        normalized_name,
                        default_days,
                        int(is_active),
                        int(is_ignored),
                        json.dumps({}, sort_keys=True),
                        now,
                        now,
                    ),
                )
                action = "whop_package.created"
            else:
                saved_package_id = existing["id"]
                connection.execute(
                    """
                    UPDATE whop_packages
                    SET whop_id = ?, whop_id_type = ?, name = ?, default_days = ?,
                        is_active = ?, is_ignored = ?, updated_at = ?
                    WHERE id = ?
                    """,
                    (
                        normalized_whop_id,
                        normalized_type,
                        normalized_name,
                        default_days,
                        int(is_active),
                        int(is_ignored),
                        now,
                        saved_package_id,
                    ),
                )
                action = "whop_package.updated"

            connection.execute("DELETE FROM whop_package_grants WHERE package_id = ?", (saved_package_id,))
            for grant in grants:
                product_id = str(grant.get("product_id") or "").strip()
                if not product_id:
                    continue
                product = connection.execute("SELECT * FROM products WHERE id = ?", (product_id,)).fetchone()
                if product is None:
                    raise ValueError(f"Strategy product not found: {product_id}")
                days = grant.get("days")
                if days is not None and int(days) < 0:
                    raise ValueError("Grant days cannot be negative.")
                connection.execute(
                    """
                    INSERT INTO whop_package_grants(
                        id, package_id, product_id, days, created_at, updated_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        uuid.uuid4().hex,
                        saved_package_id,
                        product_id,
                        int(days) if days is not None else None,
                        now,
                        now,
                    ),
                )

            self.audit(
                connection,
                "admin" if actor_id else "system",
                actor_id,
                action,
                "whop_package",
                saved_package_id,
                {
                    "whop_id": normalized_whop_id,
                    "whop_id_type": normalized_type,
                    "default_days": default_days,
                    "grant_count": len(grants),
                    "is_ignored": is_ignored,
                },
                ip_address,
            )
            package = connection.execute("SELECT * FROM whop_packages WHERE id = ?", (saved_package_id,)).fetchone()
            result = dict(package)
            result["grants"] = self._package_grants(connection, saved_package_id)
            return result

    def list_releases(self, include_inactive: bool = True) -> list[dict[str, Any]]:
        where = "" if include_inactive else "WHERE trader_releases.is_active = 1"
        with self.database.session() as connection:
            rows = connection.execute(
                f"""
                SELECT trader_releases.*, products.name AS product_name, products.slug AS product_slug,
                       products.feature_id AS feature_id
                FROM trader_releases
                LEFT JOIN products ON products.id = trader_releases.product_id
                {where}
                ORDER BY trader_releases.is_active DESC, trader_releases.channel ASC,
                         trader_releases.platform ASC, trader_releases.created_at DESC
                """
            ).fetchall()
        return [dict(row) for row in rows]

    def get_release(self, release_id: str) -> dict[str, Any] | None:
        with self.database.session() as connection:
            row = connection.execute(
                """
                SELECT trader_releases.*, products.name AS product_name, products.slug AS product_slug,
                       products.feature_id AS feature_id
                FROM trader_releases
                LEFT JOIN products ON products.id = trader_releases.product_id
                WHERE trader_releases.id = ?
                """,
                (release_id,),
            ).fetchone()
        return dict(row) if row is not None else None

    def upsert_release(
        self,
        *,
        release_id: str | None,
        scope: str,
        release_type: str | None = None,
        product_key: str | None = None,
        product_id: str | None,
        channel: str,
        platform: str,
        version: str,
        min_supported_version: str | None,
        is_required: bool,
        is_active: bool,
        artifact_path: str,
        artifact_filename: str | None,
        size_bytes: int | None,
        sha256_value: str | None,
        signature: str | None,
        signature_key_id: str | None = None,
        release_notes: str | None,
        artifact_dir: str,
        audience_mode: str | None = None,
        allowed_customer_ids: list[str] | str | None = None,
        allowed_emails: list[str] | str | None = None,
        allowed_license_keys: list[str] | str | None = None,
        required_tags: list[str] | str | None = None,
        rollout_percent: int | None = None,
        rollback_reason: str | None = None,
        actor_id: str | None = None,
        ip_address: str | None = None,
    ) -> dict[str, Any]:
        normalized_scope = scope if scope in {"app", "strategy"} else "strategy"
        normalized_release_type = release_type if release_type in RELEASE_TYPES else release_type_from_scope(normalized_scope)
        normalized_scope = scope_from_release_type(normalized_release_type)
        normalized_product_key = product_key.strip() if product_key and product_key.strip() else None
        normalized_channel = channel.strip().lower() or "stable"
        normalized_platform = platform.strip().lower() or DEFAULT_RELEASE_PLATFORM
        normalized_version = version.strip()
        normalized_path = artifact_path.strip()
        normalized_audience_mode = (audience_mode or "all").strip().lower()
        if normalized_audience_mode not in AUDIENCE_MODES:
            raise ValueError(f"Invalid audience mode: {audience_mode}")
        normalized_allowed_customer_ids = normalize_identifier_list(allowed_customer_ids)
        normalized_allowed_emails = normalize_identifier_list(allowed_emails, lower=True)
        normalized_allowed_license_key_hashes = [
            hash_license_key(value)
            for value in normalize_identifier_list(allowed_license_keys)
            if value.strip()
        ]
        normalized_required_tags = normalize_tag_list(required_tags)
        normalized_rollout_percent = clamp_rollout_percent(rollout_percent)
        if not normalized_version:
            raise ValueError("Version is required.")
        if not normalized_path:
            raise ValueError("Artifact path is required.")
        if normalized_scope == "strategy" and not product_id:
            raise ValueError("Strategy release requires a product.")
        if normalized_scope == "app":
            product_id = None
            normalized_product_key = normalized_product_key or TRADER_DESKTOP_PRODUCT_ID

        artifact_file = self._artifact_path(normalized_path, artifact_dir)
        if not artifact_filename:
            artifact_filename = artifact_file.name
        calculated_size = size_bytes
        calculated_sha = sha256_value.strip().lower() if sha256_value else None
        if artifact_file.exists() and artifact_file.is_file():
            calculated_size = artifact_file.stat().st_size if calculated_size is None else calculated_size
            calculated_sha = file_sha256(artifact_file) if not calculated_sha else calculated_sha
        if calculated_size is not None and calculated_size < 0:
            raise ValueError("Artifact size cannot be negative.")

        now = iso()
        with self.database.session() as connection:
            if product_id:
                product = connection.execute("SELECT * FROM products WHERE id = ?", (product_id,)).fetchone()
                if product is None:
                    raise ValueError("Strategy product not found.")
                normalized_product_key = normalized_product_key or product["slug"]
            existing = None
            if release_id:
                existing = connection.execute("SELECT * FROM trader_releases WHERE id = ?", (release_id,)).fetchone()
                if existing is None:
                    raise ValueError("Release not found.")
            saved_release_id = existing["id"] if existing else uuid.uuid4().hex
            if existing is None:
                connection.execute(
                    """
                    INSERT INTO trader_releases(
                        id, product_id, scope, release_type, product_key, channel, platform, version, min_supported_version,
                        is_required, is_active, artifact_path, artifact_filename, size_bytes,
                        sha256, signature, signature_key_id, release_notes, is_published, published_at,
                        audience_mode, allowed_customer_ids_json, allowed_emails_json,
                        allowed_license_key_hashes_json, required_tags_json, rollout_percent, rollback_reason,
                        created_by_admin_id, created_at, updated_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        saved_release_id,
                        product_id,
                        normalized_scope,
                        normalized_release_type,
                        normalized_product_key,
                        normalized_channel,
                        normalized_platform,
                        normalized_version,
                        min_supported_version.strip() if min_supported_version else None,
                        int(is_required),
                        int(is_active),
                        normalized_path,
                        artifact_filename.strip(),
                        calculated_size,
                        calculated_sha,
                        signature.strip() if signature else None,
                        signature_key_id.strip() if signature_key_id else None,
                        release_notes.strip() if release_notes else None,
                        int(is_active),
                        now if is_active else None,
                        normalized_audience_mode,
                        json_list_text(normalized_allowed_customer_ids),
                        json_list_text(normalized_allowed_emails),
                        json_list_text(normalized_allowed_license_key_hashes),
                        json_list_text(normalized_required_tags),
                        normalized_rollout_percent,
                        rollback_reason.strip() if rollback_reason else None,
                        actor_id,
                        now,
                        now,
                    ),
                )
                action = "release.created"
            else:
                connection.execute(
                    """
                    UPDATE trader_releases
                    SET product_id = ?, scope = ?, release_type = ?, product_key = ?, channel = ?, platform = ?, version = ?,
                        min_supported_version = ?, is_required = ?, is_active = ?,
                        artifact_path = ?, artifact_filename = ?, size_bytes = ?, sha256 = ?,
                        signature = ?, signature_key_id = ?, release_notes = ?, is_published = ?,
                        published_at = ?, audience_mode = ?, allowed_customer_ids_json = ?,
                        allowed_emails_json = ?, allowed_license_key_hashes_json = ?, required_tags_json = ?,
                        rollout_percent = ?, rollback_reason = ?, updated_at = ?
                    WHERE id = ?
                    """,
                    (
                        product_id,
                        normalized_scope,
                        normalized_release_type,
                        normalized_product_key,
                        normalized_channel,
                        normalized_platform,
                        normalized_version,
                        min_supported_version.strip() if min_supported_version else None,
                        int(is_required),
                        int(is_active),
                        normalized_path,
                        artifact_filename.strip(),
                        calculated_size,
                        calculated_sha,
                        signature.strip() if signature else None,
                        signature_key_id.strip() if signature_key_id else None,
                        release_notes.strip() if release_notes else None,
                        int(is_active),
                        now if is_active else None,
                        normalized_audience_mode,
                        json_list_text(normalized_allowed_customer_ids),
                        json_list_text(normalized_allowed_emails),
                        json_list_text(normalized_allowed_license_key_hashes),
                        json_list_text(normalized_required_tags),
                        normalized_rollout_percent,
                        rollback_reason.strip() if rollback_reason else None,
                        now,
                        saved_release_id,
                    ),
                )
                action = "release.updated"
            self.audit(
                connection,
                "admin" if actor_id else "system",
                actor_id,
                action,
                "release",
                saved_release_id,
                {
                    "scope": normalized_scope,
                    "release_type": normalized_release_type,
                    "product_id": product_id,
                    "product_key": normalized_product_key,
                    "channel": normalized_channel,
                    "platform": normalized_platform,
                    "version": normalized_version,
                    "published": is_active,
                    "audience_mode": normalized_audience_mode,
                    "rollout_percent": normalized_rollout_percent,
                    "required_tags": normalized_required_tags,
                },
                ip_address,
            )
            release = connection.execute(
                """
                SELECT trader_releases.*, products.name AS product_name, products.slug AS product_slug,
                       products.feature_id AS feature_id
                FROM trader_releases
                LEFT JOIN products ON products.id = trader_releases.product_id
                WHERE trader_releases.id = ?
                """,
                (saved_release_id,),
            ).fetchone()
            return dict(release)

    def create_or_update_customer(
        self,
        *,
        email: str | None = None,
        name: str | None = None,
        whop_user_id: str | None = None,
        whop_member_id: str | None = None,
        license_key: str | None = None,
        generate_key: bool = True,
        actor_type: str = "system",
        actor_id: str | None = None,
        ip_address: str | None = None,
    ) -> CreatedCustomer:
        normalized_email = normalize_email(email)
        lookup_conditions: list[str] = []
        parameters: list[Any] = []
        if normalized_email:
            lookup_conditions.append("email_normalized = ?")
            parameters.append(normalized_email)
        if whop_user_id:
            lookup_conditions.append("whop_user_id = ?")
            parameters.append(whop_user_id)
        if whop_member_id:
            lookup_conditions.append("whop_member_id = ?")
            parameters.append(whop_member_id)
        if license_key:
            lookup_conditions.append("license_key_hash = ?")
            parameters.append(hash_license_key(license_key))
        where = " OR ".join(lookup_conditions)
        generated_key = None
        now = iso()
        with self.database.session() as connection:
            row = connection.execute(f"SELECT * FROM customers WHERE {where}", parameters).fetchone() if where else None
            if row is None:
                customer_id = uuid.uuid4().hex
                generated_key = license_key or (generate_license_key() if generate_key else None)
                connection.execute(
                    """
                    INSERT INTO customers(
                        id, whop_user_id, whop_member_id, email, email_normalized, name,
                        license_key_hash, license_key_last4, created_at, updated_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        customer_id,
                        whop_user_id,
                        whop_member_id,
                        email.strip() if email else None,
                        normalized_email,
                        name.strip() if name else None,
                        hash_license_key(generated_key) if generated_key else None,
                        generated_key[-4:] if generated_key else None,
                        now,
                        now,
                    ),
                )
                action = "customer.created"
            else:
                customer_id = row["id"]
                connection.execute(
                    """
                    UPDATE customers
                    SET whop_user_id = COALESCE(?, whop_user_id),
                        whop_member_id = COALESCE(?, whop_member_id),
                        email = COALESCE(?, email),
                        email_normalized = COALESCE(?, email_normalized),
                        name = COALESCE(?, name),
                        updated_at = ?
                    WHERE id = ?
                    """,
                    (
                        whop_user_id,
                        whop_member_id,
                        email.strip() if email else None,
                        normalized_email,
                        name.strip() if name else None,
                        now,
                        customer_id,
                    ),
                )
                if license_key and row["license_key_hash"] is None:
                    connection.execute(
                        "UPDATE customers SET license_key_hash = ?, license_key_last4 = ?, updated_at = ? WHERE id = ?",
                        (hash_license_key(license_key), license_key[-4:], now, customer_id),
                    )
                action = "customer.updated"
            self.audit(connection, actor_type, actor_id, action, "customer", customer_id, {"email": normalized_email}, ip_address)
            customer = connection.execute("SELECT * FROM customers WHERE id = ?", (customer_id,)).fetchone()
            return CreatedCustomer(dict(customer), generated_key)

    def search_customers(self, query: str = "", limit: int = 50) -> list[dict[str, Any]]:
        pattern = f"%{query.strip().lower()}%"
        with self.database.session() as connection:
            if query.strip():
                rows = connection.execute(
                    """
                    SELECT customers.*,
                           COUNT(DISTINCT devices.id) AS device_count,
                           COUNT(DISTINCT entitlements.id) AS entitlement_count
                    FROM customers
                    LEFT JOIN devices ON devices.customer_id = customers.id
                    LEFT JOIN entitlements ON entitlements.customer_id = customers.id
                    WHERE lower(COALESCE(customers.email, '')) LIKE ?
                       OR lower(COALESCE(customers.name, '')) LIKE ?
                       OR lower(COALESCE(customers.whop_user_id, '')) LIKE ?
                       OR lower(COALESCE(customers.whop_member_id, '')) LIKE ?
                       OR customers.id LIKE ?
                    GROUP BY customers.id
                    ORDER BY customers.updated_at DESC
                    LIMIT ?
                    """,
                    (pattern, pattern, pattern, pattern, pattern, limit),
                ).fetchall()
            else:
                rows = connection.execute(
                    """
                    SELECT customers.*,
                           COUNT(DISTINCT devices.id) AS device_count,
                           COUNT(DISTINCT entitlements.id) AS entitlement_count
                    FROM customers
                    LEFT JOIN devices ON devices.customer_id = customers.id
                    LEFT JOIN entitlements ON entitlements.customer_id = customers.id
                    GROUP BY customers.id
                    ORDER BY customers.updated_at DESC
                    LIMIT ?
                    """,
                    (limit,),
                ).fetchall()
        return [dict(row) for row in rows]

    def customer_detail(self, customer_id: str, default_max_devices: int = 1) -> dict[str, Any] | None:
        with self.database.session() as connection:
            customer = connection.execute("SELECT * FROM customers WHERE id = ?", (customer_id,)).fetchone()
            if customer is None:
                return None
            active_device_count = self._active_device_count(connection, customer_id)
            effective_max_devices = self._effective_max_devices(customer, default_max_devices)
            entitlements = connection.execute(
                """
                SELECT entitlements.*, products.slug, products.name AS product_name, products.feature_id
                FROM entitlements
                JOIN products ON products.id = entitlements.product_id
                WHERE entitlements.customer_id = ?
                ORDER BY entitlements.updated_at DESC
                """,
                (customer_id,),
            ).fetchall()
            subscriptions = connection.execute(
                "SELECT * FROM subscriptions WHERE customer_id = ? ORDER BY updated_at DESC",
                (customer_id,),
            ).fetchall()
            devices = connection.execute(
                "SELECT * FROM devices WHERE customer_id = ? ORDER BY last_seen_at DESC",
                (customer_id,),
            ).fetchall()
            checks = connection.execute(
                "SELECT * FROM license_checks WHERE customer_id = ? ORDER BY created_at DESC LIMIT 30",
                (customer_id,),
            ).fetchall()
            audit = connection.execute(
                """
                SELECT * FROM audit_log
                WHERE (entity_type = 'customer' AND entity_id = ?)
                   OR details_json LIKE ?
                ORDER BY created_at DESC LIMIT 50
                """,
                (customer_id, f"%{customer_id}%"),
            ).fetchall()
        return {
            "customer": dict(customer),
            "tags": json_list(dict(customer).get("tags_json")),
            "entitlements": [dict(row) for row in entitlements],
            "subscriptions": [dict(row) for row in subscriptions],
            "devices": [dict(row) for row in devices],
            "checks": [dict(row) for row in checks],
            "audit": [dict(row) for row in audit],
            "device_limit": {
                "active_devices": active_device_count,
                "max_devices": effective_max_devices,
                "customer_max_devices": dict(customer).get("max_devices"),
                "default_max_devices": max(1, int(default_max_devices)),
            },
        }

    def manual_set_entitlement(
        self,
        *,
        customer_id: str,
        product_id: str,
        status: str,
        expires_at: str | None,
        reason: str | None,
        actor_id: str,
        ip_address: str | None,
    ) -> dict[str, Any]:
        if status not in {"active", "trialing", "expired", "revoked", "suspended", "pending"}:
            raise ValueError(f"Invalid entitlement status: {status}")
        parsed_expiry = parse_time(expires_at)
        if expires_at and parsed_expiry is None:
            raise ValueError("Invalid entitlement expiry date/time.")
        saved_expiry = iso(parsed_expiry) if parsed_expiry else None
        now = iso()
        external_id = f"manual:{customer_id}:{product_id}"
        revoked_at = now if status == "revoked" else None
        with self.database.session() as connection:
            existing = connection.execute(
                "SELECT * FROM entitlements WHERE source = 'manual' AND external_id = ?",
                (external_id,),
            ).fetchone()
            if existing is None:
                entitlement_id = uuid.uuid4().hex
                connection.execute(
                    """
                    INSERT INTO entitlements(
                        id, customer_id, product_id, external_id, source, status, starts_at,
                        expires_at, revoked_at, manual_reason, created_at, updated_at
                    )
                    VALUES (?, ?, ?, ?, 'manual', ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (entitlement_id, customer_id, product_id, external_id, status, now, saved_expiry, revoked_at, reason, now, now),
                )
                action = "entitlement.manual_created"
            else:
                entitlement_id = existing["id"]
                connection.execute(
                    """
                    UPDATE entitlements
                    SET status = ?, expires_at = ?, revoked_at = ?, manual_reason = ?, updated_at = ?
                    WHERE id = ?
                    """,
                    (status, saved_expiry, revoked_at, reason, now, entitlement_id),
                )
                action = "entitlement.manual_updated"
            self.audit(
                connection,
                "admin",
                actor_id,
                action,
                "entitlement",
                entitlement_id,
                {"customer_id": customer_id, "product_id": product_id, "status": status, "expires_at": saved_expiry},
                ip_address,
            )
            row = connection.execute("SELECT * FROM entitlements WHERE id = ?", (entitlement_id,)).fetchone()
            return dict(row)

    def set_device_blocked(
        self,
        *,
        device_id: str,
        is_blocked: bool,
        note: str | None,
        actor_id: str,
        ip_address: str | None,
    ) -> None:
        with self.database.session() as connection:
            connection.execute(
                "UPDATE devices SET is_blocked = ?, note = COALESCE(?, note) WHERE id = ?",
                (int(is_blocked), note, device_id),
            )
            self.audit(
                connection,
                "admin",
                actor_id,
                "device.blocked" if is_blocked else "device.unblocked",
                "device",
                device_id,
                {"note": note},
                ip_address,
            )

    def set_customer_max_devices(
        self,
        *,
        customer_id: str,
        max_devices: int | None,
        actor_id: str,
        ip_address: str | None,
    ) -> None:
        if max_devices is not None and max_devices < 1:
            raise ValueError("Max devices must be empty or at least 1.")
        with self.database.session() as connection:
            existing = connection.execute("SELECT * FROM customers WHERE id = ?", (customer_id,)).fetchone()
            if existing is None:
                raise ValueError("Customer not found.")
            connection.execute(
                "UPDATE customers SET max_devices = ?, updated_at = ? WHERE id = ?",
                (max_devices, iso(), customer_id),
            )
            self.audit(
                connection,
                "admin",
                actor_id,
                "customer.max_devices_updated",
                "customer",
                customer_id,
                {"max_devices": max_devices},
                ip_address,
            )

    def block_all_customer_devices(
        self,
        *,
        customer_id: str,
        note: str | None,
        actor_id: str,
        ip_address: str | None,
    ) -> int:
        with self.database.session() as connection:
            existing = connection.execute("SELECT * FROM customers WHERE id = ?", (customer_id,)).fetchone()
            if existing is None:
                raise ValueError("Customer not found.")
            cursor = connection.execute(
                """
                UPDATE devices
                SET is_blocked = 1, note = COALESCE(?, note)
                WHERE customer_id = ? AND is_blocked = 0
                """,
                (note, customer_id),
            )
            blocked_count = cursor.rowcount if cursor.rowcount is not None else 0
            self.audit(
                connection,
                "admin",
                actor_id,
                "customer.devices_blocked",
                "customer",
                customer_id,
                {"blocked_count": blocked_count, "note": note},
                ip_address,
            )
            return blocked_count

    def set_customer_tags(
        self,
        *,
        customer_id: str,
        tags: list[str] | str | None,
        actor_id: str,
        ip_address: str | None,
    ) -> list[str]:
        normalized_tags = normalize_tag_list(tags)
        with self.database.session() as connection:
            existing = connection.execute("SELECT * FROM customers WHERE id = ?", (customer_id,)).fetchone()
            if existing is None:
                raise ValueError("Customer not found.")
            connection.execute(
                "UPDATE customers SET tags_json = ?, updated_at = ? WHERE id = ?",
                (json_list_text(normalized_tags), iso(), customer_id),
            )
            self.audit(
                connection,
                "admin",
                actor_id,
                "customer.tags_updated",
                "customer",
                customer_id,
                {"tags": normalized_tags},
                ip_address,
            )
        return normalized_tags

    def process_whop_event(self, payload: dict[str, Any], webhook_id: str, *, signature_valid: bool, ip_address: str | None) -> dict[str, Any]:
        event_type = str(payload.get("action") or payload.get("type") or payload.get("event") or payload.get("event_type") or "unknown")
        data = payload.get("data") if isinstance(payload.get("data"), dict) else payload
        now = iso()
        with self.database.session() as connection:
            existing_event = connection.execute("SELECT * FROM webhook_events WHERE webhook_id = ?", (webhook_id,)).fetchone()
            if existing_event and existing_event["status"] == "processed":
                return {"status": "duplicate", "webhook_id": webhook_id}
            connection.execute(
                """
                INSERT INTO webhook_events(webhook_id, event_type, received_at, status, payload_json, signature_valid)
                VALUES (?, ?, ?, 'received', ?, ?)
                ON CONFLICT(webhook_id) DO UPDATE SET
                    event_type = excluded.event_type,
                    payload_json = excluded.payload_json,
                    signature_valid = excluded.signature_valid,
                    received_at = excluded.received_at,
                    status = 'received',
                    error = NULL
                """,
                (webhook_id, event_type, now, json.dumps(payload, sort_keys=True), int(signature_valid)),
            )
        try:
            result = self._upsert_whop_entitlement(data, event_type, webhook_id, ip_address)
        except Exception as exc:
            with self.database.session() as connection:
                connection.execute(
                    "UPDATE webhook_events SET status = 'failed', error = ? WHERE webhook_id = ?",
                    (str(exc), webhook_id),
                )
            raise
        with self.database.session() as connection:
            connection.execute(
                "UPDATE webhook_events SET status = 'processed', processed_at = ? WHERE webhook_id = ?",
                (iso(), webhook_id),
            )
        result["webhook_id"] = webhook_id
        return result

    def _upsert_whop_entitlement(self, data: dict[str, Any], event_type: str, webhook_id: str, ip_address: str | None) -> dict[str, Any]:
        customer_info = self._extract_customer_info(data)
        whop_ids = self._extract_whop_ids(data)
        subscription_info = self._extract_subscription_info(data, event_type)
        with self.database.session() as connection:
            package = self._find_whop_package(connection, whop_ids)
            direct_product = None if package is not None else self._find_direct_whop_product(connection, whop_ids)
            if package is None and direct_product is None:
                self.audit(
                    connection,
                    "whop",
                    None,
                    "whop_package.unmapped",
                    "webhook_event",
                    webhook_id,
                    {
                        "event_type": event_type,
                        "webhook_id": webhook_id,
                        "plan_id": whop_ids["plan_id"],
                        "product_id": whop_ids["product_id"],
                        "email": customer_info["email"],
                    },
                    ip_address,
                )
                return {
                    "status": "unmapped_package",
                    "customer_id": None,
                    "whop_id": whop_ids["selected_id"],
                    "message": "No Whop package mapping matched this event.",
                }

        customer_result = self.create_or_update_customer(
            email=customer_info["email"],
            name=customer_info["name"],
            whop_user_id=customer_info["whop_user_id"],
            whop_member_id=customer_info["whop_member_id"],
            actor_type="whop",
            ip_address=ip_address,
        )
        status = normalize_entitlement_status(subscription_info["status"], event_type)
        sub_status = normalize_subscription_status(subscription_info["status"], event_type)
        with self.database.session() as connection:
            subscription_id = self._upsert_whop_subscription(
                connection,
                customer_result.customer["id"],
                subscription_info,
                sub_status,
            )
            if package is None:
                entitlement = self._upsert_direct_whop_entitlement(
                    connection,
                    customer_id=customer_result.customer["id"],
                    product=direct_product,
                    subscription_id=subscription_id,
                    subscription_info=subscription_info,
                    status=status,
                    event_type=event_type,
                    webhook_id=webhook_id,
                    ip_address=ip_address,
                )
                return {
                    "status": "processed",
                    "customer_id": customer_result.customer["id"],
                    "product_id": direct_product["id"],
                    "entitlement_status": entitlement["status"],
                    "mapping_mode": "direct_product",
                }

            if package["is_ignored"]:
                self.audit(
                    connection,
                    "whop",
                    None,
                    "whop_package.ignored",
                    "whop_package",
                    package["id"],
                    {"customer_id": customer_result.customer["id"], "event_type": event_type, "webhook_id": webhook_id},
                    ip_address,
                )
                return {"status": "ignored", "customer_id": customer_result.customer["id"], "package_id": package["id"], "reason": "Whop package is marked non-license."}

            if not package["is_active"]:
                self.audit(
                    connection,
                    "whop",
                    None,
                    "whop_package.inactive",
                    "whop_package",
                    package["id"],
                    {"customer_id": customer_result.customer["id"], "event_type": event_type, "webhook_id": webhook_id},
                    ip_address,
                )
                return {"status": "inactive_package", "customer_id": customer_result.customer["id"], "package_id": package["id"]}

            grants = self._package_grants(connection, package["id"])
            if not grants:
                self.audit(
                    connection,
                    "whop",
                    None,
                    "whop_package.no_grants",
                    "whop_package",
                    package["id"],
                    {"customer_id": customer_result.customer["id"], "event_type": event_type, "webhook_id": webhook_id},
                    ip_address,
                )
                return {"status": "no_package_grants", "customer_id": customer_result.customer["id"], "package_id": package["id"]}

            applications = [
                self._apply_whop_package_grant(
                    connection,
                    customer_id=customer_result.customer["id"],
                    package=package,
                    grant=grant,
                    subscription_id=subscription_id,
                    subscription_info=subscription_info,
                    status=status,
                    event_type=event_type,
                    webhook_id=webhook_id,
                    ip_address=ip_address,
                )
                for grant in grants
            ]
        return {
            "status": "processed",
            "customer_id": customer_result.customer["id"],
            "package_id": package["id"],
            "whop_id": package["whop_id"],
            "entitlement_status": status,
            "mapping_mode": "whop_package",
            "applied_grants": applications,
        }

    def _upsert_whop_subscription(
        self,
        connection: sqlite3.Connection,
        customer_id: str,
        subscription_info: dict[str, Any],
        sub_status: str,
    ) -> str | None:
        if not subscription_info["membership_id"]:
            return None
        now = iso()
        existing_sub = connection.execute(
            "SELECT * FROM subscriptions WHERE whop_membership_id = ?",
            (subscription_info["membership_id"],),
        ).fetchone()
        if existing_sub is None:
            subscription_id = uuid.uuid4().hex
            connection.execute(
                """
                INSERT INTO subscriptions(
                    id, customer_id, whop_membership_id, whop_plan_id, status, raw_status,
                    current_period_start, current_period_end, cancel_at_period_end, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    subscription_id,
                    customer_id,
                    subscription_info["membership_id"],
                    subscription_info["plan_id"],
                    sub_status,
                    subscription_info["status"],
                    iso(subscription_info["period_start"]) if subscription_info["period_start"] else None,
                    iso(subscription_info["expires_at"]) if subscription_info["expires_at"] else None,
                    int(subscription_info["cancel_at_period_end"]),
                    now,
                    now,
                ),
            )
            return subscription_id

        connection.execute(
            """
            UPDATE subscriptions
            SET customer_id = ?, whop_plan_id = COALESCE(?, whop_plan_id), status = ?, raw_status = ?,
                current_period_start = ?, current_period_end = ?, cancel_at_period_end = ?, updated_at = ?
            WHERE id = ?
            """,
            (
                customer_id,
                subscription_info["plan_id"],
                sub_status,
                subscription_info["status"],
                iso(subscription_info["period_start"]) if subscription_info["period_start"] else None,
                iso(subscription_info["expires_at"]) if subscription_info["expires_at"] else None,
                int(subscription_info["cancel_at_period_end"]),
                now,
                existing_sub["id"],
            ),
        )
        return existing_sub["id"]

    def _upsert_direct_whop_entitlement(
        self,
        connection: sqlite3.Connection,
        *,
        customer_id: str,
        product: dict[str, Any] | sqlite3.Row,
        subscription_id: str | None,
        subscription_info: dict[str, Any],
        status: str,
        event_type: str,
        webhook_id: str,
        ip_address: str | None,
    ) -> dict[str, Any]:
        now = iso()
        external_id = subscription_info["entitlement_id"] or subscription_info["membership_id"] or webhook_id
        existing_entitlement = connection.execute(
            "SELECT * FROM entitlements WHERE source = 'whop' AND external_id = ?",
            (external_id,),
        ).fetchone()
        revoked_at = now if status == "revoked" else None
        expires_at = iso(subscription_info["expires_at"]) if subscription_info["expires_at"] else None
        if existing_entitlement is None:
            entitlement_id = uuid.uuid4().hex
            connection.execute(
                """
                INSERT INTO entitlements(
                    id, customer_id, product_id, subscription_id, external_id, source, status,
                    starts_at, expires_at, revoked_at, whop_event_id, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, 'whop', ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    entitlement_id,
                    customer_id,
                    product["id"],
                    subscription_id,
                    external_id,
                    status,
                    iso(subscription_info["period_start"]) if subscription_info["period_start"] else now,
                    expires_at,
                    revoked_at,
                    webhook_id,
                    now,
                    now,
                ),
            )
            action = "entitlement.whop_created"
        else:
            entitlement_id = existing_entitlement["id"]
            connection.execute(
                """
                UPDATE entitlements
                SET customer_id = ?, product_id = ?, subscription_id = ?, status = ?,
                    starts_at = COALESCE(?, starts_at), expires_at = ?, revoked_at = ?, whop_event_id = ?, updated_at = ?
                WHERE id = ?
                """,
                (
                    customer_id,
                    product["id"],
                    subscription_id,
                    status,
                    iso(subscription_info["period_start"]) if subscription_info["period_start"] else None,
                    expires_at,
                    revoked_at,
                    webhook_id,
                    now,
                    entitlement_id,
                ),
            )
            action = "entitlement.whop_updated"
        self.audit(
            connection,
            "whop",
            None,
            action,
            "entitlement",
            entitlement_id,
            {"customer_id": customer_id, "product_id": product["id"], "status": status, "event_type": event_type, "webhook_id": webhook_id},
            ip_address,
        )
        row = connection.execute("SELECT * FROM entitlements WHERE id = ?", (entitlement_id,)).fetchone()
        return dict(row)

    def _apply_whop_package_grant(
        self,
        connection: sqlite3.Connection,
        *,
        customer_id: str,
        package: dict[str, Any] | sqlite3.Row,
        grant: dict[str, Any],
        subscription_id: str | None,
        subscription_info: dict[str, Any],
        status: str,
        event_type: str,
        webhook_id: str,
        ip_address: str | None,
    ) -> dict[str, Any]:
        now_dt = utc_now()
        now = iso(now_dt)
        product_id = grant["product_id"]
        external_root = subscription_info["membership_id"] or subscription_info["entitlement_id"] or f"{package['whop_id']}:{customer_id}"
        external_id = f"{external_root}:{product_id}"
        existing = connection.execute(
            "SELECT * FROM entitlements WHERE source = 'whop' AND external_id = ?",
            (external_id,),
        ).fetchone()
        before_expiry = parse_time(existing["expires_at"]) if existing else None
        grant_days = grant["days"] if grant["days"] is not None else package["default_days"]
        grant_days = int(grant_days) if grant_days is not None else None
        grant_kind = self._grant_kind(status, event_type)
        fingerprint = self._grant_fingerprint(
            grant_kind,
            customer_id=customer_id,
            package_id=package["id"],
            product_id=product_id,
            subscription_info=subscription_info,
            webhook_id=webhook_id,
        )

        if grant_kind in {"trial", "paid", "renewal"}:
            duplicate = connection.execute(
                "SELECT * FROM license_grant_ledger WHERE event_fingerprint = ?",
                (fingerprint,),
            ).fetchone()
            if duplicate is not None:
                return {
                    "product_id": product_id,
                    "strategy": grant["product_name"],
                    "status": "duplicate_grant",
                    "grant_kind": grant_kind,
                    "days_applied": 0,
                }

        expires_after = before_expiry
        days_applied = 0
        revoked_at = None
        target_status = status

        if grant_kind == "trial":
            trial_end = subscription_info["trial_ends_at"] or subscription_info["expires_at"]
            if trial_end and trial_end > now_dt:
                expires_after = later_time(before_expiry, trial_end)
                days_applied = ceil_days(trial_end - now_dt)
            elif grant_days is not None:
                base = later_time(before_expiry, now_dt) or now_dt
                expires_after = base + timedelta(days=grant_days)
                days_applied = grant_days
        elif grant_kind in {"paid", "renewal"}:
            if grant_days is not None:
                base = later_time(before_expiry, now_dt) or now_dt
                expires_after = base + timedelta(days=grant_days)
                days_applied = grant_days
            elif subscription_info["expires_at"]:
                expires_after = later_time(before_expiry, subscription_info["expires_at"])
        elif grant_kind == "revoke":
            target_status = "revoked"
            revoked_at = now
        elif grant_kind == "expire":
            target_status = "expired"
            expires_after = before_expiry or now_dt
        elif grant_kind == "suspend":
            target_status = "suspended"
            expires_after = before_expiry or subscription_info["expires_at"]

        if existing is None:
            entitlement_id = uuid.uuid4().hex
            connection.execute(
                """
                INSERT INTO entitlements(
                    id, customer_id, product_id, subscription_id, external_id, source, status,
                    starts_at, expires_at, revoked_at, whop_event_id, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, 'whop', ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    entitlement_id,
                    customer_id,
                    product_id,
                    subscription_id,
                    external_id,
                    target_status,
                    iso(subscription_info["period_start"]) if subscription_info["period_start"] else now,
                    iso(expires_after) if expires_after else None,
                    revoked_at,
                    webhook_id,
                    now,
                    now,
                ),
            )
            action = "entitlement.whop_created"
        else:
            entitlement_id = existing["id"]
            connection.execute(
                """
                UPDATE entitlements
                SET customer_id = ?, product_id = ?, subscription_id = ?, status = ?,
                    starts_at = COALESCE(?, starts_at), expires_at = ?, revoked_at = ?,
                    whop_event_id = ?, updated_at = ?
                WHERE id = ?
                """,
                (
                    customer_id,
                    product_id,
                    subscription_id,
                    target_status,
                    iso(subscription_info["period_start"]) if subscription_info["period_start"] else None,
                    iso(expires_after) if expires_after else None,
                    revoked_at,
                    webhook_id,
                    now,
                    entitlement_id,
                ),
            )
            action = "entitlement.whop_updated"

        self._record_grant_ledger(
            connection,
            customer_id=customer_id,
            package_id=package["id"],
            product_id=product_id,
            subscription_id=subscription_id,
            entitlement_id=entitlement_id,
            webhook_id=webhook_id,
            event_fingerprint=fingerprint,
            grant_kind=grant_kind,
            days_applied=days_applied,
            period_start=subscription_info["period_start"],
            period_end=subscription_info["expires_at"],
            expires_at_before=before_expiry,
            expires_at_after=expires_after,
            details={
                "event_type": event_type,
                "status": status,
                "package_whop_id": package["whop_id"],
            },
        )
        self.audit(
            connection,
            "whop",
            None,
            action,
            "entitlement",
            entitlement_id,
            {
                "customer_id": customer_id,
                "package_id": package["id"],
                "product_id": product_id,
                "status": target_status,
                "grant_kind": grant_kind,
                "days_applied": days_applied,
                "webhook_id": webhook_id,
            },
            ip_address,
        )
        return {
            "product_id": product_id,
            "strategy": grant["product_name"],
            "status": target_status,
            "grant_kind": grant_kind,
            "days_applied": days_applied,
            "expires_at": iso(expires_after) if expires_after else None,
        }

    def _package_grants(self, connection: sqlite3.Connection, package_id: str) -> list[dict[str, Any]]:
        rows = connection.execute(
            """
            SELECT whop_package_grants.*,
                   products.name AS product_name,
                   products.slug AS product_slug,
                   products.feature_id AS feature_id,
                   products.is_active AS product_is_active
            FROM whop_package_grants
            JOIN products ON products.id = whop_package_grants.product_id
            WHERE whop_package_grants.package_id = ?
            ORDER BY products.name ASC
            """,
            (package_id,),
        ).fetchall()
        return [dict(row) for row in rows]

    def _find_whop_package(self, connection: sqlite3.Connection, whop_ids: dict[str, str | None]) -> dict[str, Any] | None:
        for candidate in (whop_ids["plan_id"], whop_ids["product_id"]):
            if not candidate:
                continue
            row = connection.execute("SELECT * FROM whop_packages WHERE whop_id = ?", (candidate,)).fetchone()
            if row is not None:
                return dict(row)
        return None

    def _find_direct_whop_product(self, connection: sqlite3.Connection, whop_ids: dict[str, str | None]) -> dict[str, Any] | None:
        for candidate in (whop_ids["product_id"], whop_ids["plan_id"]):
            if not candidate:
                continue
            row = connection.execute(
                "SELECT * FROM products WHERE whop_product_id IS NOT NULL AND whop_product_id = ?",
                (candidate,),
            ).fetchone()
            if row is not None:
                return dict(row)
        return None

    def _grant_kind(self, status: str, event_type: str) -> str:
        combined = f"{status} {event_type}".lower()
        if status == "revoked":
            return "revoke"
        if status == "expired":
            return "expire"
        if status == "suspended":
            return "suspend"
        if status == "trialing":
            return "trial"
        if "renew" in combined:
            return "renewal"
        if status == "active":
            return "paid"
        return "ignored"

    def _grant_fingerprint(
        self,
        grant_kind: str,
        *,
        customer_id: str,
        package_id: str,
        product_id: str,
        subscription_info: dict[str, Any],
        webhook_id: str,
    ) -> str:
        membership_id = subscription_info["membership_id"] or subscription_info["entitlement_id"] or customer_id
        payment_id = subscription_info["payment_id"]
        period_start = iso(subscription_info["period_start"]) if subscription_info["period_start"] else ""
        period_end = iso(subscription_info["expires_at"]) if subscription_info["expires_at"] else ""
        if grant_kind == "trial":
            source = f"trial:{membership_id}:{package_id}:{product_id}"
        elif grant_kind in {"paid", "renewal"} and payment_id:
            source = f"{grant_kind}:payment:{payment_id}:{product_id}"
        elif grant_kind in {"paid", "renewal"}:
            source = f"{grant_kind}:period:{membership_id}:{package_id}:{product_id}:{period_start}:{period_end}"
        else:
            source = f"{grant_kind}:event:{webhook_id}:{product_id}"
        return sha256_hex(source)

    def _record_grant_ledger(
        self,
        connection: sqlite3.Connection,
        *,
        customer_id: str,
        package_id: str,
        product_id: str,
        subscription_id: str | None,
        entitlement_id: str,
        webhook_id: str,
        event_fingerprint: str,
        grant_kind: str,
        days_applied: int,
        period_start: datetime | None,
        period_end: datetime | None,
        expires_at_before: datetime | None,
        expires_at_after: datetime | None,
        details: dict[str, Any],
    ) -> None:
        existing = connection.execute(
            "SELECT 1 FROM license_grant_ledger WHERE event_fingerprint = ?",
            (event_fingerprint,),
        ).fetchone()
        if existing is not None:
            return
        connection.execute(
            """
            INSERT INTO license_grant_ledger(
                id, customer_id, package_id, product_id, subscription_id, entitlement_id,
                whop_event_id, event_fingerprint, grant_kind, days_applied, period_start,
                period_end, expires_at_before, expires_at_after, details_json, applied_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                uuid.uuid4().hex,
                customer_id,
                package_id,
                product_id,
                subscription_id,
                entitlement_id,
                webhook_id,
                event_fingerprint,
                grant_kind,
                days_applied,
                iso(period_start) if period_start else None,
                iso(period_end) if period_end else None,
                iso(expires_at_before) if expires_at_before else None,
                iso(expires_at_after) if expires_at_after else None,
                json.dumps(details, sort_keys=True),
                iso(),
            ),
        )

    def _installed_package_versions(self, installed_packages: list[dict[str, Any]] | None) -> dict[str, str]:
        versions: dict[str, str] = {}
        if not isinstance(installed_packages, list):
            return versions
        for package in installed_packages:
            if not isinstance(package, dict):
                continue
            version = str(package.get("version") or "").strip()
            if not version:
                continue
            for key_name in ("package_id", "product_id", "feature_id", "slug"):
                key = str(package.get(key_name) or "").strip().lower()
                if key:
                    versions[key] = version
        return versions

    def _current_version_for_release(
        self,
        release: dict[str, Any],
        app_version: str | None,
        installed_versions: dict[str, str],
    ) -> str | None:
        release_type = release.get("release_type") or release_type_from_scope(release.get("scope"))
        if release_type == TRADER_DESKTOP_RELEASE_TYPE:
            return app_version
        for candidate in (release.get("product_key"), release.get("product_slug"), release.get("feature_id"), release.get("product_id")):
            key = str(candidate or "").strip().lower()
            if key and key in installed_versions:
                return installed_versions[key]
        return app_version

    def _release_sort_key(self, release: dict[str, Any]) -> tuple[Any, ...]:
        return (
            CHANNEL_PRIORITY.get(str(release.get("channel") or "stable").lower(), 0),
            int(release.get("is_required") or 0),
            str(release.get("updated_at") or ""),
            str(release.get("created_at") or ""),
            parse_version_parts(str(release.get("version") or "")),
        )

    def _release_audience_match(self, release: dict[str, Any], customer: dict[str, Any]) -> tuple[bool, str]:
        mode = str(release.get("audience_mode") or "all").strip().lower()
        if mode not in AUDIENCE_MODES:
            mode = "all"
        if mode == "disabled":
            return False, "audience_disabled"

        customer_tags = set(json_list(customer.get("tags_json")))
        required_tags = set(normalize_tag_list(json_list(release.get("required_tags_json"))))
        tag_match = bool(required_tags & customer_tags) if required_tags else True
        if mode == "all":
            return (tag_match, "tag_required" if not tag_match else "allowed")

        allowed_customer_ids = set(json_list(release.get("allowed_customer_ids_json")))
        allowed_emails = set(normalize_identifier_list(json_list(release.get("allowed_emails_json")), lower=True))
        allowed_license_hashes = set(json_list(release.get("allowed_license_key_hashes_json")))
        customer_email = normalize_email(customer.get("email"))
        license_hash = customer.get("license_key_hash")
        allowlist_match = (
            customer.get("id") in allowed_customer_ids
            or (customer_email is not None and customer_email in allowed_emails)
            or (license_hash is not None and license_hash in allowed_license_hashes)
        )

        if mode == "allowlist":
            return (allowlist_match or bool(required_tags & customer_tags), "allowlist_miss")
        if mode == "roles":
            return (bool(required_tags & customer_tags), "role_miss")
        if mode == "percent":
            if required_tags and not tag_match:
                return False, "tag_required"
            percent = clamp_rollout_percent(release.get("rollout_percent"))
            if percent <= 0:
                return False, "rollout_miss"
            if percent >= 100:
                return True, "allowed"
            identity = customer.get("id") or customer.get("license_key_hash") or customer.get("email_normalized") or ""
            bucket = int(sha256_hex(f"{identity}:{release.get('id')}")[:8], 16) % 100
            return (bucket < percent, "rollout_miss")

        return False, "audience_denied"

    def _release_visible_to_customer(
        self,
        release: dict[str, Any],
        customer: dict[str, Any],
        requested_channel: str,
    ) -> tuple[bool, str]:
        audience_allowed, reason = self._release_audience_match(release, customer)
        if not audience_allowed:
            return False, reason

        release_channel = str(release.get("channel") or "stable").strip().lower()
        requested = str(requested_channel or "stable").strip().lower()
        release_priority = CHANNEL_PRIORITY.get(release_channel, 0)
        requested_priority = CHANNEL_PRIORITY.get(requested, 0)
        if release_priority <= requested_priority:
            return True, "allowed"

        customer_tags = set(json_list(customer.get("tags_json")))
        mode = str(release.get("audience_mode") or "all").strip().lower()
        if mode in {"allowlist", "roles"}:
            return True, "allowed"
        if "internal" in customer_tags and release_channel in {"beta", "canary", "internal"}:
            return True, "allowed"
        if customer_tags & {"tester", "desktop_beta", "duo_beta", "duorc_beta", "early_access"} and release_channel in {"beta", "canary"}:
            return True, "allowed"
        return False, "channel_denied"

    def _select_visible_releases(
        self,
        releases: list[dict[str, Any]],
        customer: dict[str, Any],
        requested_channel: str,
        *,
        group_by: str,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        visible_by_group: dict[str, dict[str, Any]] = {}
        denied: list[dict[str, Any]] = []
        for release in releases:
            allowed, reason = self._release_visible_to_customer(release, customer, requested_channel)
            if not allowed:
                denied.append({"release_id": release.get("id"), "reason": reason})
                continue
            group_value = str(release.get(group_by) or release.get("product_key") or release.get("product_id") or release.get("id"))
            existing = visible_by_group.get(group_value)
            if existing is None or self._release_sort_key(release) > self._release_sort_key(existing):
                visible_by_group[group_value] = release
        return list(visible_by_group.values()), denied

    def release_manifest(
        self,
        *,
        license_key: str | None,
        email: str | None,
        customer_id: str | None,
        whop_user_id: str | None,
        machine_fingerprint: str,
        app_version: str | None,
        channel: str,
        platform: str,
        include_types: list[str] | None = None,
        installed_packages: list[dict[str, Any]] | None = None,
        ip_address: str | None,
        user_agent: str | None,
        check_interval_seconds: int,
        grace_period_seconds: int,
        max_devices: int = 1,
    ) -> dict[str, Any]:
        license_response = self.check_license(
            license_key=license_key,
            email=email,
            customer_id=customer_id,
            whop_user_id=whop_user_id,
            machine_fingerprint=machine_fingerprint,
            app_version=app_version,
            ip_address=ip_address,
            user_agent=user_agent,
            check_interval_seconds=check_interval_seconds,
            grace_period_seconds=grace_period_seconds,
            max_devices=max_devices,
        )
        if license_response["status"] != "active":
            return {
                "status": license_response["status"],
                "message": license_response["message"],
                "server_time": iso(),
                "channel": channel or "stable",
                "platform": platform or DEFAULT_RELEASE_PLATFORM,
                "releases": [],
                "app_update": None,
                "license": license_response,
            }

        licensed_product_ids = {grant["product_id"] for grant in license_response["licensed_strategies"]}
        normalized_channel = (channel or "stable").strip().lower()
        normalized_platform = (platform or DEFAULT_RELEASE_PLATFORM).strip().lower()
        requested_types = normalize_release_types(include_types)
        installed_versions = self._installed_package_versions(installed_packages)
        strategy_rows: list[dict[str, Any]] = []
        app_release: dict[str, Any] | None = None
        denied_releases: list[dict[str, Any]] = []
        with self.database.session() as connection:
            customer_row = connection.execute("SELECT * FROM customers WHERE id = ?", (license_response["customer"]["id"],)).fetchone()
            if customer_row is None:
                return {
                    "status": "unknown_customer",
                    "message": "No customer matched the supplied license identifier.",
                    "server_time": iso(),
                    "channel": normalized_channel,
                    "platform": normalized_platform,
                    "releases": [],
                    "app_update": None,
                    "license": license_response,
                }
            customer = dict(customer_row)
            if STRATEGY_RELEASE_TYPE in requested_types:
                if licensed_product_ids:
                    rows = connection.execute(
                        """
                        SELECT trader_releases.*, products.name AS product_name, products.slug AS product_slug,
                               products.feature_id AS feature_id
                        FROM trader_releases
                        LEFT JOIN products ON products.id = trader_releases.product_id
                        WHERE trader_releases.is_active = 1
                          AND COALESCE(trader_releases.is_published, trader_releases.is_active) = 1
                          AND trader_releases.platform = ?
                          AND COALESCE(trader_releases.release_type, 'strategy_package') = 'strategy_package'
                          AND trader_releases.product_id IN ({placeholders})
                        ORDER BY trader_releases.updated_at DESC, trader_releases.created_at DESC
                        """.format(placeholders=",".join("?" for _ in licensed_product_ids)),
                        (normalized_platform, *licensed_product_ids),
                    ).fetchall()
                    selected, denied = self._select_visible_releases(
                        [dict(row) for row in rows],
                        customer,
                        normalized_channel,
                        group_by="product_id",
                    )
                    strategy_rows = selected
                    denied_releases.extend(denied)
            if TRADER_DESKTOP_RELEASE_TYPE in requested_types:
                app_rows = connection.execute(
                    """
                    SELECT trader_releases.*, products.name AS product_name, products.slug AS product_slug,
                           products.feature_id AS feature_id
                    FROM trader_releases
                    LEFT JOIN products ON products.id = trader_releases.product_id
                    WHERE trader_releases.is_active = 1
                      AND COALESCE(trader_releases.is_published, trader_releases.is_active) = 1
                      AND trader_releases.platform = ?
                      AND (
                        COALESCE(trader_releases.release_type, CASE WHEN trader_releases.scope = 'app' THEN 'trader_desktop' ELSE 'strategy_package' END) = 'trader_desktop'
                        OR trader_releases.scope = 'app'
                      )
                      AND COALESCE(trader_releases.product_key, 'trader-desktop') = ?
                    ORDER BY trader_releases.updated_at DESC, trader_releases.created_at DESC
                    """,
                    (normalized_platform, TRADER_DESKTOP_PRODUCT_ID),
                ).fetchall()
                selected, denied = self._select_visible_releases(
                    [dict(row) for row in app_rows],
                    customer,
                    normalized_channel,
                    group_by="product_key",
                )
                if selected:
                    app_release = selected[0]
                denied_releases.extend(denied)
            if denied_releases:
                self.audit(
                    connection,
                    "client",
                    customer["id"],
                    "release.manifest_audience_denied",
                    "customer",
                    customer["id"],
                    {"denied": denied_releases[:25], "channel": normalized_channel, "platform": normalized_platform},
                    ip_address,
                )

        releases = [
            self._release_manifest_item(
                release,
                self._current_version_for_release(release, app_version, installed_versions),
            )
            for release in strategy_rows
        ]
        releases.sort(key=lambda item: (item["scope"], item.get("strategy") or "", item["version"]))
        app_update = None
        if app_release:
            app_current_version = self._current_version_for_release(app_release, app_version, installed_versions)
            if release_action_for_row(app_release, app_current_version) != "current":
                app_update = self._trader_desktop_update_item(app_release, app_current_version)
        return {
            "status": "active",
            "message": "Release manifest available.",
            "server_time": iso(),
            "channel": normalized_channel,
            "platform": normalized_platform,
            "releases": releases,
            "app_update": app_update,
            "license": license_response,
        }

    def create_release_download_token(
        self,
        *,
        release_id: str,
        license_key: str | None,
        email: str | None,
        customer_id: str | None,
        whop_user_id: str | None,
        machine_fingerprint: str,
        app_version: str | None,
        channel: str = "stable",
        platform: str = DEFAULT_RELEASE_PLATFORM,
        installed_packages: list[dict[str, Any]] | None = None,
        ip_address: str | None,
        user_agent: str | None,
        check_interval_seconds: int,
        grace_period_seconds: int,
        token_seconds: int,
        max_devices: int = 1,
    ) -> dict[str, Any]:
        license_response = self.check_license(
            license_key=license_key,
            email=email,
            customer_id=customer_id,
            whop_user_id=whop_user_id,
            machine_fingerprint=machine_fingerprint,
            app_version=app_version,
            ip_address=ip_address,
            user_agent=user_agent,
            check_interval_seconds=check_interval_seconds,
            grace_period_seconds=grace_period_seconds,
            max_devices=max_devices,
        )
        if license_response["status"] != "active":
            return {
                "status": license_response["status"],
                "message": license_response["message"],
                "release": None,
                "token": None,
                "expires_at": None,
            }

        licensed_product_ids = {grant["product_id"] for grant in license_response["licensed_strategies"]}
        customer = license_response["customer"]
        device = license_response["device"]
        if not customer or not device:
            return {"status": "invalid_request", "message": "Customer or device was not resolved.", "release": None, "token": None, "expires_at": None}

        normalized_channel = (channel or "stable").strip().lower()
        normalized_platform = (platform or DEFAULT_RELEASE_PLATFORM).strip().lower()
        installed_versions = self._installed_package_versions(installed_packages)
        with self.database.session() as connection:
            release = connection.execute(
                """
                SELECT trader_releases.*, products.name AS product_name, products.slug AS product_slug,
                       products.feature_id AS feature_id
                FROM trader_releases
                LEFT JOIN products ON products.id = trader_releases.product_id
                WHERE trader_releases.id = ?
                  AND trader_releases.is_active = 1
                  AND COALESCE(trader_releases.is_published, trader_releases.is_active) = 1
                  AND trader_releases.platform = ?
                """,
                (release_id, normalized_platform),
            ).fetchone()
            if release is None:
                return {"status": "not_found", "message": "Release not found.", "release": None, "token": None, "expires_at": None}
            release_type = release["release_type"] or release_type_from_scope(release["scope"])
            if release_type == STRATEGY_RELEASE_TYPE and release["product_id"] not in licensed_product_ids:
                self._record_release_download(connection, dict(release), customer["id"], device["id"], None, "not_licensed", ip_address, user_agent)
                return {"status": "not_licensed", "message": "The license does not allow this release.", "release": None, "token": None, "expires_at": None}
            full_customer = connection.execute("SELECT * FROM customers WHERE id = ?", (customer["id"],)).fetchone()
            if full_customer is None:
                return {"status": "unknown_customer", "message": "Customer was not found.", "release": None, "token": None, "expires_at": None}
            release_dict = dict(release)
            allowed, reason = self._release_visible_to_customer(release_dict, dict(full_customer), normalized_channel)
            if not allowed:
                self._record_release_download(connection, release_dict, customer["id"], device["id"], None, "audience_denied", ip_address, user_agent)
                self.audit(
                    connection,
                    "client",
                    customer["id"],
                    "release.download_token_audience_denied",
                    "release",
                    release["id"],
                    {"device_id": device["id"], "reason": reason, "channel": normalized_channel, "platform": normalized_platform},
                    ip_address,
                )
                return {"status": "audience_denied", "message": "This license is not allowed to download this release.", "release": None, "token": None, "expires_at": None}

            token = random_token()
            token_hash = sha256_hex(token)
            expires = utc_now() + timedelta(seconds=max(60, token_seconds))
            connection.execute(
                """
                INSERT INTO release_download_tokens(token_hash, release_id, customer_id, device_id, expires_at, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (token_hash, release["id"], customer["id"], device["id"], iso(expires), iso()),
            )
            self.audit(
                connection,
                "client",
                customer["id"],
                "release.download_token_created",
                "release",
                release["id"],
                {"device_id": device["id"], "expires_at": iso(expires)},
                ip_address,
            )
            return {
                "status": "ok",
                "message": "Download token created.",
                "release": self._release_manifest_item(
                    release_dict,
                    self._current_version_for_release(release_dict, app_version, installed_versions),
                ),
                "token": token,
                "expires_at": iso(expires),
            }

    def resolve_release_download(
        self,
        *,
        token: str,
        artifact_dir: str,
        ip_address: str | None,
        user_agent: str | None,
    ) -> dict[str, Any]:
        token_hash = sha256_hex(token)
        with self.database.session() as connection:
            row = connection.execute(
                """
                SELECT release_download_tokens.*, trader_releases.*,
                       products.name AS product_name, products.slug AS product_slug,
                       products.feature_id AS feature_id
                FROM release_download_tokens
                JOIN trader_releases ON trader_releases.id = release_download_tokens.release_id
                LEFT JOIN products ON products.id = trader_releases.product_id
                WHERE release_download_tokens.token_hash = ?
                """,
                (token_hash,),
            ).fetchone()
            if row is None:
                return {"status": "invalid_token", "message": "Download token is invalid."}
            release = dict(row)
            if parse_time(row["expires_at"]) is None or parse_time(row["expires_at"]) <= utc_now():
                self._record_release_download(connection, release, row["customer_id"], row["device_id"], token_hash, "expired_token", ip_address, user_agent)
                return {"status": "expired_token", "message": "Download token has expired."}
            if not row["is_active"]:
                self._record_release_download(connection, release, row["customer_id"], row["device_id"], token_hash, "inactive_release", ip_address, user_agent)
                return {"status": "inactive_release", "message": "Release is no longer active."}
            artifact_file = self._artifact_path(row["artifact_path"], artifact_dir)
            if not artifact_file.exists() or not artifact_file.is_file():
                self._record_release_download(connection, release, row["customer_id"], row["device_id"], token_hash, "artifact_missing", ip_address, user_agent)
                return {"status": "artifact_missing", "message": "Release artifact is missing on the server."}
            connection.execute(
                "UPDATE release_download_tokens SET last_used_at = ? WHERE token_hash = ?",
                (iso(), token_hash),
            )
            self._record_release_download(connection, release, row["customer_id"], row["device_id"], token_hash, "served", ip_address, user_agent)
            return {
                "status": "ok",
                "release": self._release_manifest_item(release, None),
                "artifact_path": artifact_file,
                "artifact_filename": row["artifact_filename"],
                "size_bytes": artifact_file.stat().st_size,
            }

    def _release_manifest_item(self, release: dict[str, Any], current_version: str | None) -> dict[str, Any]:
        release_type = release.get("release_type") or release_type_from_scope(release.get("scope"))
        action = release_action_for_row(release, current_version)
        return {
            "id": release["id"],
            "scope": release["scope"],
            "release_type": release_type,
            "strategy": display_strategy_name(release.get("product_name")) if release.get("product_name") else None,
            "product_id": release.get("product_id"),
            "feature_id": release.get("feature_id"),
            "channel": release["channel"],
            "platform": release["platform"],
            "version": release["version"],
            "min_supported_version": release.get("min_supported_version"),
            "required": bool(release["is_required"]),
            "current_version": current_version,
            "target_version": release["version"],
            "action": action,
            "update_available": action != "current",
            "artifact": {
                "filename": release["artifact_filename"],
                "size_bytes": release.get("size_bytes"),
                "sha256": release.get("sha256"),
                "signature": release.get("signature"),
                "signature_key_id": release.get("signature_key_id"),
            },
            "release_notes": release.get("release_notes"),
            "rollback_reason": release.get("rollback_reason"),
        }

    def _trader_desktop_update_item(self, release: dict[str, Any], current_version: str | None) -> dict[str, Any]:
        action = release_action_for_row(release, current_version)
        return {
            "product_id": release.get("product_key") or TRADER_DESKTOP_PRODUCT_ID,
            "release_type": TRADER_DESKTOP_RELEASE_TYPE,
            "current_version": current_version,
            "available_version": release["version"],
            "target_version": release["version"],
            "update_available": action != "current",
            "action": action,
            "release_id": release["id"],
            "channel": release["channel"],
            "platform": release["platform"],
            "min_supported_version": release.get("min_supported_version"),
            "required": bool(release.get("is_required")),
            "artifact": {
                "filename": release["artifact_filename"],
                "size_bytes": release.get("size_bytes"),
                "sha256": release.get("sha256"),
                "signature": release.get("signature"),
                "signature_key_id": release.get("signature_key_id"),
            },
            "release_notes": release.get("release_notes"),
            "rollback_reason": release.get("rollback_reason"),
        }

    def _record_release_download(
        self,
        connection: sqlite3.Connection,
        release: dict[str, Any],
        customer_id: str | None,
        device_id: str | None,
        token_hash: str | None,
        status: str,
        ip_address: str | None,
        user_agent: str | None,
    ) -> None:
        connection.execute(
            """
            INSERT INTO release_downloads(id, release_id, customer_id, device_id, token_hash, status, ip_address, user_agent, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (uuid.uuid4().hex, release.get("id"), customer_id, device_id, token_hash, status, ip_address, user_agent, iso()),
        )

    def _artifact_path(self, artifact_path: str, artifact_dir: str) -> Path:
        base = Path(artifact_dir).resolve()
        raw_path = Path(artifact_path)
        candidate = raw_path if raw_path.is_absolute() else base / raw_path
        resolved = candidate.resolve()
        if not resolved.is_relative_to(base):
            raise ValueError("Artifact path must stay inside AUTOEDGE_RELEASE_ARTIFACT_DIR.")
        return resolved

    def check_license(
        self,
        *,
        license_key: str | None,
        email: str | None,
        customer_id: str | None,
        whop_user_id: str | None,
        machine_fingerprint: str,
        app_version: str | None,
        ip_address: str | None,
        user_agent: str | None,
        check_interval_seconds: int,
        grace_period_seconds: int,
        max_devices: int = 1,
    ) -> dict[str, Any]:
        if not machine_fingerprint or not machine_fingerprint.strip():
            return self._license_response("invalid_request", "machine_fingerprint is required", [], check_interval_seconds, grace_period_seconds)

        with self.database.session() as connection:
            customer = self._find_customer(connection, license_key, email, customer_id, whop_user_id)
            if customer is None:
                response = self._license_response("unknown_customer", "No customer matched the supplied license identifier.", [], check_interval_seconds, grace_period_seconds)
                self._record_check(connection, None, None, email or customer_id or whop_user_id or "license_key", app_version, ip_address, user_agent, response)
                return response

            device = self._upsert_device(connection, customer["id"], machine_fingerprint, app_version, ip_address, user_agent)
            device_limit = self._device_limit_snapshot(connection, customer, device, max_devices)
            if device["is_blocked"]:
                response = self._license_response("device_blocked", "This machine is blocked for the license.", [], check_interval_seconds, grace_period_seconds, customer, device, device_limit)
                self._record_check(connection, customer["id"], device["id"], customer["email"] or customer["id"], app_version, ip_address, user_agent, response)
                return response

            grants = self._current_grants(connection, customer["id"])
            licensed = [grant for grant in grants if grant["is_licensed"]]
            if licensed:
                if not device_limit["device_is_counted"] and device_limit["active_devices"] >= device_limit["max_devices"]:
                    response = self._license_response(
                        "device_limit_exceeded",
                        "This license is already active on the maximum number of machines.",
                        [],
                        check_interval_seconds,
                        grace_period_seconds,
                        customer,
                        device,
                        device_limit,
                    )
                    self.audit(
                        connection,
                        "client",
                        customer["id"],
                        "device.limit_exceeded",
                        "device",
                        device["id"],
                        {
                            "customer_id": customer["id"],
                            "fingerprint_last8": device["fingerprint_last8"],
                            "active_devices": device_limit["active_devices"],
                            "max_devices": device_limit["max_devices"],
                        },
                        ip_address,
                    )
                    self._record_check(connection, customer["id"], device["id"], customer["email"] or customer["id"], app_version, ip_address, user_agent, response)
                    return response
                device = self._mark_device_licensed(connection, device["id"])
                device_limit = self._device_limit_snapshot(connection, customer, device, max_devices)
                status = "active"
                message = "License active."
            else:
                status, message = self._blocking_status(grants)
            response = self._license_response(status, message, licensed, check_interval_seconds, grace_period_seconds, customer, device, device_limit)
            self._record_check(connection, customer["id"], device["id"], customer["email"] or customer["id"], app_version, ip_address, user_agent, response)
            return response

    def _license_response(
        self,
        status: str,
        message: str,
        grants: list[dict[str, Any]],
        check_interval_seconds: int,
        grace_period_seconds: int,
        customer: sqlite3.Row | dict[str, Any] | None = None,
        device: sqlite3.Row | dict[str, Any] | None = None,
        device_limit: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        now = utc_now()
        expiry_values = [parse_time(grant.get("expires_at")) for grant in grants if grant.get("expires_at")]
        expiry_values = [value for value in expiry_values if value is not None]
        customer_dict = dict(customer) if customer is not None else None
        device_dict = dict(device) if device is not None else None
        return {
            "status": status,
            "message": message,
            "server_time": iso(now),
            "customer": {
                "id": customer_dict["id"],
                "email": customer_dict["email"],
                "whop_user_id": customer_dict["whop_user_id"],
                "license_key_last4": customer_dict["license_key_last4"],
                "tags": json_list(customer_dict.get("tags_json")),
            }
            if customer_dict
            else None,
            "device": {
                "id": device_dict["id"],
                "fingerprint_last8": device_dict["fingerprint_last8"],
                "is_blocked": bool(device_dict["is_blocked"]),
            }
            if device_dict
            else None,
            "licensed_strategies": [
                {
                    "product_id": grant["product_id"],
                    "slug": grant["slug"],
                    "name": grant["name"],
                    "feature_id": grant["feature_id"],
                    "status": grant["status"],
                    "source": grant["source"],
                    "expires_at": grant["expires_at"],
                }
                for grant in grants
            ],
            "expires_at": iso(min(expiry_values)) if expiry_values else None,
            "next_check_at": iso(now + timedelta(seconds=check_interval_seconds)),
            "next_check_seconds": check_interval_seconds,
            "grace_period_seconds": grace_period_seconds,
            "device_limit": device_limit,
        }

    def _record_check(
        self,
        connection: sqlite3.Connection,
        customer_id: str | None,
        device_id: str | None,
        identifier: str | None,
        app_version: str | None,
        ip_address: str | None,
        user_agent: str | None,
        response: dict[str, Any],
    ) -> None:
        connection.execute(
            """
            INSERT INTO license_checks(
                id, customer_id, device_id, request_identifier, app_version, ip_address, user_agent, status, response_json, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                uuid.uuid4().hex,
                customer_id,
                device_id,
                identifier,
                app_version,
                ip_address,
                user_agent,
                response["status"],
                json.dumps(response, sort_keys=True),
                iso(),
            ),
        )

    def _find_customer(
        self,
        connection: sqlite3.Connection,
        license_key: str | None,
        email: str | None,
        customer_id: str | None,
        whop_user_id: str | None,
    ) -> sqlite3.Row | None:
        if license_key:
            row = connection.execute("SELECT * FROM customers WHERE license_key_hash = ?", (hash_license_key(license_key),)).fetchone()
            if row:
                return row
        if customer_id:
            row = connection.execute("SELECT * FROM customers WHERE id = ?", (customer_id.strip(),)).fetchone()
            if row:
                return row
        normalized_email = normalize_email(email)
        if normalized_email:
            row = connection.execute("SELECT * FROM customers WHERE email_normalized = ?", (normalized_email,)).fetchone()
            if row:
                return row
        if whop_user_id:
            row = connection.execute("SELECT * FROM customers WHERE whop_user_id = ?", (whop_user_id.strip(),)).fetchone()
            if row:
                return row
        return None

    def _upsert_device(
        self,
        connection: sqlite3.Connection,
        customer_id: str,
        machine_fingerprint: str,
        app_version: str | None,
        ip_address: str | None,
        user_agent: str | None,
    ) -> sqlite3.Row:
        fingerprint_hash = hash_fingerprint(machine_fingerprint)
        last8 = fingerprint_hash[-8:]
        now = iso()
        existing = connection.execute(
            "SELECT * FROM devices WHERE customer_id = ? AND fingerprint_hash = ?",
            (customer_id, fingerprint_hash),
        ).fetchone()
        if existing is None:
            device_id = uuid.uuid4().hex
            connection.execute(
                """
                INSERT INTO devices(
                    id, customer_id, fingerprint_hash, fingerprint_last8, first_seen_at,
                    last_seen_at, app_version, ip_last, user_agent_last
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (device_id, customer_id, fingerprint_hash, last8, now, now, app_version, ip_address, user_agent),
            )
            self.audit(connection, "client", customer_id, "device.created", "device", device_id, {"customer_id": customer_id, "fingerprint_last8": last8}, ip_address)
        else:
            device_id = existing["id"]
            connection.execute(
                """
                UPDATE devices
                SET last_seen_at = ?, app_version = COALESCE(?, app_version), ip_last = ?, user_agent_last = ?
                WHERE id = ?
                """,
                (now, app_version, ip_address, user_agent, device_id),
            )
        return connection.execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()

    def _effective_max_devices(self, customer: sqlite3.Row | dict[str, Any], default_max_devices: int) -> int:
        customer_dict = dict(customer)
        override = customer_dict.get("max_devices")
        if override is not None:
            return max(1, int(override))
        return max(1, int(default_max_devices))

    def _active_device_count(self, connection: sqlite3.Connection, customer_id: str) -> int:
        return int(
            connection.execute(
                """
                SELECT COUNT(*)
                FROM devices
                WHERE customer_id = ?
                  AND is_blocked = 0
                  AND first_licensed_at IS NOT NULL
                """,
                (customer_id,),
            ).fetchone()[0]
        )

    def _device_limit_snapshot(
        self,
        connection: sqlite3.Connection,
        customer: sqlite3.Row | dict[str, Any],
        device: sqlite3.Row | dict[str, Any],
        default_max_devices: int,
    ) -> dict[str, Any]:
        customer_dict = dict(customer)
        device_dict = dict(device)
        active_devices = self._active_device_count(connection, customer_dict["id"])
        return {
            "active_devices": active_devices,
            "max_devices": self._effective_max_devices(customer, default_max_devices),
            "device_is_counted": bool(device_dict.get("first_licensed_at")) and not bool(device_dict.get("is_blocked")),
        }

    def _mark_device_licensed(self, connection: sqlite3.Connection, device_id: str) -> sqlite3.Row:
        now = iso()
        connection.execute(
            """
            UPDATE devices
            SET first_licensed_at = COALESCE(first_licensed_at, ?),
                last_licensed_at = ?
            WHERE id = ?
            """,
            (now, now, device_id),
        )
        return connection.execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()

    def _current_grants(self, connection: sqlite3.Connection, customer_id: str) -> list[dict[str, Any]]:
        rows = connection.execute(
            """
            SELECT entitlements.*, products.id AS product_id, products.slug, products.name, products.feature_id, products.is_active
            FROM entitlements
            JOIN products ON products.id = entitlements.product_id
            WHERE entitlements.customer_id = ?
            ORDER BY products.name ASC, entitlements.updated_at DESC
            """,
            (customer_id,),
        ).fetchall()
        now = utc_now()
        grants: list[dict[str, Any]] = []
        for row in rows:
            grant = dict(row)
            starts_at = parse_time(grant.get("starts_at"))
            expires_at = parse_time(grant.get("expires_at"))
            revoked_at = parse_time(grant.get("revoked_at"))
            grant["is_licensed"] = (
                bool(grant["is_active"])
                and grant["status"] in ACTIVE_ENTITLEMENT_STATUSES
                and revoked_at is None
                and (starts_at is None or starts_at <= now)
                and (expires_at is None or expires_at > now)
            )
            grants.append(grant)
        best_by_product: dict[str, dict[str, Any]] = {}
        for grant in grants:
            existing = best_by_product.get(grant["product_id"])
            if existing is None or grant["is_licensed"] or not existing["is_licensed"]:
                best_by_product[grant["product_id"]] = grant
        return list(best_by_product.values())

    def _blocking_status(self, grants: list[dict[str, Any]]) -> tuple[str, str]:
        statuses = {grant["status"] for grant in grants}
        now = utc_now()
        if "revoked" in statuses or any(parse_time(grant.get("revoked_at")) is not None for grant in grants):
            return "revoked", "License access has been revoked."
        if "suspended" in statuses:
            return "suspended", "License access is suspended."
        if grants and (
            "expired" in statuses
            or all(parse_time(grant.get("expires_at")) and parse_time(grant.get("expires_at")) <= now for grant in grants)
        ):
            return "expired", "License access has expired."
        return "unlicensed", "No active strategy entitlement is available."

    def _extract_customer_info(self, data: dict[str, Any]) -> dict[str, str | None]:
        user = nested_dict(data, "user") or nested_dict(data, "customer") or nested_dict(data, "member") or {}
        return {
            "email": first_text(data, "email", "customer_email", "user_email") or first_text(user, "email"),
            "name": first_text(data, "name", "customer_name") or first_text(user, "name", "username"),
            "whop_user_id": first_text(data, "whop_user_id", "user_id") or first_text(user, "id", "user_id"),
            "whop_member_id": first_text(data, "whop_member_id", "member_id", "membership_id") or first_text(user, "member_id"),
        }

    def _extract_product_info(self, data: dict[str, Any]) -> dict[str, str | None]:
        subscription = nested_dict(data, "subscription") or nested_dict(data, "membership") or {}
        product = nested_dict(data, "product") or nested_dict(data, "access_pass") or nested_dict(subscription, "product") or {}
        whop_product_id = first_text(data, "whop_product_id", "product_id", "access_pass_id") or first_text(product, "id", "product_id")
        product_name = first_text(data, "product_name") or first_text(product, "name", "title") or whop_product_id or "AutoEdge Strategy"
        slug = first_text(data, "product_slug", "strategy_slug") or slugify(product_name)
        feature_id = first_text(data, "feature_id") or f"strategy.{slugify(slug)}.runtime"
        return {
            "whop_product_id": whop_product_id,
            "slug": slug,
            "name": product_name,
            "feature_id": feature_id,
        }

    def _extract_whop_ids(self, data: dict[str, Any]) -> dict[str, str | None]:
        subscription = nested_dict(data, "subscription") or nested_dict(data, "membership") or {}
        plan = nested_dict(data, "plan") or nested_dict(subscription, "plan") or {}
        product = nested_dict(data, "product") or nested_dict(data, "access_pass") or nested_dict(subscription, "product") or {}
        plan_id = (
            first_text(data, "plan_id")
            or first_text(subscription, "plan_id", "price_id")
            or first_text(plan, "id", "plan_id", "price_id")
        )
        product_id = (
            first_text(data, "whop_product_id", "product_id", "access_pass_id")
            or first_text(product, "id", "product_id", "access_pass_id")
        )
        return {
            "plan_id": plan_id,
            "product_id": product_id,
            "selected_id": plan_id or product_id,
            "selected_type": "plan" if plan_id else ("product" if product_id else None),
        }

    def _extract_subscription_info(self, data: dict[str, Any], event_type: str) -> dict[str, Any]:
        subscription = nested_dict(data, "subscription") or nested_dict(data, "membership") or {}
        payment = nested_dict(data, "payment") or nested_dict(data, "invoice") or {}
        plan = nested_dict(data, "plan") or nested_dict(subscription, "plan") or nested_dict(payment, "plan") or {}
        event_is_membership = any(
            key in data
            for key in ("plan_id", "product_id", "trial_ends_at", "renewal_period_end", "valid_until")
        )
        payment_like_event = event_type.lower().startswith(("payment.", "invoice.", "charge."))
        membership_id = (
            first_text(data, "membership_id", "subscription_id")
            or first_text(subscription, "id", "membership_id")
            or (first_text(data, "id") if event_is_membership else None)
        )
        raw_status = (
            first_text(subscription, "status")
            or first_text(data, "status")
            or first_text(payment, "status")
            or "unknown"
        )
        substatus = first_text(data, "substatus") or first_text(payment, "substatus")
        if substatus and substatus.lower() not in raw_status.lower():
            raw_status = f"{raw_status} {substatus}"
        payment_id = (
            first_text(data, "payment_id", "invoice_id", "charge_id")
            or first_text(payment, "id", "payment_id", "invoice_id", "charge_id")
            or (first_text(data, "id") if payment_like_event else None)
        )
        return {
            "membership_id": membership_id,
            "entitlement_id": first_text(data, "entitlement_id", "id"),
            "plan_id": (
                first_text(data, "plan_id")
                or first_text(subscription, "plan_id", "price_id")
                or first_text(plan, "id", "plan_id", "price_id")
            ),
            "status": raw_status,
            "period_start": first_time(data, "current_period_start", "renewal_period_start", "starts_at", "created_at")
            or first_time(subscription, "current_period_start", "starts_at", "created_at"),
            "expires_at": first_time(data, "current_period_end", "expires_at", "expiration_date", "valid_until", "renewal_period_end")
            or first_time(subscription, "current_period_end", "expires_at", "expiration_date", "valid_until"),
            "trial_ends_at": first_time(data, "trial_ends_at")
            or first_time(subscription, "trial_ends_at"),
            "payment_id": payment_id,
            "cancel_at_period_end": bool(data.get("cancel_at_period_end") or subscription.get("cancel_at_period_end") or False),
        }

    def audit(
        self,
        connection: sqlite3.Connection,
        actor_type: str,
        actor_id: str | None,
        action: str,
        entity_type: str | None,
        entity_id: str | None,
        details: dict[str, Any] | None,
        ip_address: str | None = None,
    ) -> None:
        connection.execute(
            """
            INSERT INTO audit_log(id, actor_type, actor_id, action, entity_type, entity_id, details_json, ip_address, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                uuid.uuid4().hex,
                actor_type,
                actor_id,
                action,
                entity_type,
                entity_id,
                json.dumps(details, sort_keys=True) if details is not None else None,
                ip_address,
                iso(),
            ),
        )


def nested_dict(data: dict[str, Any], key: str) -> dict[str, Any] | None:
    value = data.get(key)
    return value if isinstance(value, dict) else None


def first_text(data: dict[str, Any], *keys: str) -> str | None:
    for key in keys:
        value = data.get(key)
        if value is None:
            continue
        text = str(value).strip()
        if text:
            return text
    return None


def first_time(data: dict[str, Any], *keys: str) -> datetime | None:
    for key in keys:
        parsed = parse_time(data.get(key))
        if parsed:
            return parsed
    return None


def later_time(left: datetime | None, right: datetime | None) -> datetime | None:
    if left is None:
        return right
    if right is None:
        return left
    return left if left >= right else right


def ceil_days(delta: timedelta) -> int:
    seconds = max(0, int(delta.total_seconds()))
    return max(1, (seconds + 86399) // 86400) if seconds else 0


def normalize_entitlement_status(raw_status: str | None, event_type: str) -> str:
    combined = f"{raw_status or ''} {event_type}".lower()
    event = event_type.lower().replace("_", ".")
    if any(word in combined for word in ("refund", "chargeback", "dispute", "revoke", "ban", "terminate", "went_invalid")):
        return "revoked"
    if (
        any(word in combined for word in ("suspend", "pause", "past_due", "payment_failed", "payment failed", "failed_payment", "failed payment"))
        or event in {"payment.failed", "invoice.payment.failed", "charge.failed"}
    ):
        return "suspended"
    if any(word in combined for word in ("expire", "cancel", "inactive", "invalid")):
        return "expired"
    if (
        any(word in combined for word in ("active", "valid", "renew", "paid", "succeeded", "completed"))
        or event in {"payment.succeeded", "invoice.payment.succeeded", "charge.succeeded"}
        or "went_valid" in event
    ):
        return "active"
    if "trial" in combined:
        return "trialing"
    return "pending"


def normalize_subscription_status(raw_status: str | None, event_type: str) -> str:
    entitlement_status = normalize_entitlement_status(raw_status, event_type)
    if entitlement_status == "active":
        return "active"
    if entitlement_status == "trialing":
        return "trialing"
    if entitlement_status == "suspended":
        return "past_due" if "past_due" in f"{raw_status or ''} {event_type}".lower() else "suspended"
    if entitlement_status == "revoked":
        return "revoked"
    if entitlement_status == "expired":
        return "expired"
    return "unknown"
