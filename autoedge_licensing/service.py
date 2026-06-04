from __future__ import annotations

import json
import re
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
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

    def customer_detail(self, customer_id: str) -> dict[str, Any] | None:
        with self.database.session() as connection:
            customer = connection.execute("SELECT * FROM customers WHERE id = ?", (customer_id,)).fetchone()
            if customer is None:
                return None
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
            "entitlements": [dict(row) for row in entitlements],
            "subscriptions": [dict(row) for row in subscriptions],
            "devices": [dict(row) for row in devices],
            "checks": [dict(row) for row in checks],
            "audit": [dict(row) for row in audit],
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
                    (entitlement_id, customer_id, product_id, external_id, status, now, iso(parsed_expiry) if parsed_expiry else None, revoked_at, reason, now, now),
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
                    (status, iso(parsed_expiry) if parsed_expiry else None, revoked_at, reason, now, entitlement_id),
                )
                action = "entitlement.manual_updated"
            self.audit(
                connection,
                "admin",
                actor_id,
                action,
                "entitlement",
                entitlement_id,
                {"customer_id": customer_id, "product_id": product_id, "status": status, "expires_at": expires_at},
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

    def process_whop_event(self, payload: dict[str, Any], webhook_id: str, *, signature_valid: bool, ip_address: str | None) -> dict[str, Any]:
        event_type = str(payload.get("type") or payload.get("event") or payload.get("event_type") or "unknown")
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
        product_info = self._extract_product_info(data)
        subscription_info = self._extract_subscription_info(data)
        customer_result = self.create_or_update_customer(
            email=customer_info["email"],
            name=customer_info["name"],
            whop_user_id=customer_info["whop_user_id"],
            whop_member_id=customer_info["whop_member_id"],
            actor_type="whop",
            ip_address=ip_address,
        )
        product = self.upsert_product(
            slug=product_info["slug"],
            name=product_info["name"],
            feature_id=product_info["feature_id"],
            whop_product_id=product_info["whop_product_id"],
            metadata={"source": "whop", "event_type": event_type},
        )
        status = normalize_entitlement_status(subscription_info["status"], event_type)
        sub_status = normalize_subscription_status(subscription_info["status"], event_type)
        now = iso()
        with self.database.session() as connection:
            subscription_id = None
            if subscription_info["membership_id"]:
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
                            customer_result.customer["id"],
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
                else:
                    subscription_id = existing_sub["id"]
                    connection.execute(
                        """
                        UPDATE subscriptions
                        SET customer_id = ?, whop_plan_id = COALESCE(?, whop_plan_id), status = ?, raw_status = ?,
                            current_period_start = ?, current_period_end = ?, cancel_at_period_end = ?, updated_at = ?
                        WHERE id = ?
                        """,
                        (
                            customer_result.customer["id"],
                            subscription_info["plan_id"],
                            sub_status,
                            subscription_info["status"],
                            iso(subscription_info["period_start"]) if subscription_info["period_start"] else None,
                            iso(subscription_info["expires_at"]) if subscription_info["expires_at"] else None,
                            int(subscription_info["cancel_at_period_end"]),
                            now,
                            subscription_id,
                        ),
                    )
            external_id = subscription_info["entitlement_id"] or subscription_info["membership_id"] or webhook_id
            existing_entitlement = connection.execute(
                "SELECT * FROM entitlements WHERE source = 'whop' AND external_id = ?",
                (external_id,),
            ).fetchone()
            revoked_at = now if status == "revoked" else None
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
                        customer_result.customer["id"],
                        product["id"],
                        subscription_id,
                        external_id,
                        status,
                        iso(subscription_info["period_start"]) if subscription_info["period_start"] else now,
                        iso(subscription_info["expires_at"]) if subscription_info["expires_at"] else None,
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
                        customer_result.customer["id"],
                        product["id"],
                        subscription_id,
                        status,
                        iso(subscription_info["period_start"]) if subscription_info["period_start"] else None,
                        iso(subscription_info["expires_at"]) if subscription_info["expires_at"] else None,
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
                {
                    "customer_id": customer_result.customer["id"],
                    "product_id": product["id"],
                    "status": status,
                    "event_type": event_type,
                    "webhook_id": webhook_id,
                },
                ip_address,
            )
        return {"status": "processed", "customer_id": customer_result.customer["id"], "product_id": product["id"], "entitlement_status": status}

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
            if device["is_blocked"]:
                response = self._license_response("device_blocked", "This machine is blocked for the license.", [], check_interval_seconds, grace_period_seconds, customer, device)
                self._record_check(connection, customer["id"], device["id"], customer["email"] or customer["id"], app_version, ip_address, user_agent, response)
                return response

            grants = self._current_grants(connection, customer["id"])
            licensed = [grant for grant in grants if grant["is_licensed"]]
            if licensed:
                status = "active"
                message = "License active."
            else:
                status, message = self._blocking_status(grants)
            response = self._license_response(status, message, licensed, check_interval_seconds, grace_period_seconds, customer, device)
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
        product = nested_dict(data, "product") or nested_dict(data, "access_pass") or {}
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

    def _extract_subscription_info(self, data: dict[str, Any]) -> dict[str, Any]:
        subscription = nested_dict(data, "subscription") or nested_dict(data, "membership") or {}
        return {
            "membership_id": first_text(data, "membership_id", "subscription_id") or first_text(subscription, "id", "membership_id"),
            "entitlement_id": first_text(data, "entitlement_id", "id"),
            "plan_id": first_text(data, "plan_id") or first_text(subscription, "plan_id", "price_id"),
            "status": first_text(data, "status") or first_text(subscription, "status") or "unknown",
            "period_start": first_time(data, "current_period_start", "starts_at", "created_at")
            or first_time(subscription, "current_period_start", "starts_at", "created_at"),
            "expires_at": first_time(data, "current_period_end", "expires_at", "expiration_date", "valid_until", "renewal_period_end")
            or first_time(subscription, "current_period_end", "expires_at", "expiration_date", "valid_until"),
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


def normalize_entitlement_status(raw_status: str | None, event_type: str) -> str:
    combined = f"{raw_status or ''} {event_type}".lower()
    if any(word in combined for word in ("revoke", "ban", "terminate")):
        return "revoked"
    if any(word in combined for word in ("suspend", "pause", "past_due", "payment_failed")):
        return "suspended"
    if any(word in combined for word in ("expire", "cancel", "inactive", "invalid")):
        return "expired"
    if "trial" in combined:
        return "trialing"
    if any(word in combined for word in ("active", "valid", "create", "update", "renew")):
        return "active"
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
