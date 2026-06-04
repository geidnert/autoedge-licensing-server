from __future__ import annotations

import tempfile
import unittest
from datetime import timedelta

from autoedge_licensing.db import Database, apply_migrations
from autoedge_licensing.service import LicensingService, iso, utc_now


class LicensingServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.database = Database(f"{self.tmp.name}/test.db")
        apply_migrations(self.database)
        self.service = LicensingService(self.database)
        self.product = self.service.upsert_product(
            slug="duo-runtime",
            name="Duo Runtime",
            feature_id="strategy.duo.runtime",
            whop_product_id="prod_duo",
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_manual_active_grant_returns_licensed_strategy(self) -> None:
        created = self.service.create_or_update_customer(email="alice@example.com", name="Alice")
        self.service.manual_set_entitlement(
            customer_id=created.customer["id"],
            product_id=self.product["id"],
            status="active",
            expires_at=iso(utc_now() + timedelta(days=30)),
            reason="support grant",
            actor_id="admin",
            ip_address="127.0.0.1",
        )

        response = self.service.check_license(
            license_key=created.license_key,
            email=None,
            customer_id=None,
            whop_user_id=None,
            machine_fingerprint="machine-001",
            app_version="0.5.0",
            ip_address="127.0.0.1",
            user_agent="test",
            check_interval_seconds=3600,
            grace_period_seconds=86400,
        )

        self.assertEqual("active", response["status"])
        self.assertEqual(["strategy.duo.runtime"], [grant["feature_id"] for grant in response["licensed_strategies"]])
        self.assertEqual(3600, response["next_check_seconds"])
        self.assertEqual(86400, response["grace_period_seconds"])

    def test_expired_grant_returns_expired_without_strategies(self) -> None:
        created = self.service.create_or_update_customer(email="expired@example.com")
        self.service.manual_set_entitlement(
            customer_id=created.customer["id"],
            product_id=self.product["id"],
            status="expired",
            expires_at=iso(utc_now() - timedelta(days=1)),
            reason="manual expiry",
            actor_id="admin",
            ip_address=None,
        )

        response = self.service.check_license(
            license_key=created.license_key,
            email=None,
            customer_id=None,
            whop_user_id=None,
            machine_fingerprint="machine-002",
            app_version=None,
            ip_address=None,
            user_agent=None,
            check_interval_seconds=3600,
            grace_period_seconds=86400,
        )

        self.assertEqual("expired", response["status"])
        self.assertEqual([], response["licensed_strategies"])

    def test_revoked_grant_returns_revoked_without_strategies(self) -> None:
        created = self.service.create_or_update_customer(email="revoked@example.com")
        self.service.manual_set_entitlement(
            customer_id=created.customer["id"],
            product_id=self.product["id"],
            status="revoked",
            expires_at=None,
            reason="chargeback",
            actor_id="admin",
            ip_address=None,
        )

        response = self.service.check_license(
            license_key=created.license_key,
            email=None,
            customer_id=None,
            whop_user_id=None,
            machine_fingerprint="machine-003",
            app_version=None,
            ip_address=None,
            user_agent=None,
            check_interval_seconds=3600,
            grace_period_seconds=86400,
        )

        self.assertEqual("revoked", response["status"])
        self.assertEqual([], response["licensed_strategies"])

    def test_whop_upsert_is_idempotent_and_activates_customer(self) -> None:
        payload = {
            "type": "membership.created",
            "data": {
                "id": "ent_001",
                "membership_id": "mem_001",
                "status": "active",
                "email": "whop@example.com",
                "user_id": "user_001",
                "product_id": "prod_duo",
                "product_name": "Duo Runtime",
                "product_slug": "duo-runtime",
                "feature_id": "strategy.duo.runtime",
                "current_period_end": iso(utc_now() + timedelta(days=10)),
            },
        }

        first = self.service.process_whop_event(payload, "evt_001", signature_valid=True, ip_address="127.0.0.1")
        second = self.service.process_whop_event(payload, "evt_001", signature_valid=True, ip_address="127.0.0.1")
        detail = self.service.customer_detail(first["customer_id"])

        self.assertEqual("processed", first["status"])
        self.assertEqual("duplicate", second["status"])
        self.assertIsNotNone(detail)
        self.assertEqual(1, len(detail["entitlements"]))
        self.assertEqual("active", detail["entitlements"][0]["status"])

    def test_update_product_adds_whop_product_id_to_existing_product(self) -> None:
        product = self.service.upsert_product(
            slug="duorc-runtime",
            name="DUOrc Runtime",
            feature_id="strategy.duorc.runtime",
        )

        updated = self.service.update_product(
            product_id=product["id"],
            slug="duorc-runtime",
            name="DUOrc Runtime",
            feature_id="strategy.duorc.runtime",
            whop_product_id="prod_duorc",
            is_active=True,
            actor_id="admin",
            ip_address="127.0.0.1",
        )

        self.assertEqual(product["id"], updated["id"])
        self.assertEqual("prod_duorc", updated["whop_product_id"])
        self.assertEqual(2, len(self.service.list_products()))

    def test_change_admin_password_revokes_sessions_and_accepts_new_password(self) -> None:
        admin_id = self.service.create_admin_user("admin", "old-password-123")
        first_login = self.service.authenticate_admin(
            "admin",
            "old-password-123",
            session_hours=12,
            ip_address="127.0.0.1",
            user_agent="test",
        )
        self.assertIsNotNone(first_login)
        _, old_session_token = first_login

        changed, message = self.service.change_admin_password(
            admin_id=admin_id,
            current_password="old-password-123",
            new_password="new-password-456",
            ip_address="127.0.0.1",
        )

        self.assertTrue(changed, message)
        self.assertIsNone(self.service.admin_from_session(old_session_token))
        self.assertIsNone(
            self.service.authenticate_admin(
                "admin",
                "old-password-123",
                session_hours=12,
                ip_address="127.0.0.1",
                user_agent="test",
            )
        )
        self.assertIsNotNone(
            self.service.authenticate_admin(
                "admin",
                "new-password-456",
                session_hours=12,
                ip_address="127.0.0.1",
                user_agent="test",
            )
        )

    def test_change_admin_password_rejects_wrong_current_password(self) -> None:
        admin_id = self.service.create_admin_user("admin", "old-password-123")

        changed, message = self.service.change_admin_password(
            admin_id=admin_id,
            current_password="wrong-password",
            new_password="new-password-456",
            ip_address="127.0.0.1",
        )

        self.assertFalse(changed)
        self.assertIn("Current password", message)
        self.assertIsNotNone(
            self.service.authenticate_admin(
                "admin",
                "old-password-123",
                session_hours=12,
                ip_address="127.0.0.1",
                user_agent="test",
            )
        )


if __name__ == "__main__":
    unittest.main()
