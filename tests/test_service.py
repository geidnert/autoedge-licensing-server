from __future__ import annotations

import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

from autoedge_licensing.db import Database, apply_migrations
from autoedge_licensing.service import LicensingService, iso, parse_time, utc_now


class LicensingServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.database = Database(f"{self.tmp.name}/test.db")
        apply_migrations(self.database)
        self.service = LicensingService(self.database)
        self.product = self.service.upsert_product(
            slug="duo-runtime",
            name="DUO Runtime",
            feature_id="strategy.duo.runtime",
            whop_product_id="prod_duo",
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def active_customer(self, email: str = "active@example.com"):
        created = self.service.create_or_update_customer(email=email)
        self.service.manual_set_entitlement(
            customer_id=created.customer["id"],
            product_id=self.product["id"],
            status="active",
            expires_at=iso(utc_now() + timedelta(days=30)),
            reason="test grant",
            actor_id="admin",
            ip_address=None,
        )
        return created

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

    def test_device_limit_allows_first_device_and_same_device(self) -> None:
        created = self.active_customer("one-device@example.com")

        first = self.service.check_license(
            license_key=created.license_key,
            email=None,
            customer_id=None,
            whop_user_id=None,
            machine_fingerprint="machine-one",
            app_version="1.0.0",
            ip_address=None,
            user_agent=None,
            check_interval_seconds=3600,
            grace_period_seconds=86400,
            max_devices=1,
        )
        repeated = self.service.check_license(
            license_key=created.license_key,
            email=None,
            customer_id=None,
            whop_user_id=None,
            machine_fingerprint="machine-one",
            app_version="1.0.1",
            ip_address=None,
            user_agent=None,
            check_interval_seconds=3600,
            grace_period_seconds=86400,
            max_devices=1,
        )

        self.assertEqual("active", first["status"])
        self.assertEqual("active", repeated["status"])
        self.assertEqual(1, repeated["device_limit"]["active_devices"])
        self.assertTrue(repeated["device_limit"]["device_is_counted"])

    def test_device_limit_blocks_second_new_device(self) -> None:
        created = self.active_customer("second-device@example.com")
        self.service.check_license(
            license_key=created.license_key,
            email=None,
            customer_id=None,
            whop_user_id=None,
            machine_fingerprint="machine-first",
            app_version="1.0.0",
            ip_address="127.0.0.1",
            user_agent=None,
            check_interval_seconds=3600,
            grace_period_seconds=86400,
            max_devices=1,
        )

        second = self.service.check_license(
            license_key=created.license_key,
            email=None,
            customer_id=None,
            whop_user_id=None,
            machine_fingerprint="machine-second",
            app_version="1.0.0",
            ip_address="127.0.0.2",
            user_agent=None,
            check_interval_seconds=3600,
            grace_period_seconds=86400,
            max_devices=1,
        )
        detail = self.service.customer_detail(created.customer["id"], default_max_devices=1)

        self.assertEqual("device_limit_exceeded", second["status"])
        self.assertEqual([], second["licensed_strategies"])
        self.assertEqual(1, second["device_limit"]["active_devices"])
        self.assertEqual(1, second["device_limit"]["max_devices"])
        self.assertIn("device.limit_exceeded", [audit["action"] for audit in detail["audit"]])

    def test_customer_max_devices_override_allows_second_device(self) -> None:
        created = self.active_customer("override-devices@example.com")
        self.service.set_customer_max_devices(
            customer_id=created.customer["id"],
            max_devices=2,
            actor_id="admin",
            ip_address=None,
        )
        first = self.service.check_license(
            license_key=created.license_key,
            email=None,
            customer_id=None,
            whop_user_id=None,
            machine_fingerprint="override-first",
            app_version="1.0.0",
            ip_address=None,
            user_agent=None,
            check_interval_seconds=3600,
            grace_period_seconds=86400,
            max_devices=1,
        )
        second = self.service.check_license(
            license_key=created.license_key,
            email=None,
            customer_id=None,
            whop_user_id=None,
            machine_fingerprint="override-second",
            app_version="1.0.0",
            ip_address=None,
            user_agent=None,
            check_interval_seconds=3600,
            grace_period_seconds=86400,
            max_devices=1,
        )
        detail = self.service.customer_detail(created.customer["id"], default_max_devices=1)

        self.assertEqual("active", first["status"])
        self.assertEqual("active", second["status"])
        self.assertEqual(2, second["device_limit"]["max_devices"])
        self.assertEqual(2, detail["device_limit"]["active_devices"])
        self.assertIn("customer.max_devices_updated", [audit["action"] for audit in detail["audit"]])

    def test_blocked_device_returns_device_blocked_before_limit(self) -> None:
        created = self.active_customer("blocked-device@example.com")
        first = self.service.check_license(
            license_key=created.license_key,
            email=None,
            customer_id=None,
            whop_user_id=None,
            machine_fingerprint="machine-blocked",
            app_version="1.0.0",
            ip_address=None,
            user_agent=None,
            check_interval_seconds=3600,
            grace_period_seconds=86400,
            max_devices=1,
        )
        self.service.set_device_blocked(
            device_id=first["device"]["id"],
            is_blocked=True,
            note="support test",
            actor_id="admin",
            ip_address=None,
        )

        blocked = self.service.check_license(
            license_key=created.license_key,
            email=None,
            customer_id=None,
            whop_user_id=None,
            machine_fingerprint="machine-blocked",
            app_version="1.0.0",
            ip_address=None,
            user_agent=None,
            check_interval_seconds=3600,
            grace_period_seconds=86400,
            max_devices=1,
        )

        self.assertEqual("device_blocked", blocked["status"])

    def test_device_limit_blocks_release_manifest(self) -> None:
        created = self.active_customer("manifest-limit@example.com")
        self.service.check_license(
            license_key=created.license_key,
            email=None,
            customer_id=None,
            whop_user_id=None,
            machine_fingerprint="manifest-first",
            app_version="1.0.0",
            ip_address=None,
            user_agent=None,
            check_interval_seconds=3600,
            grace_period_seconds=86400,
            max_devices=1,
        )
        artifact_dir = Path(self.tmp.name) / "manifest-limit-artifacts"
        artifact_dir.mkdir()
        self.service.upsert_release(
            release_id=None,
            scope="strategy",
            product_id=self.product["id"],
            channel="stable",
            platform="windows-x64",
            version="1.1.0",
            min_supported_version=None,
            is_required=False,
            is_active=True,
            artifact_path="duo.zip",
            artifact_filename=None,
            size_bytes=10,
            sha256_value="abc",
            signature=None,
            release_notes=None,
            artifact_dir=str(artifact_dir),
        )

        manifest = self.service.release_manifest(
            license_key=created.license_key,
            email=None,
            customer_id=None,
            whop_user_id=None,
            machine_fingerprint="manifest-second",
            app_version="1.0.0",
            channel="stable",
            platform="windows-x64",
            ip_address=None,
            user_agent=None,
            check_interval_seconds=3600,
            grace_period_seconds=86400,
            max_devices=1,
        )

        self.assertEqual("device_limit_exceeded", manifest["status"])
        self.assertEqual([], manifest["releases"])

    def test_device_limit_blocks_download_token(self) -> None:
        created = self.active_customer("download-limit@example.com")
        self.service.check_license(
            license_key=created.license_key,
            email=None,
            customer_id=None,
            whop_user_id=None,
            machine_fingerprint="download-first",
            app_version="1.0.0",
            ip_address=None,
            user_agent=None,
            check_interval_seconds=3600,
            grace_period_seconds=86400,
            max_devices=1,
        )
        artifact_dir = Path(self.tmp.name) / "download-limit-artifacts"
        artifact_dir.mkdir()
        release = self.service.upsert_release(
            release_id=None,
            scope="strategy",
            product_id=self.product["id"],
            channel="stable",
            platform="windows-x64",
            version="1.1.0",
            min_supported_version=None,
            is_required=False,
            is_active=True,
            artifact_path="duo.zip",
            artifact_filename=None,
            size_bytes=10,
            sha256_value="abc",
            signature=None,
            release_notes=None,
            artifact_dir=str(artifact_dir),
        )

        token = self.service.create_release_download_token(
            release_id=release["id"],
            license_key=created.license_key,
            email=None,
            customer_id=None,
            whop_user_id=None,
            machine_fingerprint="download-second",
            app_version="1.0.0",
            ip_address=None,
            user_agent=None,
            check_interval_seconds=3600,
            grace_period_seconds=86400,
            token_seconds=600,
            max_devices=1,
        )

        self.assertEqual("device_limit_exceeded", token["status"])
        self.assertIsNone(token["token"])

    def test_block_all_customer_devices_allows_next_device(self) -> None:
        created = self.active_customer("reset-devices@example.com")
        first = self.service.check_license(
            license_key=created.license_key,
            email=None,
            customer_id=None,
            whop_user_id=None,
            machine_fingerprint="reset-first",
            app_version="1.0.0",
            ip_address=None,
            user_agent=None,
            check_interval_seconds=3600,
            grace_period_seconds=86400,
            max_devices=1,
        )

        blocked_count = self.service.block_all_customer_devices(
            customer_id=created.customer["id"],
            note="support reset",
            actor_id="admin",
            ip_address=None,
        )
        next_device = self.service.check_license(
            license_key=created.license_key,
            email=None,
            customer_id=None,
            whop_user_id=None,
            machine_fingerprint="reset-second",
            app_version="1.0.0",
            ip_address=None,
            user_agent=None,
            check_interval_seconds=3600,
            grace_period_seconds=86400,
            max_devices=1,
        )

        detail = self.service.customer_detail(created.customer["id"], default_max_devices=1)
        self.assertEqual(1, blocked_count)
        self.assertEqual("active", next_device["status"])
        self.assertEqual(1, detail["device_limit"]["active_devices"])

    def test_whop_upsert_is_idempotent_and_activates_customer(self) -> None:
        self.service.upsert_whop_package(
            package_id=None,
            whop_id="prod_duo",
            whop_id_type="product",
            name="DUO 30 days",
            default_days=30,
            is_active=True,
            is_ignored=False,
            grants=[{"product_id": self.product["id"], "days": 30}],
        )
        payload = {
            "type": "membership.created",
            "data": {
                "id": "ent_001",
                "membership_id": "mem_001",
                "status": "active",
                "email": "whop@example.com",
                "user_id": "user_001",
                "product_id": "prod_duo",
                "product_name": "DUO Runtime",
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

    def test_whop_package_bundle_grants_multiple_strategies(self) -> None:
        duorc = self.service.upsert_product(
            slug="duorc-runtime",
            name="DUOrc Runtime",
            feature_id="strategy.duorc.runtime",
        )
        self.service.upsert_whop_package(
            package_id=None,
            whop_id="plan_bundle_30",
            whop_id_type="plan",
            name="AutoEdge Bundle 30 days",
            default_days=30,
            is_active=True,
            is_ignored=False,
            grants=[
                {"product_id": self.product["id"], "days": 30},
                {"product_id": duorc["id"], "days": 30},
            ],
        )

        result = self.service.process_whop_event(
            {
                "action": "membership.went_valid",
                "data": {
                    "id": "mem_bundle_001",
                    "status": "active",
                    "email": "bundle@example.com",
                    "user_id": "user_bundle_001",
                    "plan_id": "plan_bundle_30",
                    "product_id": "prod_bundle",
                    "renewal_period_end": iso(utc_now() + timedelta(days=30)),
                },
            },
            "evt_bundle_001",
            signature_valid=True,
            ip_address="127.0.0.1",
        )

        detail = self.service.customer_detail(result["customer_id"])
        self.assertEqual("whop_package", result["mapping_mode"])
        self.assertEqual(2, len(detail["entitlements"]))

        response = self.service.check_license(
            license_key=None,
            email="bundle@example.com",
            customer_id=None,
            whop_user_id=None,
            machine_fingerprint="machine-bundle",
            app_version=None,
            ip_address=None,
            user_agent=None,
            check_interval_seconds=3600,
            grace_period_seconds=86400,
        )
        self.assertEqual("active", response["status"])
        self.assertEqual(
            ["strategy.duo.runtime", "strategy.duorc.runtime"],
            sorted(grant["feature_id"] for grant in response["licensed_strategies"]),
        )

    def test_trial_then_paid_adds_package_days_after_trial(self) -> None:
        self.service.upsert_whop_package(
            package_id=None,
            whop_id="plan_duo_30",
            whop_id_type="plan",
            name="DUO 30 days",
            default_days=30,
            is_active=True,
            is_ignored=False,
            grants=[{"product_id": self.product["id"], "days": 30}],
        )
        trial_end = utc_now() + timedelta(days=7)
        trial = self.service.process_whop_event(
            {
                "action": "membership.activated",
                "data": {
                    "id": "mem_trial_001",
                    "status": "trialing",
                    "email": "trial@example.com",
                    "user_id": "user_trial_001",
                    "plan_id": "plan_duo_30",
                    "trial_ends_at": iso(trial_end),
                },
            },
            "evt_trial_001",
            signature_valid=True,
            ip_address=None,
        )
        paid = self.service.process_whop_event(
            {
                "action": "membership.went_valid",
                "data": {
                    "id": "mem_trial_001",
                    "status": "active",
                    "email": "trial@example.com",
                    "user_id": "user_trial_001",
                    "plan_id": "plan_duo_30",
                    "payment_id": "pay_trial_001",
                    "renewal_period_end": iso(trial_end + timedelta(days=30)),
                },
            },
            "evt_paid_001",
            signature_valid=True,
            ip_address=None,
        )

        detail = self.service.customer_detail(trial["customer_id"])
        expires_at = parse_time(detail["entitlements"][0]["expires_at"])
        self.assertEqual("paid", paid["applied_grants"][0]["grant_kind"])
        self.assertGreaterEqual(expires_at, trial_end + timedelta(days=29))

    def test_paid_duplicate_for_same_period_does_not_add_days_twice(self) -> None:
        self.service.upsert_whop_package(
            package_id=None,
            whop_id="plan_dupe_30",
            whop_id_type="plan",
            name="DUO 30 days",
            default_days=30,
            is_active=True,
            is_ignored=False,
            grants=[{"product_id": self.product["id"], "days": 30}],
        )
        payload = {
            "action": "membership.went_valid",
            "data": {
                "id": "mem_dupe_001",
                "status": "active",
                "email": "dupe@example.com",
                "user_id": "user_dupe_001",
                "plan_id": "plan_dupe_30",
                "current_period_start": iso(utc_now()),
                "current_period_end": iso(utc_now() + timedelta(days=30)),
            },
        }

        first = self.service.process_whop_event(payload, "evt_dupe_001", signature_valid=True, ip_address=None)
        second = self.service.process_whop_event(payload, "evt_dupe_002", signature_valid=True, ip_address=None)
        detail = self.service.customer_detail(first["customer_id"])
        expires_at = parse_time(detail["entitlements"][0]["expires_at"])

        self.assertEqual("duplicate_grant", second["applied_grants"][0]["status"])
        self.assertLess(expires_at, utc_now() + timedelta(days=32))

    def test_ignored_package_does_not_create_entitlement(self) -> None:
        self.service.upsert_whop_package(
            package_id=None,
            whop_id="plan_non_license",
            whop_id_type="plan",
            name="Community access",
            default_days=None,
            is_active=True,
            is_ignored=True,
            grants=[],
        )

        result = self.service.process_whop_event(
            {
                "action": "membership.went_valid",
                "data": {
                    "id": "mem_ignore_001",
                    "status": "active",
                    "email": "ignore@example.com",
                    "user_id": "user_ignore_001",
                    "plan_id": "plan_non_license",
                },
            },
            "evt_ignore_001",
            signature_valid=True,
            ip_address=None,
        )
        detail = self.service.customer_detail(result["customer_id"])

        self.assertEqual("ignored", result["status"])
        self.assertEqual([], detail["entitlements"])

    def test_refund_revokes_package_entitlement(self) -> None:
        self.service.upsert_whop_package(
            package_id=None,
            whop_id="plan_refund_30",
            whop_id_type="plan",
            name="DUO 30 days",
            default_days=30,
            is_active=True,
            is_ignored=False,
            grants=[{"product_id": self.product["id"], "days": 30}],
        )
        active = self.service.process_whop_event(
            {
                "action": "membership.went_valid",
                "data": {
                    "id": "mem_refund_001",
                    "status": "active",
                    "email": "refund@example.com",
                    "user_id": "user_refund_001",
                    "plan_id": "plan_refund_30",
                    "payment_id": "pay_refund_001",
                },
            },
            "evt_refund_active",
            signature_valid=True,
            ip_address=None,
        )
        self.service.process_whop_event(
            {
                "action": "refund.created",
                "data": {
                    "id": "mem_refund_001",
                    "status": "refunded",
                    "email": "refund@example.com",
                    "user_id": "user_refund_001",
                    "plan_id": "plan_refund_30",
                },
            },
            "evt_refund_001",
            signature_valid=True,
            ip_address=None,
        )

        response = self.service.check_license(
            license_key=None,
            email="refund@example.com",
            customer_id=None,
            whop_user_id=None,
            machine_fingerprint="machine-refund",
            app_version=None,
            ip_address=None,
            user_agent=None,
            check_interval_seconds=3600,
            grace_period_seconds=86400,
        )
        detail = self.service.customer_detail(active["customer_id"])
        self.assertEqual("revoked", response["status"])
        self.assertEqual("revoked", detail["entitlements"][0]["status"])

    def test_plan_id_takes_precedence_over_product_id(self) -> None:
        duorc = self.service.upsert_product(
            slug="duorc-runtime",
            name="DUOrc Runtime",
            feature_id="strategy.duorc.runtime",
        )
        self.service.upsert_whop_package(
            package_id=None,
            whop_id="plan_precedence",
            whop_id_type="plan",
            name="Plan DUO",
            default_days=30,
            is_active=True,
            is_ignored=False,
            grants=[{"product_id": self.product["id"], "days": 30}],
        )
        self.service.upsert_whop_package(
            package_id=None,
            whop_id="prod_precedence",
            whop_id_type="product",
            name="Product DUOrc",
            default_days=30,
            is_active=True,
            is_ignored=False,
            grants=[{"product_id": duorc["id"], "days": 30}],
        )

        result = self.service.process_whop_event(
            {
                "action": "membership.went_valid",
                "data": {
                    "id": "mem_precedence_001",
                    "status": "active",
                    "email": "precedence@example.com",
                    "user_id": "user_precedence_001",
                    "plan_id": "plan_precedence",
                    "product_id": "prod_precedence",
                    "payment_id": "pay_precedence_001",
                },
            },
            "evt_precedence_001",
            signature_valid=True,
            ip_address=None,
        )
        detail = self.service.customer_detail(result["customer_id"])

        self.assertEqual("plan_precedence", result["whop_id"])
        self.assertEqual([self.product["id"]], [entitlement["product_id"] for entitlement in detail["entitlements"]])

    def test_nested_whop_payment_failed_uses_plan_object_and_suspends(self) -> None:
        self.service.upsert_whop_package(
            package_id=None,
            whop_id="plan_bundle_nested",
            whop_id_type="plan",
            name="Bundle 30 days",
            default_days=30,
            is_active=True,
            is_ignored=False,
            grants=[{"product_id": self.product["id"], "days": 30}],
        )

        result = self.service.process_whop_event(
            {
                "type": "payment.failed",
                "data": {
                    "id": "pay_nested_failed",
                    "status": "open",
                    "substatus": "failed",
                    "created_at": iso(utc_now()),
                    "membership": {"id": "mem_nested_failed", "status": "trialing"},
                    "plan": {"id": "plan_bundle_nested"},
                    "product": {"id": "prod_bundle_nested", "title": "8 Bot Bundle"},
                    "user": {
                        "email": "nested-failed@example.com",
                        "id": "user_nested_failed",
                        "name": "Nested Failed",
                    },
                },
            },
            "evt_nested_failed",
            signature_valid=True,
            ip_address=None,
        )

        detail = self.service.customer_detail(result["customer_id"])
        with self.database.session() as connection:
            subscription = connection.execute(
                "SELECT * FROM subscriptions WHERE whop_membership_id = ?",
                ("mem_nested_failed",),
            ).fetchone()

        self.assertEqual("processed", result["status"])
        self.assertEqual("whop_package", result["mapping_mode"])
        self.assertEqual("plan_bundle_nested", result["whop_id"])
        self.assertEqual("suspended", result["entitlement_status"])
        self.assertEqual("suspend", result["applied_grants"][0]["grant_kind"])
        self.assertEqual("suspended", detail["entitlements"][0]["status"])
        self.assertEqual("plan_bundle_nested", subscription["whop_plan_id"])

    def test_payment_succeeded_over_trial_status_adds_paid_days(self) -> None:
        self.service.upsert_whop_package(
            package_id=None,
            whop_id="plan_payment_success",
            whop_id_type="plan",
            name="DUO 30 days",
            default_days=30,
            is_active=True,
            is_ignored=False,
            grants=[{"product_id": self.product["id"], "days": 30}],
        )
        trial_end = utc_now() + timedelta(days=7)
        self.service.process_whop_event(
            {
                "action": "membership.activated",
                "data": {
                    "id": "mem_payment_success",
                    "status": "trialing",
                    "email": "payment-success@example.com",
                    "user_id": "user_payment_success",
                    "plan_id": "plan_payment_success",
                    "trial_ends_at": iso(trial_end),
                },
            },
            "evt_payment_success_trial",
            signature_valid=True,
            ip_address=None,
        )

        paid = self.service.process_whop_event(
            {
                "type": "payment.succeeded",
                "data": {
                    "id": "pay_payment_success",
                    "status": "paid",
                    "membership": {"id": "mem_payment_success", "status": "trialing"},
                    "plan": {"id": "plan_payment_success"},
                    "product": {"id": "prod_payment_success"},
                    "user": {
                        "email": "payment-success@example.com",
                        "id": "user_payment_success",
                    },
                },
            },
            "evt_payment_success_paid",
            signature_valid=True,
            ip_address=None,
        )

        detail = self.service.customer_detail(paid["customer_id"])
        expires_at = parse_time(detail["entitlements"][0]["expires_at"])
        self.assertEqual("active", paid["entitlement_status"])
        self.assertEqual("paid", paid["applied_grants"][0]["grant_kind"])
        self.assertGreaterEqual(expires_at, trial_end + timedelta(days=29))

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

    def test_release_manifest_returns_only_licensed_strategy_releases(self) -> None:
        duorc = self.service.upsert_product(
            slug="duorc-runtime",
            name="DUOrc Runtime",
            feature_id="strategy.duorc.runtime",
        )
        created = self.service.create_or_update_customer(email="release@example.com")
        self.service.manual_set_entitlement(
            customer_id=created.customer["id"],
            product_id=self.product["id"],
            status="active",
            expires_at=iso(utc_now() + timedelta(days=30)),
            reason="release test",
            actor_id="admin",
            ip_address=None,
        )
        artifact_dir = Path(self.tmp.name) / "artifacts"
        artifact_dir.mkdir()
        artifact = artifact_dir / "duo-1.2.0.zip"
        artifact.write_bytes(b"duo package")
        self.service.upsert_release(
            release_id=None,
            scope="strategy",
            product_id=self.product["id"],
            channel="stable",
            platform="windows-x64",
            version="1.2.0",
            min_supported_version=None,
            is_required=False,
            is_active=True,
            artifact_path="duo-1.2.0.zip",
            artifact_filename=None,
            size_bytes=None,
            sha256_value=None,
            signature=None,
            release_notes="DUO update",
            artifact_dir=str(artifact_dir),
        )
        self.service.upsert_release(
            release_id=None,
            scope="strategy",
            product_id=duorc["id"],
            channel="stable",
            platform="windows-x64",
            version="1.2.0",
            min_supported_version=None,
            is_required=False,
            is_active=True,
            artifact_path="duorc-1.2.0.zip",
            artifact_filename=None,
            size_bytes=10,
            sha256_value="abc",
            signature=None,
            release_notes=None,
            artifact_dir=str(artifact_dir),
        )

        manifest = self.service.release_manifest(
            license_key=created.license_key,
            email=None,
            customer_id=None,
            whop_user_id=None,
            machine_fingerprint="release-machine",
            app_version="1.1.0",
            channel="stable",
            platform="windows-x64",
            ip_address=None,
            user_agent=None,
            check_interval_seconds=3600,
            grace_period_seconds=86400,
        )

        self.assertEqual("active", manifest["status"])
        self.assertEqual(["DUO"], [release["strategy"] for release in manifest["releases"]])
        self.assertTrue(manifest["releases"][0]["update_available"])
        self.assertEqual(len(b"duo package"), manifest["releases"][0]["artifact"]["size_bytes"])

    def test_release_download_token_and_resolution_are_license_gated(self) -> None:
        created = self.service.create_or_update_customer(email="download@example.com")
        self.service.manual_set_entitlement(
            customer_id=created.customer["id"],
            product_id=self.product["id"],
            status="active",
            expires_at=iso(utc_now() + timedelta(days=30)),
            reason="download test",
            actor_id="admin",
            ip_address=None,
        )
        artifact_dir = Path(self.tmp.name) / "artifacts"
        artifact_dir.mkdir()
        artifact = artifact_dir / "duo-1.3.0.zip"
        artifact.write_bytes(b"download bytes")
        release = self.service.upsert_release(
            release_id=None,
            scope="strategy",
            product_id=self.product["id"],
            channel="stable",
            platform="windows-x64",
            version="1.3.0",
            min_supported_version=None,
            is_required=True,
            is_active=True,
            artifact_path="duo-1.3.0.zip",
            artifact_filename=None,
            size_bytes=None,
            sha256_value=None,
            signature="sig",
            release_notes=None,
            artifact_dir=str(artifact_dir),
        )

        token_result = self.service.create_release_download_token(
            release_id=release["id"],
            license_key=created.license_key,
            email=None,
            customer_id=None,
            whop_user_id=None,
            machine_fingerprint="download-machine",
            app_version="1.2.0",
            ip_address=None,
            user_agent=None,
            check_interval_seconds=3600,
            grace_period_seconds=86400,
            token_seconds=600,
        )
        resolved = self.service.resolve_release_download(
            token=token_result["token"],
            artifact_dir=str(artifact_dir),
            ip_address=None,
            user_agent=None,
        )

        self.assertEqual("ok", token_result["status"])
        self.assertEqual("ok", resolved["status"])
        self.assertEqual(artifact.resolve(), resolved["artifact_path"])
        self.assertEqual("duo-1.3.0.zip", resolved["artifact_filename"])

    def test_release_download_token_rejects_unlicensed_strategy(self) -> None:
        duorc = self.service.upsert_product(
            slug="duorc-runtime",
            name="DUOrc Runtime",
            feature_id="strategy.duorc.runtime",
        )
        created = self.service.create_or_update_customer(email="notlicensed@example.com")
        self.service.manual_set_entitlement(
            customer_id=created.customer["id"],
            product_id=self.product["id"],
            status="active",
            expires_at=iso(utc_now() + timedelta(days=30)),
            reason="download test",
            actor_id="admin",
            ip_address=None,
        )
        artifact_dir = Path(self.tmp.name) / "artifacts"
        artifact_dir.mkdir()
        release = self.service.upsert_release(
            release_id=None,
            scope="strategy",
            product_id=duorc["id"],
            channel="stable",
            platform="windows-x64",
            version="1.0.0",
            min_supported_version=None,
            is_required=False,
            is_active=True,
            artifact_path="duorc.zip",
            artifact_filename=None,
            size_bytes=10,
            sha256_value="abc",
            signature=None,
            release_notes=None,
            artifact_dir=str(artifact_dir),
        )

        result = self.service.create_release_download_token(
            release_id=release["id"],
            license_key=created.license_key,
            email=None,
            customer_id=None,
            whop_user_id=None,
            machine_fingerprint="download-machine-2",
            app_version=None,
            ip_address=None,
            user_agent=None,
            check_interval_seconds=3600,
            grace_period_seconds=86400,
            token_seconds=600,
        )

        self.assertEqual("not_licensed", result["status"])

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
