from __future__ import annotations

import base64
import json
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

from autoedge_licensing.db import Database, apply_migrations
from autoedge_licensing.security import unsign_value
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

    def strategy_release(
        self,
        *,
        version: str,
        channel: str = "stable",
        product_id: str | None = None,
        audience_mode: str = "all",
        allowed_customer_ids: str | None = None,
        allowed_emails: str | None = None,
        required_tags: str | None = None,
        rollout_percent: int | None = None,
        platform: str = "windows-x64",
        is_active: bool = True,
        rollback_reason: str | None = None,
    ):
        artifact_dir = Path(self.tmp.name) / "release-test-artifacts"
        artifact_dir.mkdir(exist_ok=True)
        path = f"strategy-{version}-{channel}-{platform}.zip"
        (artifact_dir / path).write_bytes(f"strategy {version}".encode())
        return self.service.upsert_release(
            release_id=None,
            scope="strategy",
            product_id=product_id or self.product["id"],
            channel=channel,
            platform=platform,
            version=version,
            min_supported_version=None,
            is_required=False,
            is_active=is_active,
            artifact_path=path,
            artifact_filename=None,
            size_bytes=None,
            sha256_value=None,
            signature=None,
            release_notes=None,
            artifact_dir=str(artifact_dir),
            audience_mode=audience_mode,
            allowed_customer_ids=allowed_customer_ids,
            allowed_emails=allowed_emails,
            required_tags=required_tags,
            rollout_percent=rollout_percent,
            rollback_reason=rollback_reason,
        )

    def desktop_release(
        self,
        *,
        version: str,
        channel: str = "stable",
        audience_mode: str = "all",
        allowed_customer_ids: str | None = None,
        allowed_emails: str | None = None,
        required_tags: str | None = None,
        rollout_percent: int | None = None,
        platform: str = "windows-x64",
        rollback_reason: str | None = None,
    ):
        artifact_dir = Path(self.tmp.name) / "desktop-test-artifacts"
        artifact_dir.mkdir(exist_ok=True)
        path = f"Trader-Setup-{version}-{platform}.zip"
        (artifact_dir / path).write_bytes(f"desktop {version}".encode())
        return self.service.upsert_release(
            release_id=None,
            scope="app",
            release_type="trader_desktop",
            product_key="trader-desktop",
            product_id=None,
            channel=channel,
            platform=platform,
            version=version,
            min_supported_version=None,
            is_required=False,
            is_active=True,
            artifact_path=path,
            artifact_filename=None,
            size_bytes=None,
            sha256_value=None,
            signature=None,
            release_notes=None,
            artifact_dir=str(artifact_dir),
            audience_mode=audience_mode,
            allowed_customer_ids=allowed_customer_ids,
            allowed_emails=allowed_emails,
            required_tags=required_tags,
            rollout_percent=rollout_percent,
            rollback_reason=rollback_reason,
        )

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

    def test_rotate_customer_license_key_replaces_old_key_and_audits(self) -> None:
        created = self.active_customer("rotate@example.com")

        new_key = self.service.rotate_customer_license_key(
            customer_id=created.customer["id"],
            actor_id="admin-001",
            ip_address="127.0.0.1",
        )
        old_response = self.service.check_license(
            license_key=created.license_key,
            email=None,
            customer_id=None,
            whop_user_id=None,
            machine_fingerprint="rotate-machine",
            app_version="0.5.0",
            ip_address="127.0.0.1",
            user_agent="test",
            check_interval_seconds=3600,
            grace_period_seconds=86400,
        )
        new_response = self.service.check_license(
            license_key=new_key,
            email=None,
            customer_id=None,
            whop_user_id=None,
            machine_fingerprint="rotate-machine",
            app_version="0.5.0",
            ip_address="127.0.0.1",
            user_agent="test",
            check_interval_seconds=3600,
            grace_period_seconds=86400,
        )
        detail = self.service.customer_detail(created.customer["id"], default_max_devices=1)

        self.assertNotEqual(created.license_key, new_key)
        self.assertEqual("unknown_customer", old_response["status"])
        self.assertEqual("active", new_response["status"])
        self.assertEqual(new_key[-4:], detail["customer"]["license_key_last4"])
        self.assertTrue(any(audit["action"] == "customer.license_key_rotated" for audit in detail["audit"]))

    def test_nt8_active_grant_returns_strategy_key_and_signed_lease(self) -> None:
        created = self.active_customer("nt8-active@example.com")
        lease_secret = "lease-secret-" + ("x" * 40)

        response = self.service.check_nt8_license(
            license_key=created.license_key,
            email=None,
            customer_id=None,
            whop_user_id=None,
            machine_fingerprint="nt8-machine-001",
            nt8_version="8.1.5",
            strategy="DUO",
            ip_address="127.0.0.1",
            user_agent="NinjaTrader",
            check_interval_seconds=3600,
            grace_period_seconds=86400,
            max_devices=1,
            lease_secret=lease_secret,
        )

        signed_payload = unsign_value(lease_secret, response["lease"]["token"])
        lease_payload = json.loads(base64.urlsafe_b64decode(signed_payload.encode("ascii")).decode("utf-8"))

        self.assertEqual("active", response["status"])
        self.assertTrue(response["licensed"])
        self.assertEqual(["DUO"], response["strategy_keys"])
        self.assertEqual("nt8", response["device"]["client_type"])
        self.assertEqual("nt8_license_lease", lease_payload["type"])
        self.assertEqual(["DUO"], lease_payload["strategy_keys"])

    def test_nt8_requested_unlicensed_strategy_blocks_without_lease(self) -> None:
        created = self.active_customer("nt8-unlicensed-strategy@example.com")

        response = self.service.check_nt8_license(
            license_key=created.license_key,
            email=None,
            customer_id=None,
            whop_user_id=None,
            machine_fingerprint="nt8-machine-002",
            nt8_version="8.1.5",
            strategy="ADAM",
            ip_address=None,
            user_agent=None,
            check_interval_seconds=3600,
            grace_period_seconds=86400,
            max_devices=1,
            lease_secret="lease-secret-" + ("x" * 40),
        )

        self.assertEqual("unlicensed_strategy", response["status"])
        self.assertFalse(response["licensed"])
        self.assertIsNone(response["lease"])

    def test_nt8_disabled_product_is_not_returned_but_trader_still_can_be(self) -> None:
        self.service.update_product(
            product_id=self.product["id"],
            slug=self.product["slug"],
            name=self.product["name"],
            feature_id=self.product["feature_id"],
            whop_product_id=self.product["whop_product_id"],
            is_active=True,
            nt8_strategy_key="DUO",
            trader_enabled=True,
            nt8_enabled=False,
        )
        created = self.active_customer("nt8-disabled@example.com")

        nt8 = self.service.check_nt8_license(
            license_key=created.license_key,
            email=None,
            customer_id=None,
            whop_user_id=None,
            machine_fingerprint="nt8-disabled-machine",
            nt8_version="8.1.5",
            strategy="DUO",
            ip_address=None,
            user_agent=None,
            check_interval_seconds=3600,
            grace_period_seconds=86400,
            max_devices=1,
            lease_secret="lease-secret-" + ("x" * 40),
        )
        trader = self.service.check_license(
            license_key=created.license_key,
            email=None,
            customer_id=None,
            whop_user_id=None,
            machine_fingerprint="trader-disabled-machine",
            app_version="1.0.0",
            ip_address=None,
            user_agent=None,
            check_interval_seconds=3600,
            grace_period_seconds=86400,
            max_devices=2,
        )

        self.assertEqual("unlicensed", nt8["status"])
        self.assertFalse(nt8["licensed"])
        self.assertEqual("active", trader["status"])
        self.assertEqual(["strategy.duo.runtime"], [grant["feature_id"] for grant in trader["licensed_strategies"]])

    def test_nt8_device_limit_exceeded_blocks_and_omits_lease(self) -> None:
        created = self.active_customer("nt8-limit@example.com")
        kwargs = {
            "license_key": created.license_key,
            "email": None,
            "customer_id": None,
            "whop_user_id": None,
            "nt8_version": "8.1.5",
            "strategy": "DUO",
            "ip_address": None,
            "user_agent": None,
            "check_interval_seconds": 3600,
            "grace_period_seconds": 86400,
            "max_devices": 1,
            "lease_secret": "lease-secret-" + ("x" * 40),
        }

        first = self.service.check_nt8_license(machine_fingerprint="nt8-limit-one", **kwargs)
        second = self.service.check_nt8_license(machine_fingerprint="nt8-limit-two", **kwargs)

        self.assertEqual("active", first["status"])
        self.assertEqual("device_limit_exceeded", second["status"])
        self.assertFalse(second["licensed"])
        self.assertIsNone(second["lease"])

    def test_nt8_lowering_device_limit_blocks_existing_extra_device(self) -> None:
        created = self.active_customer("nt8-limit-reduced@example.com")
        self.service.set_customer_max_devices(
            customer_id=created.customer["id"],
            max_devices=2,
            actor_id="admin",
            ip_address=None,
        )
        kwargs = {
            "license_key": created.license_key,
            "email": None,
            "customer_id": None,
            "whop_user_id": None,
            "nt8_version": "8.1.5",
            "strategy": "DUO",
            "ip_address": None,
            "user_agent": None,
            "check_interval_seconds": 3600,
            "grace_period_seconds": 86400,
            "max_devices": 1,
            "lease_secret": "lease-secret-" + ("x" * 40),
        }
        first = self.service.check_nt8_license(machine_fingerprint="nt8-reduced-one", **kwargs)
        second = self.service.check_nt8_license(machine_fingerprint="nt8-reduced-two", **kwargs)

        self.service.set_customer_max_devices(
            customer_id=created.customer["id"],
            max_devices=1,
            actor_id="admin",
            ip_address=None,
        )
        first_after_limit_reduction = self.service.check_nt8_license(machine_fingerprint="nt8-reduced-one", **kwargs)
        second_after_limit_reduction = self.service.check_nt8_license(machine_fingerprint="nt8-reduced-two", **kwargs)

        self.assertEqual("active", first["status"])
        self.assertEqual("active", second["status"])
        self.assertEqual("active", first_after_limit_reduction["status"])
        self.assertTrue(first_after_limit_reduction["licensed"])
        self.assertEqual("device_limit_exceeded", second_after_limit_reduction["status"])
        self.assertFalse(second_after_limit_reduction["licensed"])
        self.assertIsNone(second_after_limit_reduction["lease"])
        self.assertEqual(2, second_after_limit_reduction["device_limit"]["active_devices"])
        self.assertEqual(1, second_after_limit_reduction["device_limit"]["max_devices"])

    def test_manual_grant_accepts_datetime_local_expiry(self) -> None:
        created = self.service.create_or_update_customer(email="picker@example.com")
        entitlement = self.service.manual_set_entitlement(
            customer_id=created.customer["id"],
            product_id=self.product["id"],
            status="active",
            expires_at="2026-12-31T23:59",
            reason="picker grant",
            actor_id="admin",
            ip_address=None,
        )

        self.assertEqual("2026-12-31T23:59:00Z", entitlement["expires_at"])

    def test_manual_grant_rejects_invalid_expiry_text(self) -> None:
        created = self.service.create_or_update_customer(email="bad-expiry@example.com")

        with self.assertRaises(ValueError):
            self.service.manual_set_entitlement(
                customer_id=created.customer["id"],
                product_id=self.product["id"],
                status="active",
                expires_at="not a date",
                reason="bad grant",
                actor_id="admin",
                ip_address=None,
            )

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

    def test_lowering_device_limit_blocks_existing_extra_device(self) -> None:
        created = self.active_customer("reduced-devices@example.com")
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
            machine_fingerprint="reduced-first",
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
            machine_fingerprint="reduced-second",
            app_version="1.0.0",
            ip_address=None,
            user_agent=None,
            check_interval_seconds=3600,
            grace_period_seconds=86400,
            max_devices=1,
        )
        self.service.set_customer_max_devices(
            customer_id=created.customer["id"],
            max_devices=1,
            actor_id="admin",
            ip_address=None,
        )
        first_after_limit_reduction = self.service.check_license(
            license_key=created.license_key,
            email=None,
            customer_id=None,
            whop_user_id=None,
            machine_fingerprint="reduced-first",
            app_version="1.0.1",
            ip_address=None,
            user_agent=None,
            check_interval_seconds=3600,
            grace_period_seconds=86400,
            max_devices=1,
        )
        second_after_limit_reduction = self.service.check_license(
            license_key=created.license_key,
            email=None,
            customer_id=None,
            whop_user_id=None,
            machine_fingerprint="reduced-second",
            app_version="1.0.1",
            ip_address=None,
            user_agent=None,
            check_interval_seconds=3600,
            grace_period_seconds=86400,
            max_devices=1,
        )

        self.assertEqual("active", first["status"])
        self.assertEqual("active", second["status"])
        self.assertEqual("active", first_after_limit_reduction["status"])
        self.assertEqual("device_limit_exceeded", second_after_limit_reduction["status"])
        self.assertEqual(2, second_after_limit_reduction["device_limit"]["active_devices"])
        self.assertEqual(1, second_after_limit_reduction["device_limit"]["max_devices"])
        self.assertFalse(second_after_limit_reduction["device_limit"]["device_is_within_limit"])

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

    def test_unmapped_whop_event_does_not_create_blank_customer(self) -> None:
        result = self.service.process_whop_event(
            {
                "type": "withdrawal.updated",
                "data": {
                    "id": "withdrawal_001",
                    "status": "pending",
                },
            },
            "evt_withdrawal_001",
            signature_valid=True,
            ip_address="127.0.0.1",
        )

        with self.database.session() as connection:
            customer_count = connection.execute("SELECT COUNT(*) FROM customers").fetchone()[0]
            audit = connection.execute(
                "SELECT * FROM audit_log WHERE action = 'whop_package.unmapped'"
            ).fetchone()

        self.assertEqual("unmapped_package", result["status"])
        self.assertIsNone(result["customer_id"])
        self.assertEqual(0, customer_count)
        self.assertIsNotNone(audit)
        self.assertEqual("webhook_event", audit["entity_type"])
        self.assertEqual("evt_withdrawal_001", audit["entity_id"])

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

    def test_release_manifest_returns_trader_desktop_app_update(self) -> None:
        created = self.active_customer("app-update@example.com")
        artifact_dir = Path(self.tmp.name) / "app-update-artifacts"
        artifact_dir.mkdir()
        artifact = artifact_dir / "Trader-Setup-0.1.1-windows-x64.zip"
        artifact.write_bytes(b"desktop app update")
        release = self.service.upsert_release(
            release_id=None,
            scope="app",
            release_type="trader_desktop",
            product_key="trader-desktop",
            product_id=None,
            channel="stable",
            platform="windows-x64",
            version="0.1.1",
            min_supported_version="0.1.0",
            is_required=False,
            is_active=True,
            artifact_path=artifact.name,
            artifact_filename=None,
            size_bytes=None,
            sha256_value=None,
            signature="sig",
            signature_key_id="key-1",
            release_notes="Desktop update",
            artifact_dir=str(artifact_dir),
        )

        manifest = self.service.release_manifest(
            license_key=created.license_key,
            email=None,
            customer_id=None,
            whop_user_id=None,
            machine_fingerprint="app-update-machine",
            app_version="0.1.0",
            channel="stable",
            platform="windows-x64",
            include_types=["strategy_package", "trader_desktop"],
            ip_address=None,
            user_agent=None,
            check_interval_seconds=3600,
            grace_period_seconds=86400,
        )

        self.assertEqual("active", manifest["status"])
        self.assertEqual([], manifest["releases"])
        self.assertIsNotNone(manifest["app_update"])
        self.assertEqual("trader-desktop", manifest["app_update"]["product_id"])
        self.assertEqual("0.1.0", manifest["app_update"]["current_version"])
        self.assertEqual("0.1.1", manifest["app_update"]["available_version"])
        self.assertEqual(release["id"], manifest["app_update"]["release_id"])
        self.assertEqual(len(b"desktop app update"), manifest["app_update"]["artifact"]["size_bytes"])
        self.assertIsNotNone(manifest["app_update"]["artifact"]["sha256"])
        self.assertEqual("key-1", manifest["app_update"]["artifact"]["signature_key_id"])

    def test_release_manifest_returns_no_app_update_when_current_is_same_or_newer(self) -> None:
        created = self.active_customer("no-app-update@example.com")
        artifact_dir = Path(self.tmp.name) / "no-app-update-artifacts"
        artifact_dir.mkdir()
        self.service.upsert_release(
            release_id=None,
            scope="app",
            release_type="trader_desktop",
            product_key="trader-desktop",
            product_id=None,
            channel="stable",
            platform="windows-x64",
            version="0.1.1",
            min_supported_version=None,
            is_required=False,
            is_active=True,
            artifact_path="Trader-Setup-0.1.1-windows-x64.zip",
            artifact_filename=None,
            size_bytes=100,
            sha256_value="abc",
            signature=None,
            release_notes=None,
            artifact_dir=str(artifact_dir),
        )

        same = self.service.release_manifest(
            license_key=created.license_key,
            email=None,
            customer_id=None,
            whop_user_id=None,
            machine_fingerprint="no-app-update-machine",
            app_version="0.1.1",
            channel="stable",
            platform="windows-x64",
            include_types=["trader_desktop"],
            ip_address=None,
            user_agent=None,
            check_interval_seconds=3600,
            grace_period_seconds=86400,
        )
        newer = self.service.release_manifest(
            license_key=created.license_key,
            email=None,
            customer_id=None,
            whop_user_id=None,
            machine_fingerprint="no-app-update-machine",
            app_version="0.1.2",
            channel="stable",
            platform="windows-x64",
            include_types=["trader_desktop"],
            ip_address=None,
            user_agent=None,
            check_interval_seconds=3600,
            grace_period_seconds=86400,
        )

        self.assertIsNone(same["app_update"])
        self.assertIsNone(newer["app_update"])

    def test_release_manifest_supports_macos_arm64_desktop_and_strategy_releases(self) -> None:
        created = self.active_customer("macos-release@example.com")
        self.strategy_release(version="2.0.0", platform="macos-arm64")
        desktop = self.desktop_release(version="0.2.0", platform="macos-arm64")

        manifest = self.service.release_manifest(
            license_key=created.license_key,
            email=None,
            customer_id=None,
            whop_user_id=None,
            machine_fingerprint="macos-release-machine",
            app_version="0.1.0",
            channel="stable",
            platform="macos-arm64",
            include_types=["strategy_package", "trader_desktop"],
            ip_address=None,
            user_agent=None,
            check_interval_seconds=3600,
            grace_period_seconds=86400,
        )

        self.assertEqual("active", manifest["status"])
        self.assertEqual("macos-arm64", manifest["platform"])
        self.assertEqual(["2.0.0"], [release["version"] for release in manifest["releases"]])
        self.assertEqual("macos-arm64", manifest["releases"][0]["platform"])
        self.assertEqual(desktop["id"], manifest["app_update"]["release_id"])
        self.assertEqual("macos-arm64", manifest["app_update"]["platform"])

    def test_release_manifest_still_supports_windows_x64_releases(self) -> None:
        created = self.active_customer("windows-release@example.com")
        self.strategy_release(version="2.0.0", platform="windows-x64")
        desktop = self.desktop_release(version="0.2.0", platform="windows-x64")

        manifest = self.service.release_manifest(
            license_key=created.license_key,
            email=None,
            customer_id=None,
            whop_user_id=None,
            machine_fingerprint="windows-release-machine",
            app_version="0.1.0",
            channel="stable",
            platform="windows-x64",
            include_types=["strategy_package", "trader_desktop"],
            ip_address=None,
            user_agent=None,
            check_interval_seconds=3600,
            grace_period_seconds=86400,
        )

        self.assertEqual("active", manifest["status"])
        self.assertEqual("windows-x64", manifest["platform"])
        self.assertEqual(["2.0.0"], [release["version"] for release in manifest["releases"]])
        self.assertEqual("windows-x64", manifest["releases"][0]["platform"])
        self.assertEqual(desktop["id"], manifest["app_update"]["release_id"])
        self.assertEqual("windows-x64", manifest["app_update"]["platform"])

    def test_release_manifest_platform_mismatch_returns_no_releases_or_update(self) -> None:
        created = self.active_customer("platform-mismatch@example.com")
        self.strategy_release(version="2.0.0", platform="macos-arm64")
        self.desktop_release(version="0.2.0", platform="macos-arm64")

        manifest = self.service.release_manifest(
            license_key=created.license_key,
            email=None,
            customer_id=None,
            whop_user_id=None,
            machine_fingerprint="platform-mismatch-machine",
            app_version="0.1.0",
            channel="stable",
            platform="windows-x64",
            include_types=["strategy_package", "trader_desktop"],
            ip_address=None,
            user_agent=None,
            check_interval_seconds=3600,
            grace_period_seconds=86400,
        )

        self.assertEqual("active", manifest["status"])
        self.assertEqual("windows-x64", manifest["platform"])
        self.assertEqual([], manifest["releases"])
        self.assertIsNone(manifest["app_update"])

    def test_stable_customer_only_sees_stable_release(self) -> None:
        created = self.active_customer("stable-only@example.com")
        self.strategy_release(version="1.0.0", channel="stable")
        self.strategy_release(version="1.1.0", channel="beta")

        manifest = self.service.release_manifest(
            license_key=created.license_key,
            email=None,
            customer_id=None,
            whop_user_id=None,
            machine_fingerprint="stable-only-machine",
            app_version="0.9.0",
            channel="stable",
            platform="windows-x64",
            include_types=["strategy_package"],
            ip_address=None,
            user_agent=None,
            check_interval_seconds=3600,
            grace_period_seconds=86400,
        )

        self.assertEqual(["1.0.0"], [release["version"] for release in manifest["releases"]])

    def test_tester_role_sees_beta_targeted_release(self) -> None:
        created = self.active_customer("desktop-beta@example.com")
        self.service.set_customer_tags(
            customer_id=created.customer["id"],
            tags="desktop_beta",
            actor_id="admin",
            ip_address=None,
        )
        release = self.desktop_release(
            version="0.2.0",
            channel="beta",
            audience_mode="roles",
            required_tags="desktop_beta",
        )

        manifest = self.service.release_manifest(
            license_key=created.license_key,
            email=None,
            customer_id=None,
            whop_user_id=None,
            machine_fingerprint="desktop-beta-machine",
            app_version="0.1.0",
            channel="stable",
            platform="windows-x64",
            include_types=["trader_desktop"],
            ip_address=None,
            user_agent=None,
            check_interval_seconds=3600,
            grace_period_seconds=86400,
        )

        self.assertEqual(release["id"], manifest["app_update"]["release_id"])
        self.assertEqual("update", manifest["app_update"]["action"])

    def test_internal_role_sees_internal_release(self) -> None:
        created = self.active_customer("internal-release@example.com")
        self.service.set_customer_tags(
            customer_id=created.customer["id"],
            tags="internal",
            actor_id="admin",
            ip_address=None,
        )
        self.strategy_release(version="1.0.0", channel="stable")
        self.strategy_release(version="1.2.0", channel="internal", audience_mode="roles", required_tags="internal")

        manifest = self.service.release_manifest(
            license_key=created.license_key,
            email=None,
            customer_id=None,
            whop_user_id=None,
            machine_fingerprint="internal-release-machine",
            app_version="0.9.0",
            channel="stable",
            platform="windows-x64",
            include_types=["strategy_package"],
            ip_address=None,
            user_agent=None,
            check_interval_seconds=3600,
            grace_period_seconds=86400,
        )

        self.assertEqual(["1.2.0"], [release["version"] for release in manifest["releases"]])

    def test_allowlisted_email_sees_targeted_release(self) -> None:
        created = self.active_customer("allowlisted@example.com")
        self.strategy_release(
            version="1.3.0",
            channel="beta",
            audience_mode="allowlist",
            allowed_emails="allowlisted@example.com",
        )

        manifest = self.service.release_manifest(
            license_key=created.license_key,
            email=None,
            customer_id=None,
            whop_user_id=None,
            machine_fingerprint="allowlisted-machine",
            app_version="1.0.0",
            channel="stable",
            platform="windows-x64",
            include_types=["strategy_package"],
            ip_address=None,
            user_agent=None,
            check_interval_seconds=3600,
            grace_period_seconds=86400,
        )

        self.assertEqual(["1.3.0"], [release["version"] for release in manifest["releases"]])

    def test_non_allowlisted_customer_does_not_see_targeted_release(self) -> None:
        created = self.active_customer("not-allowlisted@example.com")
        self.strategy_release(
            version="1.3.0",
            channel="stable",
            audience_mode="allowlist",
            allowed_emails="someone-else@example.com",
        )

        manifest = self.service.release_manifest(
            license_key=created.license_key,
            email=None,
            customer_id=None,
            whop_user_id=None,
            machine_fingerprint="not-allowlisted-machine",
            app_version="1.0.0",
            channel="stable",
            platform="windows-x64",
            include_types=["strategy_package"],
            ip_address=None,
            user_agent=None,
            check_interval_seconds=3600,
            grace_period_seconds=86400,
        )

        self.assertEqual([], manifest["releases"])

    def test_percent_rollout_is_deterministic(self) -> None:
        created = self.active_customer("percent@example.com")
        self.strategy_release(version="1.4.0", channel="stable", audience_mode="percent", rollout_percent=50)

        first = self.service.release_manifest(
            license_key=created.license_key,
            email=None,
            customer_id=None,
            whop_user_id=None,
            machine_fingerprint="percent-machine",
            app_version="1.0.0",
            channel="stable",
            platform="windows-x64",
            include_types=["strategy_package"],
            ip_address=None,
            user_agent=None,
            check_interval_seconds=3600,
            grace_period_seconds=86400,
        )
        second = self.service.release_manifest(
            license_key=created.license_key,
            email=None,
            customer_id=None,
            whop_user_id=None,
            machine_fingerprint="percent-machine",
            app_version="1.0.0",
            channel="stable",
            platform="windows-x64",
            include_types=["strategy_package"],
            ip_address=None,
            user_agent=None,
            check_interval_seconds=3600,
            grace_period_seconds=86400,
        )

        self.assertEqual(first["releases"], second["releases"])

    def test_manifest_can_return_trader_desktop_rollback(self) -> None:
        created = self.active_customer("desktop-rollback@example.com")
        self.desktop_release(version="0.1.0", rollback_reason="Rollback bad installer")

        manifest = self.service.release_manifest(
            license_key=created.license_key,
            email=None,
            customer_id=None,
            whop_user_id=None,
            machine_fingerprint="desktop-rollback-machine",
            app_version="0.1.1",
            channel="stable",
            platform="windows-x64",
            include_types=["trader_desktop"],
            ip_address=None,
            user_agent=None,
            check_interval_seconds=3600,
            grace_period_seconds=86400,
        )

        self.assertEqual("rollback", manifest["app_update"]["action"])
        self.assertEqual("0.1.0", manifest["app_update"]["target_version"])
        self.assertEqual("Rollback bad installer", manifest["app_update"]["rollback_reason"])

    def test_strategy_package_rollback_uses_installed_packages(self) -> None:
        created = self.active_customer("strategy-rollback@example.com")
        self.strategy_release(version="0.1.0", rollback_reason="Rollback strategy package")

        manifest = self.service.release_manifest(
            license_key=created.license_key,
            email=None,
            customer_id=None,
            whop_user_id=None,
            machine_fingerprint="strategy-rollback-machine",
            app_version="9.9.9",
            channel="stable",
            platform="windows-x64",
            include_types=["strategy_package"],
            installed_packages=[{"package_id": "duo-runtime", "version": "0.1.1"}],
            ip_address=None,
            user_agent=None,
            check_interval_seconds=3600,
            grace_period_seconds=86400,
        )

        self.assertEqual("rollback", manifest["releases"][0]["action"])
        self.assertEqual("0.1.0", manifest["releases"][0]["target_version"])
        self.assertEqual("0.1.1", manifest["releases"][0]["current_version"])

    def test_download_token_denied_when_audience_denies_release(self) -> None:
        created = self.active_customer("token-audience@example.com")
        release = self.strategy_release(
            version="1.5.0",
            channel="stable",
            audience_mode="allowlist",
            allowed_emails="someone-else@example.com",
        )

        token = self.service.create_release_download_token(
            release_id=release["id"],
            license_key=created.license_key,
            email=None,
            customer_id=None,
            whop_user_id=None,
            machine_fingerprint="token-audience-machine",
            app_version="1.0.0",
            channel="stable",
            platform="windows-x64",
            ip_address=None,
            user_agent=None,
            check_interval_seconds=3600,
            grace_period_seconds=86400,
            token_seconds=600,
        )

        self.assertEqual("audience_denied", token["status"])
        self.assertIsNone(token["token"])

    def test_disabled_release_is_never_returned(self) -> None:
        created = self.active_customer("disabled-release@example.com")
        self.strategy_release(version="1.6.0", channel="stable", audience_mode="disabled")

        manifest = self.service.release_manifest(
            license_key=created.license_key,
            email=None,
            customer_id=None,
            whop_user_id=None,
            machine_fingerprint="disabled-release-machine",
            app_version="1.0.0",
            channel="stable",
            platform="windows-x64",
            include_types=["strategy_package"],
            ip_address=None,
            user_agent=None,
            check_interval_seconds=3600,
            grace_period_seconds=86400,
        )

        self.assertEqual([], manifest["releases"])

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
            platform="windows-x64",
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
            platform="windows-x64",
            ip_address=None,
            user_agent=None,
            check_interval_seconds=3600,
            grace_period_seconds=86400,
            token_seconds=600,
        )

        self.assertEqual("not_licensed", result["status"])

    def test_blocked_license_cannot_receive_trader_desktop_download_token(self) -> None:
        created = self.service.create_or_update_customer(email="desktop-blocked@example.com")
        self.service.manual_set_entitlement(
            customer_id=created.customer["id"],
            product_id=self.product["id"],
            status="suspended",
            expires_at=iso(utc_now() + timedelta(days=30)),
            reason="payment failed",
            actor_id="admin",
            ip_address=None,
        )
        artifact_dir = Path(self.tmp.name) / "desktop-blocked-artifacts"
        artifact_dir.mkdir()
        release = self.service.upsert_release(
            release_id=None,
            scope="app",
            release_type="trader_desktop",
            product_key="trader-desktop",
            product_id=None,
            channel="stable",
            platform="windows-x64",
            version="0.1.1",
            min_supported_version=None,
            is_required=False,
            is_active=True,
            artifact_path="Trader-Setup-0.1.1-windows-x64.zip",
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
            machine_fingerprint="desktop-blocked-machine",
            app_version="0.1.0",
            ip_address=None,
            user_agent=None,
            check_interval_seconds=3600,
            grace_period_seconds=86400,
            token_seconds=600,
        )

        self.assertEqual("suspended", token["status"])
        self.assertIsNone(token["token"])

    def test_device_limit_blocks_trader_desktop_manifest_and_download_token(self) -> None:
        created = self.active_customer("desktop-device-limit@example.com")
        self.service.check_license(
            license_key=created.license_key,
            email=None,
            customer_id=None,
            whop_user_id=None,
            machine_fingerprint="desktop-limit-first",
            app_version="0.1.0",
            ip_address=None,
            user_agent=None,
            check_interval_seconds=3600,
            grace_period_seconds=86400,
            max_devices=1,
        )
        artifact_dir = Path(self.tmp.name) / "desktop-limit-artifacts"
        artifact_dir.mkdir()
        release = self.service.upsert_release(
            release_id=None,
            scope="app",
            release_type="trader_desktop",
            product_key="trader-desktop",
            product_id=None,
            channel="stable",
            platform="windows-x64",
            version="0.1.1",
            min_supported_version=None,
            is_required=False,
            is_active=True,
            artifact_path="Trader-Setup-0.1.1-windows-x64.zip",
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
            machine_fingerprint="desktop-limit-second",
            app_version="0.1.0",
            channel="stable",
            platform="windows-x64",
            include_types=["trader_desktop"],
            ip_address=None,
            user_agent=None,
            check_interval_seconds=3600,
            grace_period_seconds=86400,
            max_devices=1,
        )
        token = self.service.create_release_download_token(
            release_id=release["id"],
            license_key=created.license_key,
            email=None,
            customer_id=None,
            whop_user_id=None,
            machine_fingerprint="desktop-limit-third",
            app_version="0.1.0",
            ip_address=None,
            user_agent=None,
            check_interval_seconds=3600,
            grace_period_seconds=86400,
            token_seconds=600,
            max_devices=1,
        )

        self.assertEqual("device_limit_exceeded", manifest["status"])
        self.assertIsNone(manifest["app_update"])
        self.assertEqual("device_limit_exceeded", token["status"])
        self.assertIsNone(token["token"])

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
