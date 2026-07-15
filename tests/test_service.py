from __future__ import annotations

import base64
import json
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from hashlib import sha256
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
        nt8_version: str | None = None,
        trader_revision: int | None = None,
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
            nt8_version=nt8_version,
            trader_revision=trader_revision,
        )

    def strategy_manifest(
        self,
        created,
        *,
        installed_packages: list[dict[str, str]] | None,
        platform: str = "windows-x64",
        channel: str = "stable",
        app_version: str = "9.9.9",
    ):
        return self.service.release_manifest(
            license_key=created.license_key,
            email=None,
            customer_id=None,
            whop_user_id=None,
            machine_fingerprint=f"strategy-manifest-{created.customer['id']}",
            app_version=app_version,
            channel=channel,
            platform=platform,
            include_types=["strategy_package"],
            installed_packages=installed_packages,
            ip_address=None,
            user_agent=None,
            check_interval_seconds=3600,
            grace_period_seconds=86400,
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
        path = f"TraderPro-Desktop-{version}-{platform}.zip"
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
            release_notes="TraderPro Desktop update",
            artifact_dir=str(artifact_dir),
            audience_mode=audience_mode,
            allowed_customer_ids=allowed_customer_ids,
            allowed_emails=allowed_emails,
            required_tags=required_tags,
            rollout_percent=rollout_percent,
            rollback_reason=rollback_reason,
        )

    def discord_product(self):
        return self.service.upsert_product(
            slug="discord-notifier",
            name="Discord Notifier",
            feature_id="trader.notifications.discord",
            nt8_enabled=False,
            metadata={"seeded": True, "package_kind": "extension", "release_type": "extension_package"},
        )

    def extension_release(
        self,
        *,
        product_id: str | None = None,
        version: str = "1.0.0",
        channel: str = "stable",
        platform: str = "windows-x64",
        audience_mode: str = "all",
        allowed_customer_ids: str | None = None,
        allowed_emails: str | None = None,
        allowed_license_keys: str | None = None,
        required_tags: str | None = None,
        rollout_percent: int | None = None,
    ):
        product = self.discord_product()
        artifact_dir = Path(self.tmp.name) / "extension-test-artifacts"
        artifact_dir.mkdir(exist_ok=True)
        path = f"discord-notifier-{version}-{channel}-{platform}.zip"
        (artifact_dir / path).write_bytes(f"discord notifier {version}".encode())
        return self.service.upsert_release(
            release_id=None,
            scope="strategy",
            release_type="extension_package",
            product_key="discord-notifier",
            product_id=product_id or product["id"],
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
            release_notes="Discord Notifier release",
            artifact_dir=str(artifact_dir),
            audience_mode=audience_mode,
            allowed_customer_ids=allowed_customer_ids,
            allowed_emails=allowed_emails,
            allowed_license_keys=allowed_license_keys,
            required_tags=required_tags,
            rollout_percent=rollout_percent,
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

    def test_manual_customers_can_share_blank_whop_fields(self) -> None:
        first = self.service.create_or_update_customer(
            email="first-manual@example.com",
            name="First Manual",
            whop_user_id="",
            whop_member_id="",
        )
        second = self.service.create_or_update_customer(
            email="second-manual@example.com",
            name="Second Manual",
            whop_user_id=" ",
            whop_member_id="\t",
        )

        self.assertNotEqual(first.customer["id"], second.customer["id"])
        self.assertIsNone(first.customer["whop_user_id"])
        self.assertIsNone(first.customer["whop_member_id"])
        self.assertIsNone(second.customer["whop_user_id"])
        self.assertIsNone(second.customer["whop_member_id"])

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

    def test_manual_grant_expiry_can_be_replaced_in_both_directions(self) -> None:
        created = self.service.create_or_update_customer(email="replace-expiry@example.com")
        later_expiry = "2026-12-31T23:59:00Z"
        earlier_expiry = "2026-07-15T18:19:06Z"

        self.service.manual_set_entitlement(
            customer_id=created.customer["id"],
            product_id=self.product["id"],
            status="active",
            expires_at=later_expiry,
            reason="initial dated grant",
            actor_id="admin",
            ip_address=None,
        )
        shortened = self.service.manual_set_entitlement(
            customer_id=created.customer["id"],
            product_id=self.product["id"],
            status="active",
            expires_at=earlier_expiry,
            reason="shortened dated grant",
            actor_id="admin",
            ip_address=None,
        )
        lifetime = self.service.manual_set_entitlement(
            customer_id=created.customer["id"],
            product_id=self.product["id"],
            status="active",
            expires_at=None,
            reason="lifetime grant",
            actor_id="admin",
            ip_address=None,
        )
        dated_again = self.service.manual_set_entitlement(
            customer_id=created.customer["id"],
            product_id=self.product["id"],
            status="active",
            expires_at=earlier_expiry,
            reason="dated again",
            actor_id="admin",
            ip_address=None,
        )

        self.assertEqual(earlier_expiry, shortened["expires_at"])
        self.assertIsNone(lifetime["expires_at"])
        self.assertEqual(earlier_expiry, dated_again["expires_at"])

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

    def test_remove_entitlement_deletes_row_and_audits(self) -> None:
        created = self.service.create_or_update_customer(email="remove-service@example.com")
        entitlement = self.service.manual_set_entitlement(
            customer_id=created.customer["id"],
            product_id=self.product["id"],
            status="active",
            expires_at=None,
            reason="temporary",
            actor_id="admin",
            ip_address=None,
        )

        removed = self.service.remove_entitlement(
            customer_id=created.customer["id"],
            entitlement_id=entitlement["id"],
            actor_id="admin",
            ip_address=None,
        )
        detail = self.service.customer_detail(created.customer["id"])
        response = self.service.check_license(
            license_key=created.license_key,
            email=None,
            customer_id=None,
            whop_user_id=None,
            machine_fingerprint="machine-removed",
            app_version=None,
            ip_address=None,
            user_agent=None,
            check_interval_seconds=3600,
            grace_period_seconds=86400,
        )

        self.assertTrue(removed)
        self.assertEqual([], detail["entitlements"])
        self.assertTrue(any(audit["action"] == "entitlement.removed" for audit in detail["audit"]))
        self.assertEqual("unlicensed", response["status"])
        removed_state = next(
            state for state in response["entitlement_states"] if state["product_id"] == self.product["id"]
        )
        self.assertEqual("removed", removed_state["status"])
        self.assertEqual("strategy.duo.runtime", removed_state["feature_id"])
        self.assertIsNotNone(removed_state["changed_at"])

    def test_expired_grant_returns_expired_without_strategies(self) -> None:
        created = self.service.create_or_update_customer(email="expired@example.com")
        expired_at = iso(utc_now() - timedelta(days=1))
        self.service.manual_set_entitlement(
            customer_id=created.customer["id"],
            product_id=self.product["id"],
            status="expired",
            expires_at=expired_at,
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
        expired_state = response["entitlement_states"][0]
        self.assertEqual("expired", expired_state["status"])
        self.assertEqual(expired_at, expired_state["expires_at"])
        self.assertIsNotNone(expired_state["changed_at"])

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

        response = self.service.check_license(
            license_key=None,
            email="trial@example.com",
            customer_id=None,
            whop_user_id=None,
            machine_fingerprint="machine-trial-paid",
            app_version=None,
            ip_address=None,
            user_agent=None,
            check_interval_seconds=3600,
            grace_period_seconds=86400,
        )
        self.assertEqual("active", response["status"])
        self.assertGreaterEqual(parse_time(response["expires_at"]), trial_end + timedelta(days=29))

    def test_manually_extended_trial_remains_effective_after_payment(self) -> None:
        package = self.service.upsert_whop_package(
            package_id=None,
            whop_id="plan_manual_trial_paid",
            whop_id_type="plan",
            name="DUO 30 days",
            default_days=30,
            is_active=True,
            is_ignored=False,
            grants=[{"product_id": self.product["id"], "days": 30}],
        )
        customer = self.service.create_or_update_customer(email="manual-trial-paid@example.com")
        initial_trial_end = utc_now() + timedelta(days=7)
        extended_trial_end = utc_now() + timedelta(days=60)
        self.service.manual_set_entitlement(
            customer_id=customer.customer["id"],
            product_id=self.product["id"],
            status="trialing",
            expires_at=iso(initial_trial_end),
            reason="initial trial",
            actor_id="admin",
            ip_address=None,
        )
        self.service.manual_set_entitlement(
            customer_id=customer.customer["id"],
            product_id=self.product["id"],
            status="trialing",
            expires_at=iso(extended_trial_end),
            reason="extended trial",
            actor_id="admin",
            ip_address=None,
        )
        paid_end = utc_now() + timedelta(days=30)
        paid = self.service.process_whop_event(
            {
                "type": "payment.succeeded",
                "data": {
                    "id": "pay_manual_trial_paid",
                    "status": "paid",
                    "email": "manual-trial-paid@example.com",
                    "user_id": "user_manual_trial_paid",
                    "plan_id": "plan_manual_trial_paid",
                    "membership_id": "mem_manual_trial_paid",
                    "current_period_start": iso(utc_now()),
                    "current_period_end": iso(paid_end),
                },
            },
            "evt_manual_trial_paid",
            signature_valid=True,
            ip_address=None,
        )

        detail = self.service.customer_detail(customer.customer["id"])
        response = self.service.check_license(
            license_key=customer.license_key,
            email=None,
            customer_id=None,
            whop_user_id=None,
            machine_fingerprint="machine-manual-trial-paid",
            app_version=None,
            ip_address=None,
            user_agent=None,
            check_interval_seconds=3600,
            grace_period_seconds=86400,
        )

        self.assertEqual(package["id"], paid["package_id"])
        self.assertEqual(2, len(detail["entitlements"]))
        self.assertEqual("active", response["status"])
        self.assertGreaterEqual(parse_time(response["expires_at"]), extended_trial_end - timedelta(seconds=1))

    def test_standalone_trial_and_bundle_are_independent_sources(self) -> None:
        standalone = self.service.upsert_whop_package(
            package_id=None,
            whop_id="plan_standalone_trial",
            whop_id_type="plan",
            name="DUO standalone trial",
            default_days=7,
            is_active=True,
            is_ignored=False,
            grants=[{"product_id": self.product["id"], "days": 7}],
        )
        bundle = self.service.upsert_whop_package(
            package_id=None,
            whop_id="plan_bundle_paid",
            whop_id_type="plan",
            name="Strategy bundle",
            default_days=30,
            is_active=True,
            is_ignored=False,
            grants=[{"product_id": self.product["id"], "days": 30}],
        )
        now = utc_now().replace(microsecond=0)
        trial_end = now + timedelta(days=7)
        paid_end = trial_end + timedelta(days=30)
        shared_membership_id = "mem_standalone_to_bundle"
        self.service.process_whop_event(
            {
                "action": "membership.activated",
                "data": {
                    "id": shared_membership_id,
                    "status": "trialing",
                    "email": "standalone-bundle@example.com",
                    "user_id": "user_standalone_bundle",
                    "plan_id": "plan_standalone_trial",
                    "trial_ends_at": iso(trial_end),
                },
            },
            "evt_standalone_trial",
            signature_valid=True,
            ip_address=None,
        )
        paid = self.service.process_whop_event(
            {
                "type": "payment.succeeded",
                "data": {
                    "id": "pay_standalone_bundle",
                    "status": "paid",
                    "membership_id": shared_membership_id,
                    "email": "standalone-bundle@example.com",
                    "user_id": "user_standalone_bundle",
                    "plan_id": "plan_bundle_paid",
                    "current_period_start": iso(trial_end),
                    "current_period_end": iso(paid_end),
                },
            },
            "evt_bundle_paid",
            signature_valid=True,
            ip_address=None,
        )
        self.service.process_whop_event(
            {
                "action": "membership.expired",
                "data": {
                    "id": shared_membership_id,
                    "status": "expired",
                    "email": "standalone-bundle@example.com",
                    "user_id": "user_standalone_bundle",
                    "plan_id": "plan_standalone_trial",
                    "current_period_end": iso(trial_end),
                },
            },
            "evt_standalone_expired",
            signature_valid=True,
            ip_address=None,
        )

        detail = self.service.customer_detail(paid["customer_id"])
        response = self.service.check_license(
            license_key=None,
            email="standalone-bundle@example.com",
            customer_id=None,
            whop_user_id=None,
            machine_fingerprint="machine-standalone-bundle",
            app_version=None,
            ip_address=None,
            user_agent=None,
            check_interval_seconds=3600,
            grace_period_seconds=86400,
        )

        self.assertEqual(2, len(detail["entitlements"]))
        self.assertEqual({standalone["id"], bundle["id"]}, {row["package_id"] for row in detail["entitlements"]})
        self.assertEqual("active", response["status"])
        self.assertGreaterEqual(parse_time(response["expires_at"]), paid_end)

    def test_old_expiration_after_paid_grant_does_not_override_paid_expiry(self) -> None:
        self.service.upsert_whop_package(
            package_id=None,
            whop_id="plan_old_trial_expiry",
            whop_id_type="plan",
            name="DUO trial then paid",
            default_days=30,
            is_active=True,
            is_ignored=False,
            grants=[{"product_id": self.product["id"], "days": 30}],
        )
        now = utc_now().replace(microsecond=0)
        trial_end = now + timedelta(days=7)
        paid_end = trial_end + timedelta(days=30)
        common = {
            "id": "mem_old_trial_expiry",
            "email": "old-trial-expiry@example.com",
            "user_id": "user_old_trial_expiry",
            "plan_id": "plan_old_trial_expiry",
        }
        self.service.process_whop_event(
            {"action": "membership.activated", "data": {**common, "status": "trialing", "trial_ends_at": iso(trial_end)}},
            "evt_old_trial_started",
            signature_valid=True,
            ip_address=None,
        )
        paid = self.service.process_whop_event(
            {
                "action": "membership.renewed",
                "data": {
                    **common,
                    "status": "active",
                    "payment_id": "pay_old_trial_expiry",
                    "current_period_start": iso(trial_end),
                    "current_period_end": iso(paid_end),
                },
            },
            "evt_old_trial_paid",
            signature_valid=True,
            ip_address=None,
        )
        expired = self.service.process_whop_event(
            {
                "action": "membership.expired",
                "data": {**common, "status": "expired", "trial_ends_at": iso(trial_end), "current_period_end": iso(trial_end)},
            },
            "evt_old_trial_expired_late",
            signature_valid=True,
            ip_address=None,
        )

        detail = self.service.customer_detail(paid["customer_id"])
        entitlement = detail["entitlements"][0]
        response = self.service.check_license(
            license_key=None,
            email="old-trial-expiry@example.com",
            customer_id=None,
            whop_user_id=None,
            machine_fingerprint="machine-old-trial-expiry",
            app_version=None,
            ip_address=None,
            user_agent=None,
            check_interval_seconds=3600,
            grace_period_seconds=86400,
        )

        self.assertEqual("renewal", paid["applied_grants"][0]["grant_kind"])
        self.assertEqual("active", expired["applied_grants"][0]["status"])
        self.assertEqual("active", entitlement["status"])
        self.assertGreaterEqual(parse_time(entitlement["expires_at"]), paid_end)
        self.assertEqual("active", response["status"])

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

    def test_duplicate_payment_and_renewal_event_apply_period_once(self) -> None:
        self.service.upsert_whop_package(
            package_id=None,
            whop_id="plan_duplicate_payment_renewal",
            whop_id_type="plan",
            name="DUO duplicate payment renewal",
            default_days=30,
            is_active=True,
            is_ignored=False,
            grants=[{"product_id": self.product["id"], "days": 30}],
        )
        period_start = utc_now().replace(microsecond=0)
        period_end = period_start + timedelta(days=30)
        common = {
            "status": "active",
            "email": "duplicate-payment-renewal@example.com",
            "user_id": "user_duplicate_payment_renewal",
            "membership_id": "mem_duplicate_payment_renewal",
            "plan_id": "plan_duplicate_payment_renewal",
            "payment_id": "pay_duplicate_payment_renewal",
            "current_period_start": iso(period_start),
            "current_period_end": iso(period_end),
        }
        first = self.service.process_whop_event(
            {"type": "payment.succeeded", "data": {"id": "pay_duplicate_payment_renewal", **common}},
            "evt_duplicate_payment",
            signature_valid=True,
            ip_address=None,
        )
        first_expiry = first["applied_grants"][0]["expires_at"]
        second = self.service.process_whop_event(
            {"action": "membership.renewed", "data": {"id": "mem_duplicate_payment_renewal", **common}},
            "evt_duplicate_renewal",
            signature_valid=True,
            ip_address=None,
        )

        with self.database.session() as connection:
            grant_count = connection.execute(
                "SELECT COUNT(*) FROM license_grant_ledger WHERE grant_kind IN ('paid', 'renewal')"
            ).fetchone()[0]
            entitlement = connection.execute(
                "SELECT * FROM entitlements WHERE customer_id = ?",
                (first["customer_id"],),
            ).fetchone()

        self.assertEqual("duplicate_grant", second["applied_grants"][0]["status"])
        self.assertEqual(1, grant_count)
        self.assertEqual(parse_time(first_expiry), parse_time(entitlement["expires_at"]))

    def test_final_explicit_revocation_blocks_when_no_source_remains(self) -> None:
        self.service.upsert_whop_package(
            package_id=None,
            whop_id="plan_final_revocation",
            whop_id_type="plan",
            name="DUO revocation",
            default_days=30,
            is_active=True,
            is_ignored=False,
            grants=[{"product_id": self.product["id"], "days": 30}],
        )
        common = {
            "id": "mem_final_revocation",
            "email": "final-revocation@example.com",
            "user_id": "user_final_revocation",
            "plan_id": "plan_final_revocation",
        }
        active = self.service.process_whop_event(
            {
                "action": "membership.went_valid",
                "data": {**common, "status": "active", "current_period_end": iso(utc_now() + timedelta(days=30))},
            },
            "evt_final_revocation_active",
            signature_valid=True,
            ip_address=None,
        )
        revoked = self.service.process_whop_event(
            {"action": "membership.went_invalid", "data": {**common, "status": "invalid"}},
            "evt_final_revocation",
            signature_valid=True,
            ip_address=None,
        )
        response = self.service.check_license(
            license_key=None,
            email="final-revocation@example.com",
            customer_id=None,
            whop_user_id=None,
            machine_fingerprint="machine-final-revocation",
            app_version=None,
            ip_address=None,
            user_agent=None,
            check_interval_seconds=3600,
            grace_period_seconds=86400,
        )
        detail = self.service.customer_detail(active["customer_id"])

        self.assertEqual("revoke", revoked["applied_grants"][0]["grant_kind"])
        self.assertEqual("revoked", detail["entitlements"][0]["status"])
        self.assertEqual("revoked", response["status"])

    def test_lifetime_grant_ignores_expiration_update(self) -> None:
        common = {
            "id": "mem_lifetime",
            "email": "lifetime@example.com",
            "user_id": "user_lifetime",
            "product_id": "prod_duo",
        }
        active = self.service.process_whop_event(
            {"action": "membership.went_valid", "data": {**common, "status": "active"}},
            "evt_lifetime_active",
            signature_valid=True,
            ip_address=None,
        )
        expired = self.service.process_whop_event(
            {
                "action": "membership.expired",
                "data": {**common, "status": "expired", "current_period_end": iso(utc_now() - timedelta(days=1))},
            },
            "evt_lifetime_expiration",
            signature_valid=True,
            ip_address=None,
        )
        detail = self.service.customer_detail(active["customer_id"])
        response = self.service.check_license(
            license_key=None,
            email="lifetime@example.com",
            customer_id=None,
            whop_user_id=None,
            machine_fingerprint="machine-lifetime",
            app_version=None,
            ip_address=None,
            user_agent=None,
            check_interval_seconds=3600,
            grace_period_seconds=86400,
        )

        self.assertEqual("active", expired["entitlement_status"])
        self.assertEqual("active", detail["entitlements"][0]["status"])
        self.assertIsNone(detail["entitlements"][0]["expires_at"])
        self.assertEqual("active", response["status"])
        self.assertIsNone(response["expires_at"])

    def test_concurrent_out_of_order_grants_keep_later_expiration(self) -> None:
        self.service.upsert_whop_package(
            package_id=None,
            whop_id="plan_concurrent_grants",
            whop_id_type="plan",
            name="DUO concurrent grants",
            default_days=30,
            is_active=True,
            is_ignored=False,
            grants=[{"product_id": self.product["id"], "days": 30}],
        )
        self.service.create_or_update_customer(
            email="concurrent-grants@example.com",
            whop_user_id="user_concurrent_grants",
            whop_member_id="mem_concurrent_grants",
        )
        period_start = utc_now().replace(microsecond=0)
        later_end = period_start + timedelta(days=60)

        def apply_event(name: str, start_offset: int, end_offset: int) -> dict:
            return self.service.process_whop_event(
                {
                    "action": "membership.renewed",
                    "data": {
                        "id": "mem_concurrent_grants",
                        "status": "active",
                        "email": "concurrent-grants@example.com",
                        "user_id": "user_concurrent_grants",
                        "plan_id": "plan_concurrent_grants",
                        "current_period_start": iso(period_start + timedelta(days=start_offset)),
                        "current_period_end": iso(period_start + timedelta(days=end_offset)),
                    },
                },
                f"evt_concurrent_{name}",
                signature_valid=True,
                ip_address=None,
            )

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(lambda args: apply_event(*args), [("older", 0, 30), ("newer", 30, 60)]))

        detail = self.service.customer_detail(results[0]["customer_id"])
        entitlement = detail["entitlements"][0]
        subscription = detail["subscriptions"][0]

        self.assertEqual(2, len(results))
        self.assertGreaterEqual(parse_time(entitlement["expires_at"]), later_end)
        self.assertGreaterEqual(parse_time(subscription["current_period_end"]), later_end)

    def test_payment_succeeded_and_membership_activated_do_not_add_days_twice(self) -> None:
        self.service.upsert_whop_package(
            package_id=None,
            whop_id="plan_pay_activation_90",
            whop_id_type="plan",
            name="DUO 90 days",
            default_days=90,
            is_active=True,
            is_ignored=False,
            grants=[{"product_id": self.product["id"], "days": 90}],
        )
        period_start = utc_now().replace(microsecond=0)
        period_end = period_start + timedelta(days=90)
        payment = self.service.process_whop_event(
            {
                "type": "payment.succeeded",
                "data": {
                    "id": "pay_same_period_001",
                    "status": "succeeded",
                    "email": "same-period@example.com",
                    "user_id": "user_same_period",
                    "plan_id": "plan_pay_activation_90",
                    "created_at": iso(period_start),
                    "membership": {"id": "mem_same_period_001", "status": "active"},
                },
            },
            "evt_same_period_payment",
            signature_valid=True,
            ip_address=None,
        )
        activated = self.service.process_whop_event(
            {
                "action": "membership.activated",
                "data": {
                    "id": "mem_same_period_001",
                    "status": "active",
                    "email": "same-period@example.com",
                    "user_id": "user_same_period",
                    "plan_id": "plan_pay_activation_90",
                    "renewal_period_start": iso(period_start),
                    "renewal_period_end": iso(period_end),
                },
            },
            "evt_same_period_activated",
            signature_valid=True,
            ip_address=None,
        )
        detail = self.service.customer_detail(payment["customer_id"])
        expires_at = parse_time(detail["entitlements"][0]["expires_at"])

        self.assertEqual("paid", payment["applied_grants"][0]["grant_kind"])
        self.assertEqual("duplicate_grant", activated["applied_grants"][0]["status"])
        self.assertLess(expires_at, period_start + timedelta(days=92))

    def test_cancel_at_period_end_changed_keeps_entitlement_active(self) -> None:
        self.service.upsert_whop_package(
            package_id=None,
            whop_id="plan_cancel_later_90",
            whop_id_type="plan",
            name="DUO 90 days",
            default_days=90,
            is_active=True,
            is_ignored=False,
            grants=[{"product_id": self.product["id"], "days": 90}],
        )
        period_start = utc_now().replace(microsecond=0)
        period_end = period_start + timedelta(days=90)
        active = self.service.process_whop_event(
            {
                "type": "payment.succeeded",
                "data": {
                    "id": "pay_cancel_later_001",
                    "status": "succeeded",
                    "email": "cancel-later@example.com",
                    "user_id": "user_cancel_later",
                    "plan_id": "plan_cancel_later_90",
                    "created_at": iso(period_start),
                    "membership": {"id": "mem_cancel_later_001", "status": "active"},
                },
            },
            "evt_cancel_later_payment",
            signature_valid=True,
            ip_address=None,
        )
        cancel_at_period_end = self.service.process_whop_event(
            {
                "action": "membership.cancel_at_period_end_changed",
                "data": {
                    "id": "mem_cancel_later_001",
                    "status": "active",
                    "email": "cancel-later@example.com",
                    "user_id": "user_cancel_later",
                    "plan_id": "plan_cancel_later_90",
                    "cancel_at_period_end": True,
                    "renewal_period_start": iso(period_start),
                    "renewal_period_end": iso(period_end),
                },
            },
            "evt_cancel_later_changed",
            signature_valid=True,
            ip_address=None,
        )
        detail = self.service.customer_detail(active["customer_id"])
        entitlement = detail["entitlements"][0]
        response = self.service.check_license(
            license_key=None,
            email="cancel-later@example.com",
            customer_id=None,
            whop_user_id=None,
            machine_fingerprint="machine-cancel-later",
            app_version=None,
            ip_address=None,
            user_agent=None,
            check_interval_seconds=3600,
            grace_period_seconds=86400,
        )

        self.assertEqual("ignored", cancel_at_period_end["applied_grants"][0]["grant_kind"])
        self.assertEqual("active", entitlement["status"])
        self.assertEqual(1, len(detail["effective_entitlements"]))
        self.assertEqual("active", detail["effective_entitlements"][0]["status"])
        self.assertEqual("active", response["status"])
        self.assertEqual(parse_time(entitlement["expires_at"]), parse_time(active["applied_grants"][0]["expires_at"]))

    def test_customer_detail_effective_entitlements_are_one_current_row_per_product(self) -> None:
        expired_product = self.service.upsert_product(
            slug="duorc-runtime",
            name="DUOrc Runtime",
            feature_id="strategy.duorc.runtime",
            whop_product_id="prod_duorc",
        )
        customer = self.service.create_or_update_customer(email="current-grants@example.com")
        now = utc_now().replace(microsecond=0)
        older = now - timedelta(days=2)
        newer_inactive = now - timedelta(days=1)
        current_expiry = now + timedelta(days=90)

        with self.database.session() as connection:
            connection.execute(
                """
                INSERT INTO subscriptions(
                    id, customer_id, whop_membership_id, whop_plan_id, status, raw_status,
                    current_period_start, current_period_end, cancel_at_period_end, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)
                """,
                (
                    "sub-old",
                    customer.customer["id"],
                    "mem_old",
                    "plan_old",
                    "expired",
                    "expired",
                    iso(older - timedelta(days=30)),
                    iso(older),
                    iso(older),
                    iso(older),
                ),
            )
            connection.execute(
                """
                INSERT INTO subscriptions(
                    id, customer_id, whop_membership_id, whop_plan_id, status, raw_status,
                    current_period_start, current_period_end, cancel_at_period_end, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)
                """,
                (
                    "sub-current",
                    customer.customer["id"],
                    "mem_current",
                    "plan_current",
                    "active",
                    "active",
                    iso(now),
                    iso(current_expiry),
                    iso(now),
                    iso(now),
                ),
            )
            connection.execute(
                """
                INSERT INTO entitlements(
                    id, customer_id, product_id, subscription_id, external_id, source, status,
                    starts_at, expires_at, revoked_at, whop_event_id, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, 'whop', ?, ?, ?, NULL, ?, ?, ?)
                """,
                (
                    "ent-old",
                    customer.customer["id"],
                    self.product["id"],
                    "sub-old",
                    "mem_old",
                    "expired",
                    iso(older - timedelta(days=30)),
                    iso(older),
                    "evt-old",
                    iso(older),
                    iso(older),
                ),
            )
            connection.execute(
                """
                INSERT INTO entitlements(
                    id, customer_id, product_id, subscription_id, external_id, source, status,
                    starts_at, expires_at, revoked_at, whop_event_id, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, 'whop', ?, ?, ?, NULL, ?, ?, ?)
                """,
                (
                    "ent-current",
                    customer.customer["id"],
                    self.product["id"],
                    "sub-current",
                    "mem_current",
                    "active",
                    iso(now),
                    iso(current_expiry),
                    "evt-current",
                    iso(now),
                    iso(now),
                ),
            )
            connection.execute(
                """
                INSERT INTO entitlements(
                    id, customer_id, product_id, subscription_id, external_id, source, status,
                    starts_at, expires_at, revoked_at, whop_event_id, created_at, updated_at
                )
                VALUES (?, ?, ?, NULL, ?, 'whop', ?, ?, ?, NULL, ?, ?, ?)
                """,
                (
                    "ent-inactive-old",
                    customer.customer["id"],
                    expired_product["id"],
                    "expired-old",
                    "expired",
                    iso(older - timedelta(days=30)),
                    iso(older),
                    "evt-inactive-old",
                    iso(older),
                    iso(older),
                ),
            )
            connection.execute(
                """
                INSERT INTO entitlements(
                    id, customer_id, product_id, subscription_id, external_id, source, status,
                    starts_at, expires_at, revoked_at, whop_event_id, created_at, updated_at
                )
                VALUES (?, ?, ?, NULL, ?, 'whop', ?, ?, ?, NULL, ?, ?, ?)
                """,
                (
                    "ent-inactive-new",
                    customer.customer["id"],
                    expired_product["id"],
                    "expired-new",
                    "expired",
                    iso(newer_inactive - timedelta(days=30)),
                    iso(newer_inactive),
                    "evt-inactive-new",
                    iso(newer_inactive),
                    iso(newer_inactive),
                ),
            )

        detail = self.service.customer_detail(customer.customer["id"])
        effective_by_product = {entitlement["product_id"]: entitlement for entitlement in detail["effective_entitlements"]}

        self.assertEqual(4, len(detail["entitlements"]))
        self.assertEqual(2, len(detail["effective_entitlements"]))
        self.assertEqual("active", effective_by_product[self.product["id"]]["status"])
        self.assertEqual("mem_current", effective_by_product[self.product["id"]]["whop_membership_id"])
        self.assertEqual("expired", effective_by_product[expired_product["id"]]["status"])
        self.assertEqual(iso(newer_inactive), effective_by_product[expired_product["id"]]["expires_at"])

    def test_search_customers_counts_entitled_products_not_raw_rows(self) -> None:
        extra_product = self.service.upsert_product(
            slug="adam-runtime",
            name="ADAM Runtime",
            feature_id="strategy.adam.runtime",
            whop_product_id="prod_adam",
        )
        customer = self.service.create_or_update_customer(email="count-products@example.com")
        now = iso()

        with self.database.session() as connection:
            connection.execute(
                """
                INSERT INTO entitlements(
                    id, customer_id, product_id, external_id, source, status,
                    starts_at, expires_at, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, 'whop', 'expired', ?, ?, ?, ?)
                """,
                ("raw-duo-old", customer.customer["id"], self.product["id"], "raw-duo-old", now, now, now, now),
            )
            connection.execute(
                """
                INSERT INTO entitlements(
                    id, customer_id, product_id, external_id, source, status,
                    starts_at, expires_at, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, 'whop', 'active', ?, NULL, ?, ?)
                """,
                ("raw-duo-current", customer.customer["id"], self.product["id"], "raw-duo-current", now, now, now),
            )
            connection.execute(
                """
                INSERT INTO entitlements(
                    id, customer_id, product_id, external_id, source, status,
                    starts_at, expires_at, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, 'whop', 'active', ?, NULL, ?, ?)
                """,
                ("raw-adam-current", customer.customer["id"], extra_product["id"], "raw-adam-current", now, now, now),
            )

        rows = self.service.search_customers("count-products")

        self.assertEqual(1, len(rows))
        self.assertEqual(2, rows[0]["entitlement_count"])

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
        self.assertEqual(1, [product["slug"] for product in self.service.list_products()].count("duorc-runtime"))

    def test_product_subscription_url_create_update_readback_and_clear(self) -> None:
        first_url = "https://whop.com/auto-edge/example-product/"
        second_url = "https://whop.com/auto-edge/example-renewal/?source=traderpro"
        product = self.service.upsert_product(
            slug="subscription-product",
            name="Subscription Product",
            feature_id="strategy.subscription.runtime",
            subscription_url=first_url,
        )

        self.assertEqual(first_url, product["subscription_url"])
        self.assertEqual(first_url, self.service.get_product(product["id"])["subscription_url"])

        updated = self.service.update_product(
            product_id=product["id"],
            slug=product["slug"],
            name=product["name"],
            feature_id=product["feature_id"],
            whop_product_id=None,
            is_active=True,
            subscription_url=second_url,
        )
        listed = next(item for item in self.service.list_products() if item["id"] == product["id"])

        self.assertEqual(second_url, updated["subscription_url"])
        self.assertEqual(second_url, listed["subscription_url"])

        cleared = self.service.update_product(
            product_id=product["id"],
            slug=product["slug"],
            name=product["name"],
            feature_id=product["feature_id"],
            whop_product_id=None,
            is_active=True,
            subscription_url="",
        )

        self.assertIsNone(cleared["subscription_url"])
        self.assertIsNone(self.service.get_product(product["id"])["subscription_url"])

    def test_product_subscription_url_accepts_only_absolute_https_urls(self) -> None:
        valid = self.service.upsert_product(
            slug="valid-subscription-url",
            name="Valid Subscription URL",
            feature_id="strategy.valid-subscription-url.runtime",
            subscription_url="https://example.com/products/strategy?renew=1#access",
        )
        self.assertEqual(
            "https://example.com/products/strategy?renew=1#access",
            valid["subscription_url"],
        )

        for index, invalid_url in enumerate(
            [
                "http://example.com/product",
                "//example.com/product",
                "/products/strategy",
                "whop.com/auto-edge/product",
                "https://",
                "https://user:password@example.com/product",
                "https://example.com/product with spaces",
            ]
        ):
            with self.subTest(invalid_url=invalid_url), self.assertRaises(ValueError):
                self.service.upsert_product(
                    slug=f"invalid-subscription-url-{index}",
                    name=f"Invalid Subscription URL {index}",
                    feature_id=f"strategy.invalid-subscription-url-{index}.runtime",
                    subscription_url=invalid_url,
                )

    def test_seeded_mich_product_can_be_licensed_and_manifested_after_artifact_registration(self) -> None:
        mich = next(product for product in self.service.list_products() if product["slug"] == "mich-runtime")
        metadata = json.loads(mich["metadata_json"])
        with self.database.session() as connection:
            release_count = connection.execute(
                "SELECT COUNT(*) FROM trader_releases WHERE product_id = ?",
                (mich["id"],),
            ).fetchone()[0]

        self.assertEqual("MICH Runtime", mich["name"])
        self.assertEqual("strategy.mich.runtime", mich["feature_id"])
        self.assertEqual("MICH", mich["nt8_strategy_key"])
        self.assertEqual("mich-runtime", metadata["runtime_package_id"])
        self.assertEqual("strategy_package", metadata["release_type"])
        self.assertEqual("Trader.Strategies.Mich.dll", metadata["entry_assembly"])
        self.assertEqual(["macos-arm64", "windows-x64", "linux-x64"], metadata["supported_platforms"])
        self.assertEqual(0, release_count)

        created = self.service.create_or_update_customer(email="mich-license@example.com")
        self.service.manual_set_entitlement(
            customer_id=created.customer["id"],
            product_id=mich["id"],
            status="active",
            expires_at=iso(utc_now() + timedelta(days=30)),
            reason="mich runtime test",
            actor_id="admin",
            ip_address=None,
        )
        machine_fingerprint = "mich-runtime-machine"
        license_response = self.service.check_license(
            license_key=created.license_key,
            email=None,
            customer_id=None,
            whop_user_id=None,
            machine_fingerprint=machine_fingerprint,
            app_version="0.1.0",
            ip_address=None,
            user_agent=None,
            check_interval_seconds=3600,
            grace_period_seconds=86400,
        )
        unpublished_manifest = self.service.release_manifest(
            license_key=created.license_key,
            email=None,
            customer_id=None,
            whop_user_id=None,
            machine_fingerprint=machine_fingerprint,
            app_version="0.1.0",
            channel="stable",
            platform="macos-arm64",
            include_types=["strategy_package"],
            installed_packages=[{"package_id": "mich-runtime", "version": "0.0.0"}],
            ip_address=None,
            user_agent=None,
            check_interval_seconds=3600,
            grace_period_seconds=86400,
        )

        self.assertEqual("active", license_response["status"])
        self.assertEqual(["strategy.mich.runtime"], [grant["feature_id"] for grant in license_response["licensed_strategies"]])
        self.assertEqual([], unpublished_manifest["releases"])

        artifact_dir = Path(self.tmp.name) / "mich-artifacts"
        artifact_subdir = artifact_dir / "strategies" / "mich"
        artifact_subdir.mkdir(parents=True)
        for platform in ("macos-arm64", "windows-x64", "linux-x64"):
            artifact_path = f"strategies/mich/MICH-0.1.0-{platform}.zip"
            (artifact_dir / artifact_path).write_bytes(f"mich runtime {platform}".encode())
            self.service.upsert_release(
                release_id=None,
                scope="strategy",
                release_type="strategy_package",
                product_key="mich-runtime",
                product_id=mich["id"],
                channel="stable",
                platform=platform,
                version="0.1.0",
                min_supported_version=None,
                is_required=False,
                is_active=True,
                artifact_path=artifact_path,
                artifact_filename=None,
                size_bytes=None,
                sha256_value=None,
                signature=None,
                release_notes="MICH runtime test release",
                artifact_dir=str(artifact_dir),
            )

        for platform in ("macos-arm64", "windows-x64", "linux-x64"):
            manifest = self.service.release_manifest(
                license_key=created.license_key,
                email=None,
                customer_id=None,
                whop_user_id=None,
                machine_fingerprint=machine_fingerprint,
                app_version="0.1.0",
                channel="stable",
                platform=platform,
                include_types=["strategy_package"],
                installed_packages=[{"package_id": "mich-runtime", "version": "0.0.0"}],
                ip_address=None,
                user_agent=None,
                check_interval_seconds=3600,
                grace_period_seconds=86400,
            )

            self.assertEqual("active", manifest["status"])
            self.assertEqual(1, len(manifest["releases"]))
            release = manifest["releases"][0]
            self.assertEqual("strategy_package", release["release_type"])
            self.assertEqual("mich-runtime", release["package_id"])
            self.assertEqual("MICH", release["display_name"])
            self.assertEqual("MICH", release["strategy"])
            self.assertEqual("strategy.mich.runtime", release["feature_id"])
            self.assertEqual(["strategy.mich.runtime"], release["required_features"])
            self.assertEqual("0.1.0", release["version"])
            self.assertEqual(platform, release["platform"])

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

    def test_manifest_packages_expose_subscription_url_without_changing_authorization(self) -> None:
        subscription_url = "https://whop.com/auto-edge/duo-nasdaq-futures-bot/"
        self.service.update_product(
            product_id=self.product["id"],
            slug=self.product["slug"],
            name=self.product["name"],
            feature_id=self.product["feature_id"],
            whop_product_id=self.product["whop_product_id"],
            is_active=True,
            subscription_url=subscription_url,
        )
        release = self.strategy_release(version="8.0.0")
        entitled = self.active_customer("subscription-entitled@example.com")
        unentitled = self.service.create_or_update_customer(email="subscription-unentitled@example.com")
        expired = self.service.create_or_update_customer(email="subscription-expired@example.com")
        self.service.manual_set_entitlement(
            customer_id=expired.customer["id"],
            product_id=self.product["id"],
            status="expired",
            expires_at=iso(utc_now() - timedelta(days=1)),
            reason="expired subscription URL test",
            actor_id="admin",
            ip_address=None,
        )

        def manifest_for(created, fingerprint: str) -> dict:
            return self.service.release_manifest(
                license_key=created.license_key,
                email=None,
                customer_id=None,
                whop_user_id=None,
                machine_fingerprint=fingerprint,
                app_version="1.0.0",
                channel="stable",
                platform="windows-x64",
                include_types=["strategy_package"],
                installed_packages=None,
                ip_address=None,
                user_agent=None,
                check_interval_seconds=3600,
                grace_period_seconds=86400,
            )

        entitled_manifest = manifest_for(entitled, "subscription-entitled-machine")
        unentitled_manifest = manifest_for(unentitled, "subscription-unentitled-machine")
        expired_manifest = manifest_for(expired, "subscription-expired-machine")
        entitled_package = next(
            package for package in entitled_manifest["packages"] if package["product_id"] == self.product["id"]
        )
        unentitled_package = next(
            package for package in unentitled_manifest["packages"] if package["product_id"] == self.product["id"]
        )
        expired_package = next(
            package for package in expired_manifest["packages"] if package["product_id"] == self.product["id"]
        )
        null_package = next(
            package for package in unentitled_manifest["packages"] if package["package_id"] == "mich-runtime"
        )

        self.assertEqual("active", entitled_manifest["status"])
        self.assertEqual(subscription_url, entitled_package["subscription_url"])
        self.assertEqual("active", entitled_package["license_status"])
        self.assertEqual(subscription_url, entitled_manifest["releases"][0]["subscription_url"])
        self.assertEqual("unlicensed", unentitled_manifest["status"])
        self.assertEqual(subscription_url, unentitled_package["subscription_url"])
        self.assertEqual("unlicensed", unentitled_package["license_status"])
        self.assertEqual([], unentitled_manifest["releases"])
        self.assertIsNone(unentitled_manifest["app_update"])
        self.assertEqual("expired", expired_manifest["status"])
        self.assertEqual(subscription_url, expired_package["subscription_url"])
        self.assertEqual("expired", expired_package["license_status"])
        self.assertEqual([], expired_manifest["releases"])
        self.assertIsNone(null_package["subscription_url"])

        denied_token = self.service.create_release_download_token(
            release_id=release["id"],
            license_key=unentitled.license_key,
            email=None,
            customer_id=None,
            whop_user_id=None,
            machine_fingerprint="subscription-unentitled-machine",
            app_version="1.0.0",
            channel="stable",
            platform="windows-x64",
            installed_packages=None,
            ip_address=None,
            user_agent=None,
            check_interval_seconds=3600,
            grace_period_seconds=86400,
            token_seconds=600,
        )

        self.assertEqual("unlicensed", denied_token["status"])
        self.assertIsNone(denied_token["token"])

    def test_strategy_release_identity_is_created_updated_and_platform_specific(self) -> None:
        windows = self.strategy_release(
            version="3.0.0",
            platform="windows-x64",
            nt8_version="12.3.0.45",
            trader_revision=0,
        )
        macos = self.strategy_release(
            version="3.0.0",
            platform="macos-arm64",
            nt8_version="12.3.0.45",
            trader_revision=0,
        )

        updated = self.service.upsert_release(
            release_id=windows["id"],
            scope="strategy",
            release_type="strategy_package",
            product_key="duo-runtime",
            product_id=self.product["id"],
            channel="stable",
            platform="windows-x64",
            version="3.0.1",
            min_supported_version=None,
            is_required=False,
            is_active=True,
            artifact_path=windows["artifact_path"],
            artifact_filename=windows["artifact_filename"],
            size_bytes=windows["size_bytes"],
            sha256_value=windows["sha256"],
            signature=None,
            release_notes="TraderPro-only strategy update",
            artifact_dir=str(Path(self.tmp.name) / "release-test-artifacts"),
            nt8_version="12.3.0.45",
            trader_revision=1,
        )

        self.assertEqual("12.3.0.45", windows["nt8_version"])
        self.assertEqual(0, windows["trader_revision"])
        self.assertEqual("12.3.0.45", macos["nt8_version"])
        self.assertEqual(0, macos["trader_revision"])
        self.assertEqual("3.0.1", updated["version"])
        self.assertEqual("12.3.0.45", updated["nt8_version"])
        self.assertEqual(1, updated["trader_revision"])

    def test_strategy_release_manifest_serializes_legacy_null_identity(self) -> None:
        created = self.active_customer("legacy-release-identity@example.com")
        self.strategy_release(version="1.0.0")

        manifest = self.service.release_manifest(
            license_key=created.license_key,
            email=None,
            customer_id=None,
            whop_user_id=None,
            machine_fingerprint="legacy-release-identity-machine",
            app_version="9.9.9",
            channel="stable",
            platform="windows-x64",
            include_types=["strategy_package"],
            installed_packages=[{"package_id": "duo-runtime", "version": "0.9.0"}],
            ip_address=None,
            user_agent=None,
            check_interval_seconds=3600,
            grace_period_seconds=86400,
        )

        release = manifest["releases"][0]
        self.assertIn("nt8_version", release)
        self.assertIn("trader_revision", release)
        self.assertIsNone(release["nt8_version"])
        self.assertIsNone(release["trader_revision"])

    def test_strategy_manifest_returns_installed_and_target_release_identities(self) -> None:
        created = self.active_customer("installed-release-identity@example.com")
        self.strategy_release(version="0.1.38", nt8_version="2.1.0.8", trader_revision=0)
        self.strategy_release(version="0.1.39", nt8_version="2.1.0.9", trader_revision=0)

        manifest = self.strategy_manifest(
            created,
            installed_packages=[{"package_id": "duo-runtime", "version": "0.1.38"}],
        )

        release = manifest["releases"][0]
        self.assertEqual("0.1.38", release["current_version"])
        self.assertEqual("0.1.39", release["target_version"])
        self.assertEqual("2.1.0.9", release["nt8_version"])
        self.assertEqual(0, release["trader_revision"])
        self.assertEqual("2.1.0.8", release["installed_nt8_version"])
        self.assertEqual(0, release["installed_trader_revision"])
        self.assertEqual("update", release["action"])
        self.assertTrue(release["update_available"])

    def test_strategy_manifest_current_release_returns_its_installed_identity(self) -> None:
        created = self.active_customer("current-release-identity@example.com")
        self.strategy_release(version="0.1.39", nt8_version="2.1.0.9", trader_revision=2)

        release = self.strategy_manifest(
            created,
            installed_packages=[{"package_id": "duo-runtime", "version": "0.1.39"}],
        )["releases"][0]

        self.assertEqual("current", release["action"])
        self.assertFalse(release["update_available"])
        self.assertEqual("2.1.0.9", release["installed_nt8_version"])
        self.assertEqual(2, release["installed_trader_revision"])

    def test_strategy_manifest_rollback_returns_newer_installed_release_identity(self) -> None:
        created = self.active_customer("rollback-installed-identity@example.com")
        self.strategy_release(
            version="0.1.39",
            rollback_reason="Rollback strategy package",
            nt8_version="2.1.0.9",
            trader_revision=0,
        )
        self.strategy_release(
            version="0.1.40",
            is_active=False,
            nt8_version="2.1.0.10",
            trader_revision=1,
        )

        release = self.strategy_manifest(
            created,
            installed_packages=[{"package_id": "duo-runtime", "version": "0.1.40"}],
        )["releases"][0]

        self.assertEqual("rollback", release["action"])
        self.assertEqual("0.1.40", release["current_version"])
        self.assertEqual("0.1.39", release["target_version"])
        self.assertEqual("2.1.0.10", release["installed_nt8_version"])
        self.assertEqual(1, release["installed_trader_revision"])
        self.assertEqual("2.1.0.9", release["nt8_version"])
        self.assertEqual(0, release["trader_revision"])

    def test_strategy_manifest_unknown_installed_version_returns_null_identity_pair(self) -> None:
        created = self.active_customer("unknown-installed-identity@example.com")
        self.strategy_release(version="0.1.39", nt8_version="2.1.0.9", trader_revision=0)

        release = self.strategy_manifest(
            created,
            installed_packages=[{"package_id": "duo-runtime", "version": "legacy-build"}],
        )["releases"][0]

        self.assertIsNone(release["installed_nt8_version"])
        self.assertIsNone(release["installed_trader_revision"])

    def test_strategy_manifest_installed_release_with_missing_metadata_returns_null_pair(self) -> None:
        created = self.active_customer("missing-installed-identity@example.com")
        installed = self.strategy_release(version="0.1.38")
        with self.database.session() as connection:
            connection.execute(
                "UPDATE trader_releases SET nt8_version = ? WHERE id = ?",
                ("2.1.0.8", installed["id"]),
            )
        self.strategy_release(version="0.1.39", nt8_version="2.1.0.9", trader_revision=0)

        release = self.strategy_manifest(
            created,
            installed_packages=[{"package_id": "duo-runtime", "version": "0.1.38"}],
        )["releases"][0]

        self.assertIsNone(release["installed_nt8_version"])
        self.assertIsNone(release["installed_trader_revision"])
        self.assertEqual("2.1.0.9", release["nt8_version"])
        self.assertEqual(0, release["trader_revision"])

    def test_strategy_manifest_resolves_multiple_installed_package_identities(self) -> None:
        created = self.active_customer("multiple-installed-identities@example.com")
        duorc = self.service.upsert_product(
            slug="duorc-runtime",
            name="DUOrc Runtime",
            feature_id="strategy.duorc.runtime",
            whop_product_id="prod_duorc",
        )
        self.service.manual_set_entitlement(
            customer_id=created.customer["id"],
            product_id=duorc["id"],
            status="active",
            expires_at=iso(utc_now() + timedelta(days=30)),
            reason="test grant",
            actor_id="admin",
            ip_address=None,
        )
        self.strategy_release(version="0.1.38", nt8_version="2.1.0.8", trader_revision=0)
        self.strategy_release(version="0.1.39", nt8_version="2.1.0.9", trader_revision=0)
        self.strategy_release(version="1.4.2", product_id=duorc["id"], nt8_version="3.0.0.2", trader_revision=4)
        self.strategy_release(version="1.4.3", product_id=duorc["id"], nt8_version="3.0.0.3", trader_revision=0)

        manifest = self.strategy_manifest(
            created,
            installed_packages=[
                {"package_id": "duo-runtime", "version": "0.1.38"},
                {"package_id": "duorc-runtime", "version": "1.4.2"},
            ],
        )

        releases = {release["package_id"]: release for release in manifest["releases"]}
        self.assertEqual("2.1.0.8", releases["duo-runtime"]["installed_nt8_version"])
        self.assertEqual(0, releases["duo-runtime"]["installed_trader_revision"])
        self.assertEqual("3.0.0.2", releases["duorc-runtime"]["installed_nt8_version"])
        self.assertEqual(4, releases["duorc-runtime"]["installed_trader_revision"])

    def test_strategy_manifest_installed_identity_is_platform_specific(self) -> None:
        created = self.active_customer("platform-installed-identity@example.com")
        self.strategy_release(
            version="0.1.38",
            platform="windows-x64",
            nt8_version="2.1.0.8",
            trader_revision=0,
        )
        self.strategy_release(
            version="0.1.38",
            platform="macos-arm64",
            nt8_version="9.9.9.9",
            trader_revision=9,
        )
        self.strategy_release(
            version="0.1.39",
            platform="windows-x64",
            nt8_version="2.1.0.9",
            trader_revision=0,
        )

        release = self.strategy_manifest(
            created,
            installed_packages=[{"package_id": "duo-runtime", "version": "0.1.38"}],
            platform="windows-x64",
        )["releases"][0]

        self.assertEqual("2.1.0.8", release["installed_nt8_version"])
        self.assertEqual(0, release["installed_trader_revision"])

    def test_strategy_manifest_without_installed_package_keeps_previous_shape(self) -> None:
        created = self.active_customer("no-installed-identity@example.com")
        self.strategy_release(version="0.1.39", nt8_version="2.1.0.9", trader_revision=0)

        release = self.strategy_manifest(
            created,
            installed_packages=None,
            app_version="0.1.38",
        )["releases"][0]

        self.assertEqual("0.1.38", release["current_version"])
        self.assertNotIn("installed_nt8_version", release)
        self.assertNotIn("installed_trader_revision", release)

    def test_strategy_release_identity_validation(self) -> None:
        for invalid_version in ("2.1.0", "2.1.0.8.1", "2.1.a.8", "2..0.8", "v2.1.0.8"):
            with self.subTest(nt8_version=invalid_version):
                with self.assertRaisesRegex(ValueError, "exactly four numeric components"):
                    self.strategy_release(
                        version=f"invalid-{invalid_version}",
                        nt8_version=invalid_version,
                        trader_revision=0,
                    )

        with self.assertRaisesRegex(ValueError, "both be supplied or both be blank"):
            self.strategy_release(version="missing-revision", nt8_version="2.1.0.8")
        with self.assertRaisesRegex(ValueError, "both be supplied or both be blank"):
            self.strategy_release(version="missing-nt8-version", trader_revision=0)
        with self.assertRaisesRegex(ValueError, "non-negative integer"):
            self.strategy_release(version="negative-revision", nt8_version="2.1.0.8", trader_revision=-1)

    def test_extension_package_hidden_and_not_downloadable_without_feature_grant(self) -> None:
        created = self.active_customer("discord-hidden@example.com")
        release = self.extension_release(version="1.0.0")

        manifest = self.service.release_manifest(
            license_key=created.license_key,
            email=None,
            customer_id=None,
            whop_user_id=None,
            machine_fingerprint="discord-hidden-machine",
            app_version="0.9.0",
            channel="stable",
            platform="windows-x64",
            include_types=["extension_package"],
            ip_address=None,
            user_agent=None,
            check_interval_seconds=3600,
            grace_period_seconds=86400,
        )
        token = self.service.create_release_download_token(
            release_id=release["id"],
            license_key=created.license_key,
            email=None,
            customer_id=None,
            whop_user_id=None,
            machine_fingerprint="discord-hidden-machine",
            app_version="0.9.0",
            platform="windows-x64",
            ip_address=None,
            user_agent=None,
            check_interval_seconds=3600,
            grace_period_seconds=86400,
            token_seconds=600,
        )

        self.assertEqual("active", manifest["status"])
        self.assertEqual([], manifest["releases"])
        self.assertEqual("not_licensed", token["status"])
        self.assertIsNone(token["token"])

    def test_active_discord_feature_grant_exposes_extension_package_metadata(self) -> None:
        product = self.discord_product()
        created = self.service.create_or_update_customer(email="discord-active@example.com")
        expires_at = iso(utc_now() + timedelta(days=30))
        self.service.manual_set_entitlement(
            customer_id=created.customer["id"],
            product_id=product["id"],
            status="active",
            expires_at=expires_at,
            reason="discord extension",
            actor_id="admin",
            ip_address=None,
        )
        release = self.extension_release(product_id=product["id"], version="1.2.0", platform="macos-arm64")

        manifest = self.service.release_manifest(
            license_key=created.license_key,
            email=None,
            customer_id=None,
            whop_user_id=None,
            machine_fingerprint="discord-active-machine",
            app_version="1.1.0",
            channel="stable",
            platform="macos-arm64",
            include_types=["extension_package"],
            installed_packages=[{"package_id": "discord-notifier", "version": "1.1.0"}],
            ip_address=None,
            user_agent=None,
            check_interval_seconds=3600,
            grace_period_seconds=86400,
        )

        self.assertEqual("active", manifest["status"])
        self.assertEqual(1, len(manifest["releases"]))
        item = manifest["releases"][0]
        self.assertEqual(release["id"], item["id"])
        self.assertEqual(release["id"], item["release_id"])
        self.assertEqual("extension", item["scope"])
        self.assertEqual("extension_package", item["release_type"])
        self.assertEqual("discord-notifier", item["package_id"])
        self.assertEqual("Discord Notifier", item["display_name"])
        self.assertIsNone(item["strategy"])
        self.assertEqual(product["id"], item["product_id"])
        self.assertEqual("trader.notifications.discord", item["feature_id"])
        self.assertEqual(["trader.notifications.discord"], item["required_features"])
        self.assertEqual("1.2.0", item["version"])
        self.assertEqual("macos-arm64", item["platform"])
        self.assertEqual("discord-notifier-1.2.0-stable-macos-arm64.zip", item["artifact"]["path"])
        self.assertEqual("discord-notifier-1.2.0-stable-macos-arm64.zip", item["artifact"]["filename"])
        self.assertEqual("Discord Notifier release", item["release_notes"])
        self.assertEqual("active", item["license_status"])
        self.assertEqual(expires_at, item["expires_at"])
        self.assertEqual("1.1.0", item["current_version"])
        self.assertEqual("update", item["action"])
        self.assertNotIn("nt8_version", item)
        self.assertNotIn("trader_revision", item)

    def test_expired_discord_feature_grant_does_not_expose_extension_package(self) -> None:
        product = self.discord_product()
        created = self.active_customer("discord-expired@example.com")
        self.service.manual_set_entitlement(
            customer_id=created.customer["id"],
            product_id=product["id"],
            status="expired",
            expires_at=iso(utc_now() - timedelta(days=1)),
            reason="expired discord extension",
            actor_id="admin",
            ip_address=None,
        )
        self.extension_release(product_id=product["id"], version="1.0.0")

        manifest = self.service.release_manifest(
            license_key=created.license_key,
            email=None,
            customer_id=None,
            whop_user_id=None,
            machine_fingerprint="discord-expired-machine",
            app_version="0.9.0",
            channel="stable",
            platform="windows-x64",
            include_types=["extension_package"],
            ip_address=None,
            user_agent=None,
            check_interval_seconds=3600,
            grace_period_seconds=86400,
        )

        self.assertEqual("active", manifest["status"])
        self.assertEqual([], manifest["releases"])

    def test_allowlisted_extension_release_matches_customer_email_or_license_key(self) -> None:
        product = self.discord_product()
        by_customer = self.service.create_or_update_customer(email="discord-customer@example.com")
        by_email = self.service.create_or_update_customer(email="discord-email@example.com")
        by_key = self.service.create_or_update_customer(email="discord-key@example.com")
        denied = self.service.create_or_update_customer(email="discord-denied@example.com")
        for created in (by_customer, by_email, by_key, denied):
            self.service.manual_set_entitlement(
                customer_id=created.customer["id"],
                product_id=product["id"],
                status="active",
                expires_at=iso(utc_now() + timedelta(days=30)),
                reason="allowlist discord extension",
                actor_id="admin",
                ip_address=None,
            )
        self.extension_release(
            product_id=product["id"],
            version="1.4.0",
            channel="beta",
            audience_mode="allowlist",
            allowed_customer_ids=by_customer.customer["id"],
            allowed_emails="discord-email@example.com",
            allowed_license_keys=by_key.license_key,
        )

        def release_versions(created, fingerprint: str) -> list[str]:
            manifest = self.service.release_manifest(
                license_key=created.license_key,
                email=None,
                customer_id=None,
                whop_user_id=None,
                machine_fingerprint=fingerprint,
                app_version="1.0.0",
                channel="stable",
                platform="windows-x64",
                include_types=["extension_package"],
                ip_address=None,
                user_agent=None,
                check_interval_seconds=3600,
                grace_period_seconds=86400,
            )
            return [release["version"] for release in manifest["releases"]]

        self.assertEqual(["1.4.0"], release_versions(by_customer, "discord-allow-customer"))
        self.assertEqual(["1.4.0"], release_versions(by_email, "discord-allow-email"))
        self.assertEqual(["1.4.0"], release_versions(by_key, "discord-allow-key"))
        self.assertEqual([], release_versions(denied, "discord-allow-denied"))

    def test_extension_packages_are_opt_in_so_strategy_manifest_stays_compatible(self) -> None:
        product = self.discord_product()
        created = self.active_customer("discord-compatible@example.com")
        self.service.manual_set_entitlement(
            customer_id=created.customer["id"],
            product_id=product["id"],
            status="active",
            expires_at=iso(utc_now() + timedelta(days=30)),
            reason="discord extension",
            actor_id="admin",
            ip_address=None,
        )
        self.strategy_release(version="2.0.0", platform="windows-x64")
        self.extension_release(product_id=product["id"], version="1.0.0", platform="windows-x64")

        default_manifest = self.service.release_manifest(
            license_key=created.license_key,
            email=None,
            customer_id=None,
            whop_user_id=None,
            machine_fingerprint="discord-compatible-default",
            app_version="1.0.0",
            channel="stable",
            platform="windows-x64",
            ip_address=None,
            user_agent=None,
            check_interval_seconds=3600,
            grace_period_seconds=86400,
        )
        strategy_manifest = self.service.release_manifest(
            license_key=created.license_key,
            email=None,
            customer_id=None,
            whop_user_id=None,
            machine_fingerprint="discord-compatible-default",
            app_version="1.0.0",
            channel="stable",
            platform="windows-x64",
            include_types=["strategy_package"],
            ip_address=None,
            user_agent=None,
            check_interval_seconds=3600,
            grace_period_seconds=86400,
        )

        self.assertEqual(["strategy_package"], [release["release_type"] for release in default_manifest["releases"]])
        self.assertEqual(["DUO"], [release["strategy"] for release in default_manifest["releases"]])
        self.assertEqual(default_manifest["releases"], strategy_manifest["releases"])

    def test_release_manifest_returns_trader_desktop_app_update(self) -> None:
        created = self.active_customer("app-update@example.com")
        artifact_dir = Path(self.tmp.name) / "app-update-artifacts"
        artifact_dir.mkdir()
        artifact = artifact_dir / "TraderPro-Desktop-0.1.1-windows-x64.zip"
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
            signature=None,
            signature_key_id=None,
            release_notes="TraderPro Desktop update",
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
        self.assertEqual("TraderPro Desktop", manifest["app_update"]["display_name"])
        self.assertEqual("TraderPro Desktop", manifest["app_update"]["product_name"])
        self.assertEqual("0.1.0", manifest["app_update"]["current_version"])
        self.assertEqual("0.1.1", manifest["app_update"]["available_version"])
        self.assertEqual(release["id"], manifest["app_update"]["release_id"])
        self.assertEqual(len(b"desktop app update"), manifest["app_update"]["artifact"]["size_bytes"])
        self.assertIsNotNone(manifest["app_update"]["artifact"]["sha256"])
        self.assertIsNone(manifest["app_update"]["artifact"]["signature_key_id"])

    def test_desktop_artifact_names_use_release_metadata_and_preserve_legacy_downloads(self) -> None:
        created = self.active_customer("desktop-filename-compatibility@example.com")
        machine_fingerprint = "desktop-filename-compatibility-machine"
        license_before = self.service.check_license(
            license_key=created.license_key,
            email=None,
            customer_id=None,
            whop_user_id=None,
            machine_fingerprint=machine_fingerprint,
            app_version="0.8.0",
            ip_address=None,
            user_agent="legacy-client",
            check_interval_seconds=3600,
            grace_period_seconds=86400,
        )
        artifact_dir = Path(self.tmp.name) / "artifact-name-compatibility"
        storage_dir = artifact_dir / "trader-desktop"
        storage_dir.mkdir(parents=True)
        cases = [
            ("0.9.0", "windows-x64", "Trader-Desktop-0.9.0-windows-x64.zip"),
            ("1.0.0", "macos-arm64", "TraderPro-Desktop-1.0.0-macos-arm64.dmg"),
            ("1.0.1", "macos-arm64", "TraderPro-Desktop-1.0.1-macos-arm64.zip"),
            ("1.0.2", "windows-x64", "TraderPro-Desktop-1.0.2-windows-x64-Setup.exe"),
            ("1.0.3", "windows-x64", "TraderPro-Desktop-1.0.3-windows-x64.zip"),
        ]
        release_ids: set[str] = set()

        for index, (version, platform, download_filename) in enumerate(cases):
            with self.subTest(download_filename=download_filename):
                contents = f"desktop artifact {index}".encode()
                stored_path = storage_dir / f"build-{index}.bin"
                stored_path.write_bytes(contents)
                release = self.service.upsert_release(
                    release_id=None,
                    scope="app",
                    release_type="trader_desktop",
                    product_key="trader-desktop",
                    product_id=None,
                    channel="stable",
                    platform=platform,
                    version=version,
                    min_supported_version=None,
                    is_required=False,
                    is_active=True,
                    artifact_path=f"trader-desktop/{stored_path.name}",
                    artifact_filename=download_filename,
                    size_bytes=None,
                    sha256_value=None,
                    signature=None,
                    signature_key_id=None,
                    release_notes=None,
                    artifact_dir=str(artifact_dir),
                )
                release_ids.add(release["id"])
                self.assertEqual("trader_desktop", release["release_type"])
                self.assertEqual("trader-desktop", release["product_key"])
                self.assertEqual(download_filename, release["artifact_filename"])
                self.assertEqual(sha256(contents).hexdigest(), release["sha256"])
                self.assertEqual("TraderPro Desktop update", release["release_notes"])

                token_result = self.service.create_release_download_token(
                    release_id=release["id"],
                    license_key=created.license_key,
                    email=None,
                    customer_id=None,
                    whop_user_id=None,
                    machine_fingerprint=machine_fingerprint,
                    app_version="0.8.0",
                    channel="stable",
                    platform=platform,
                    ip_address=None,
                    user_agent="legacy-client",
                    check_interval_seconds=3600,
                    grace_period_seconds=86400,
                    token_seconds=600,
                )
                self.assertEqual("ok", token_result["status"])
                self.assertEqual("trader_desktop", token_result["release"]["release_type"])
                self.assertEqual("trader-desktop", token_result["release"]["package_id"])
                self.assertEqual("TraderPro Desktop", token_result["release"]["display_name"])
                self.assertEqual("TraderPro Desktop", token_result["release"]["product_name"])
                self.assertEqual(download_filename, token_result["release"]["artifact"]["filename"])
                self.assertEqual(sha256(contents).hexdigest(), token_result["release"]["artifact"]["sha256"])
                self.assertIsNone(token_result["release"]["artifact"]["signature"])

                resolved = self.service.resolve_release_download(
                    token=token_result["token"],
                    artifact_dir=str(artifact_dir),
                    ip_address=None,
                    user_agent="legacy-client",
                )
                self.assertEqual("ok", resolved["status"])
                self.assertEqual(stored_path.resolve(), resolved["artifact_path"])
                self.assertEqual(download_filename, resolved["artifact_filename"])

        release_history = self.service.list_releases()
        matching_history = [release for release in release_history if release["id"] in release_ids]
        self.assertEqual(release_ids, {release["id"] for release in matching_history})
        self.assertEqual({filename for _, _, filename in cases}, {release["artifact_filename"] for release in matching_history})
        self.assertTrue(all(release["product_key"] == "trader-desktop" for release in matching_history))

        manifest = self.service.release_manifest(
            license_key=created.license_key,
            email=None,
            customer_id=None,
            whop_user_id=None,
            machine_fingerprint=machine_fingerprint,
            app_version="0.8.0",
            channel="stable",
            platform="windows-x64",
            include_types=["trader_desktop"],
            ip_address=None,
            user_agent="legacy-client",
            check_interval_seconds=3600,
            grace_period_seconds=86400,
        )
        self.assertEqual("trader-desktop", manifest["app_update"]["product_id"])
        self.assertEqual("trader_desktop", manifest["app_update"]["release_type"])
        self.assertEqual("TraderPro Desktop", manifest["app_update"]["display_name"])
        self.assertEqual("TraderPro-Desktop-1.0.3-windows-x64.zip", manifest["app_update"]["artifact"]["filename"])

        license_after = self.service.check_license(
            license_key=created.license_key,
            email=None,
            customer_id=None,
            whop_user_id=None,
            machine_fingerprint=machine_fingerprint,
            app_version="1.0.3",
            ip_address=None,
            user_agent="TraderPro Desktop",
            check_interval_seconds=3600,
            grace_period_seconds=86400,
        )
        self.assertEqual(license_before["customer"]["id"], license_after["customer"]["id"])
        self.assertEqual(license_before["device"]["id"], license_after["device"]["id"])
        with self.database.session() as connection:
            device_count = connection.execute(
                "SELECT COUNT(*) FROM devices WHERE customer_id = ? AND client_type = 'trader_desktop'",
                (created.customer["id"],),
            ).fetchone()[0]
        self.assertEqual(1, device_count)

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
            artifact_path="Trader-Desktop-0.1.1-windows-x64.zip",
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

    def test_legacy_desktop_release_row_is_presented_as_traderpro_without_rewriting_history(self) -> None:
        created = self.active_customer("legacy-desktop-row@example.com")
        artifact_dir = Path(self.tmp.name) / "legacy-desktop-row-artifacts"
        stored_dir = artifact_dir / "trader-desktop"
        stored_dir.mkdir(parents=True)
        filename = "Trader-Desktop-0.8.0-windows-x64.zip"
        artifact = stored_dir / filename
        contents = b"legacy desktop release"
        artifact.write_bytes(contents)
        release_id = "legacy-desktop-release"
        created_at = iso()
        with self.database.session() as connection:
            connection.execute(
                """
                INSERT INTO trader_releases(
                    id, product_id, scope, channel, platform, version,
                    is_required, is_active, artifact_path, artifact_filename,
                    size_bytes, sha256, signature, release_notes, created_at, updated_at
                )
                VALUES (?, NULL, 'app', 'stable', 'windows-x64', '0.8.0',
                        0, 1, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    release_id,
                    f"trader-desktop/{filename}",
                    filename,
                    len(contents),
                    sha256(contents).hexdigest(),
                    "legacy-signature",
                    "Original Trader Desktop release",
                    created_at,
                    created_at,
                ),
            )

        manifest = self.service.release_manifest(
            license_key=created.license_key,
            email=None,
            customer_id=None,
            whop_user_id=None,
            machine_fingerprint="legacy-desktop-release-machine",
            app_version="0.7.0",
            channel="stable",
            platform="windows-x64",
            include_types=["trader_desktop"],
            ip_address=None,
            user_agent="legacy-client",
            check_interval_seconds=3600,
            grace_period_seconds=86400,
        )

        update = manifest["app_update"]
        self.assertEqual(release_id, update["release_id"])
        self.assertEqual("TraderPro Desktop", update["display_name"])
        self.assertEqual("TraderPro Desktop", update["product_name"])
        self.assertEqual("trader-desktop", update["product_id"])
        self.assertEqual("trader_desktop", update["release_type"])
        self.assertEqual(filename, update["artifact"]["filename"])
        self.assertEqual("legacy-signature", update["artifact"]["signature"])
        self.assertEqual("Original Trader Desktop release", update["release_notes"])

        token_result = self.service.create_release_download_token(
            release_id=release_id,
            license_key=created.license_key,
            email=None,
            customer_id=None,
            whop_user_id=None,
            machine_fingerprint="legacy-desktop-release-machine",
            app_version="0.7.0",
            channel="stable",
            platform="windows-x64",
            ip_address=None,
            user_agent="legacy-client",
            check_interval_seconds=3600,
            grace_period_seconds=86400,
            token_seconds=600,
        )
        resolved = self.service.resolve_release_download(
            token=token_result["token"],
            artifact_dir=str(artifact_dir),
            ip_address=None,
            user_agent="legacy-client",
        )
        self.assertEqual("ok", token_result["status"])
        self.assertEqual("TraderPro Desktop", token_result["release"]["display_name"])
        self.assertEqual("ok", resolved["status"])
        self.assertEqual(artifact.resolve(), resolved["artifact_path"])
        self.assertEqual(filename, resolved["artifact_filename"])

        with self.database.session() as connection:
            row = connection.execute(
                "SELECT release_type, product_key, artifact_filename, release_notes FROM trader_releases WHERE id = ?",
                (release_id,),
            ).fetchone()
            matching_rows = connection.execute(
                "SELECT COUNT(*) FROM trader_releases WHERE id = ?",
                (release_id,),
            ).fetchone()[0]
        self.assertIsNone(row["release_type"])
        self.assertIsNone(row["product_key"])
        self.assertEqual(filename, row["artifact_filename"])
        self.assertEqual("Original Trader Desktop release", row["release_notes"])
        self.assertEqual(1, matching_rows)

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

    def test_linux_x64_manifest_and_download_tokens_are_exact_platform_for_all_release_types(self) -> None:
        created = self.active_customer("linux-release@example.com")
        extension_product = self.discord_product()
        self.service.manual_set_entitlement(
            customer_id=created.customer["id"],
            product_id=extension_product["id"],
            status="active",
            expires_at=iso(utc_now() + timedelta(days=30)),
            reason="linux extension test",
            actor_id="admin",
            ip_address=None,
        )
        linux_strategy = self.strategy_release(version="2.0.0", platform="linux-x64")
        linux_extension = self.extension_release(
            product_id=extension_product["id"], version="1.0.0", platform="linux-x64"
        )
        linux_desktop = self.desktop_release(version="0.2.0", platform="linux-x64")
        macos_strategy = self.strategy_release(version="9.0.0", platform="macos-arm64")
        windows_extension = self.extension_release(
            product_id=extension_product["id"], version="9.0.0", platform="windows-x64"
        )
        windows_desktop = self.desktop_release(version="9.0.0", platform="windows-x64")

        manifest = self.service.release_manifest(
            license_key=created.license_key,
            email=None,
            customer_id=None,
            whop_user_id=None,
            machine_fingerprint="linux-release-machine",
            app_version="0.1.0",
            channel="stable",
            platform="linux-x64",
            include_types=["strategy_package", "extension_package", "trader_desktop"],
            installed_packages=[
                {"package_id": "duo-runtime", "version": "1.0.0"},
                {"package_id": "discord-notifier", "version": "0.9.0"},
            ],
            ip_address=None,
            user_agent="TraderPro Desktop Linux",
            check_interval_seconds=3600,
            grace_period_seconds=86400,
        )

        self.assertEqual("active", manifest["status"])
        self.assertEqual("linux-x64", manifest["platform"])
        self.assertEqual(
            {"strategy_package", "extension_package"},
            {release["release_type"] for release in manifest["releases"]},
        )
        self.assertEqual(
            {linux_strategy["id"], linux_extension["id"]},
            {release["release_id"] for release in manifest["releases"]},
        )
        self.assertTrue(all(release["platform"] == "linux-x64" for release in manifest["releases"]))
        self.assertEqual(linux_desktop["id"], manifest["app_update"]["release_id"])
        self.assertEqual("linux-x64", manifest["app_update"]["platform"])

        for release in (linux_strategy, linux_extension, linux_desktop):
            with self.subTest(release_type=release["release_type"]):
                token = self.service.create_release_download_token(
                    release_id=release["id"],
                    license_key=created.license_key,
                    email=None,
                    customer_id=None,
                    whop_user_id=None,
                    machine_fingerprint="linux-release-machine",
                    app_version="0.1.0",
                    channel="stable",
                    platform="linux-x64",
                    ip_address=None,
                    user_agent="TraderPro Desktop Linux",
                    check_interval_seconds=3600,
                    grace_period_seconds=86400,
                    token_seconds=600,
                )
                self.assertEqual("ok", token["status"])
                self.assertEqual("linux-x64", token["release"]["platform"])
                self.assertEqual(release["release_type"], token["release"]["release_type"])

        for release in (macos_strategy, windows_extension, windows_desktop):
            with self.subTest(rejected_release=release["id"]):
                token = self.service.create_release_download_token(
                    release_id=release["id"],
                    license_key=created.license_key,
                    email=None,
                    customer_id=None,
                    whop_user_id=None,
                    machine_fingerprint="linux-release-machine",
                    app_version="0.1.0",
                    channel="stable",
                    platform="linux-x64",
                    ip_address=None,
                    user_agent="TraderPro Desktop Linux",
                    check_interval_seconds=3600,
                    grace_period_seconds=86400,
                    token_seconds=600,
                )
                self.assertEqual("not_found", token["status"])
                self.assertIsNone(token["token"])

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
        self.assertNotIn("nt8_version", manifest["app_update"])
        self.assertNotIn("trader_revision", manifest["app_update"])

    def test_strategy_package_rollback_uses_installed_packages(self) -> None:
        created = self.active_customer("strategy-rollback@example.com")
        self.strategy_release(
            version="0.1.0",
            rollback_reason="Rollback strategy package",
            nt8_version="2.1.0.8",
            trader_revision=1,
        )

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
        self.assertEqual("2.1.0.8", manifest["releases"][0]["nt8_version"])
        self.assertEqual(1, manifest["releases"][0]["trader_revision"])

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
            signature=None,
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
