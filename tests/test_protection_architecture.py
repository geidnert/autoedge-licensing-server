from __future__ import annotations

import tempfile
import unittest
from datetime import timedelta
from hashlib import sha256
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec

from autoedge_licensing.db import Database, apply_migrations
from autoedge_licensing.security import hash_fingerprint
from autoedge_licensing.service import LicensingService, iso, parse_time, utc_now
from autoedge_licensing.signing import (
    LICENSE_PAYLOAD_KIND,
    LICENSE_TOKEN_TYPE,
    RELEASE_TOKEN_TYPE,
    CompactES256Signer,
    release_envelope_payload,
    verify_compact_token,
)


class ProtectionArchitectureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.artifact_dir = Path(self.tmp.name) / "artifacts"
        self.artifact_dir.mkdir()
        self.database = Database(f"{self.tmp.name}/test.db")
        apply_migrations(self.database)
        self.license_private = ec.generate_private_key(ec.SECP256R1())
        self.release_private = ec.generate_private_key(ec.SECP256R1())
        self.license_signer = CompactES256Signer(self.license_private, "license-test-1")
        self.release_signer = CompactES256Signer(self.release_private, "release-test-1")
        self.service = LicensingService(
            self.database,
            license_signer=self.license_signer,
            release_public_keys={"release-test-1": self.release_private.public_key()},
            license_issuer="solidparts.se",
            license_audience="traderpro",
        )
        self.product = self.service.upsert_product(
            slug="duo-runtime",
            name="DUO Runtime",
            feature_id="strategy.duo.runtime",
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def active_customer(self, *, lifetime: bool = False):
        created = self.service.create_or_update_customer(email="signed-license@example.com")
        expiry = None if lifetime else iso(utc_now() + timedelta(hours=2))
        self.service.manual_set_entitlement(
            customer_id=created.customer["id"],
            product_id=self.product["id"],
            status="active",
            expires_at=expiry,
            reason="signed lease test",
            actor_id="admin",
            ip_address=None,
        )
        return created, expiry

    def check(self, created, fingerprint: str, grace: int = 3600):
        return self.service.check_license(
            license_key=created.license_key,
            email=None,
            customer_id=None,
            whop_user_id=None,
            machine_fingerprint=fingerprint,
            app_version="1.0.0",
            ip_address=None,
            user_agent=None,
            check_interval_seconds=600,
            grace_period_seconds=grace,
        )

    def verify_lease(self, token: str):
        return verify_compact_token(
            token,
            {"license-test-1": self.license_private.public_key()},
            expected_type=LICENSE_TOKEN_TYPE,
            expected_kind=LICENSE_PAYLOAD_KIND,
            validate_lease_times=True,
            expected_issuer="solidparts.se",
            expected_audience="traderpro",
        )

    def test_active_license_has_bound_finite_signed_lease_and_feature_expiry(self) -> None:
        created, feature_expiry = self.active_customer()
        fingerprint = "exact-machine-fingerprint"
        response = self.check(created, fingerprint, grace=7200)
        lease = response["license_lease"]
        verified = self.verify_lease(lease["token"])

        self.assertEqual("active", response["status"])
        self.assertEqual("license-test-1", lease["key_id"])
        self.assertEqual(created.customer["id"], verified.payload["sub"])
        self.assertEqual(response["device"]["id"], verified.payload["device_id"])
        self.assertEqual(hash_fingerprint(fingerprint), verified.payload["device_fingerprint_sha256"])
        self.assertEqual([{"id": "strategy.duo.runtime", "exp": feature_expiry}], verified.payload["features"])
        self.assertLessEqual(verified.payload["exp"] - verified.payload["iat"], 7200)
        self.assertEqual(lease["expires_at"], iso(parse_time(feature_expiry)))

    def test_lifetime_feature_still_gets_finite_lease(self) -> None:
        created, _ = self.active_customer(lifetime=True)
        response = self.check(created, "lifetime-machine", grace=1800)
        verified = self.verify_lease(response["license_lease"]["token"])

        self.assertEqual([{"id": "strategy.duo.runtime", "exp": None}], verified.payload["features"])
        self.assertEqual(1800, verified.payload["exp"] - verified.payload["iat"])

    def test_seeded_traderpro_runtime_features_are_bound_into_signed_lease(self) -> None:
        expected_features = [
            "strategy.adam.runtime",
            "strategy.aura.runtime",
            "strategy.emal.runtime",
            "strategy.eve.runtime",
            "strategy.orbo.runtime",
            "strategy.orboib.runtime",
        ]
        products = [
            product
            for product in self.service.list_products()
            if product["feature_id"] in expected_features
        ]
        created = self.service.create_or_update_customer(email="signed-runtime-seeds@example.com")
        feature_expiry = iso(utc_now() + timedelta(hours=2))
        for product in products:
            self.service.manual_set_entitlement(
                customer_id=created.customer["id"],
                product_id=product["id"],
                status="active",
                expires_at=feature_expiry,
                reason="signed runtime seed lease",
                actor_id="admin",
                ip_address=None,
            )

        response = self.check(created, "signed-runtime-seeds-machine", grace=7200)
        verified = self.verify_lease(response["license_lease"]["token"])

        self.assertEqual(expected_features, sorted(grant["feature_id"] for grant in response["licensed_strategies"]))
        self.assertEqual(
            [{"id": feature_id, "exp": feature_expiry} for feature_id in expected_features],
            verified.payload["features"],
        )

    def test_manifest_lease_omits_private_feature_when_release_audience_denies_customer(self) -> None:
        created, duo_expiry = self.active_customer()
        emal = next(
            product
            for product in self.service.list_products()
            if product["slug"] == "emal-runtime"
        )
        emal_expiry = iso(utc_now() + timedelta(hours=2))
        self.service.manual_set_entitlement(
            customer_id=created.customer["id"],
            product_id=emal["id"],
            status="active",
            expires_at=emal_expiry,
            reason="private manifest lease test",
            actor_id="admin",
            ip_address=None,
        )
        artifact = self.artifact_dir / "emal-private-windows-x64.zip"
        artifact.write_bytes(b"private EMAL release")
        self.service.upsert_release(
            release_id=None,
            scope="strategy",
            release_type="strategy_package",
            product_key="emal-runtime",
            product_id=emal["id"],
            channel="internal",
            platform="windows-x64",
            version="0.1.0",
            min_supported_version="0.1.182",
            is_required=False,
            is_active=True,
            artifact_path=artifact.name,
            artifact_filename=artifact.name,
            size_bytes=None,
            sha256_value=None,
            signature=None,
            release_notes=None,
            artifact_dir=str(self.artifact_dir),
            audience_mode="allowlist",
            allowed_customer_ids="different-customer",
            nt8_version="1.0.0.0",
            trader_revision=0,
        )

        direct_license = self.check(created, "private-manifest-machine")
        manifest = self.service.release_manifest(
            license_key=created.license_key,
            email=None,
            customer_id=None,
            whop_user_id=None,
            machine_fingerprint="private-manifest-machine",
            app_version="0.1.182",
            channel="stable",
            platform="windows-x64",
            include_types=["strategy_package"],
            ip_address=None,
            user_agent=None,
            check_interval_seconds=600,
            grace_period_seconds=3600,
        )
        verified = self.verify_lease(manifest["license"]["license_lease"]["token"])

        self.assertEqual(
            ["strategy.duo.runtime", "strategy.emal.runtime"],
            sorted(grant["feature_id"] for grant in direct_license["licensed_strategies"]),
        )
        self.assertNotIn("emal-runtime", [item["package_id"] for item in manifest["packages"]])
        self.assertEqual([], manifest["releases"])
        self.assertEqual(
            [{"id": "strategy.duo.runtime", "exp": duo_expiry}],
            verified.payload["features"],
        )

    def test_blocking_responses_have_null_lease(self) -> None:
        unknown = self.service.check_license(
            license_key=None,
            email="unknown@example.com",
            customer_id=None,
            whop_user_id=None,
            machine_fingerprint="unknown-machine",
            app_version=None,
            ip_address=None,
            user_agent=None,
            check_interval_seconds=600,
            grace_period_seconds=3600,
        )
        created, _ = self.active_customer()
        active = self.check(created, "blocked-machine")
        self.service.set_device_blocked(
            device_id=active["device"]["id"],
            is_blocked=True,
            note="test",
            actor_id="admin",
            ip_address=None,
        )
        blocked = self.check(created, "blocked-machine")

        self.assertIsNone(unknown["license_lease"])
        self.assertIsNone(blocked["license_lease"])

    def envelope(self, artifact: Path, **overrides):
        values = {
            "release_type": "strategy_package",
            "package_id": "duo-runtime",
            "feature_id": "strategy.duo.runtime",
            "channel": "stable",
            "platform": "windows-x64",
            "version": "1.2.3",
            "minimum_trader_version": "1.0.0",
            "filename": artifact.name,
            "size_bytes": artifact.stat().st_size,
            "sha256": sha256(artifact.read_bytes()).hexdigest(),
        }
        values.update(overrides)
        return release_envelope_payload(**values)

    def register(self, artifact: Path, signature: str | None, *, service=None, signature_key_id="release-test-1"):
        return (service or self.service).upsert_release(
            release_id=None,
            scope="strategy",
            release_type="strategy_package",
            product_key="duo-runtime",
            product_id=self.product["id"],
            channel="stable",
            platform="windows-x64",
            version="1.2.3",
            min_supported_version="1.0.0",
            is_required=False,
            is_active=True,
            artifact_path=artifact.name,
            artifact_filename=artifact.name,
            size_bytes=None,
            sha256_value=None,
            signature=signature,
            signature_key_id=signature_key_id if signature else None,
            release_notes=None,
            artifact_dir=str(self.artifact_dir),
        )

    def test_valid_release_signature_is_preserved_in_manifest_and_download_token(self) -> None:
        created, _ = self.active_customer()
        artifact = self.artifact_dir / "duo-1.2.3.zip"
        artifact.write_bytes(b"signed release artifact")
        signature = self.release_signer.sign(self.envelope(artifact), token_type=RELEASE_TOKEN_TYPE)
        release = self.register(artifact, signature)
        manifest = self.service.release_manifest(
            license_key=created.license_key,
            email=None,
            customer_id=None,
            whop_user_id=None,
            machine_fingerprint="signed-release-machine",
            app_version="1.0.0",
            channel="stable",
            platform="windows-x64",
            include_types=["strategy_package"],
            ip_address=None,
            user_agent=None,
            check_interval_seconds=600,
            grace_period_seconds=3600,
        )
        token = self.service.create_release_download_token(
            release_id=release["id"],
            license_key=created.license_key,
            email=None,
            customer_id=None,
            whop_user_id=None,
            machine_fingerprint="signed-release-machine",
            app_version="1.0.0",
            channel="stable",
            platform="windows-x64",
            ip_address=None,
            user_agent=None,
            check_interval_seconds=600,
            grace_period_seconds=3600,
            token_seconds=600,
        )

        self.assertEqual(signature, release["signature"])
        self.assertEqual(signature, manifest["releases"][0]["artifact"]["signature"])
        self.assertEqual(signature, token["release"]["artifact"]["signature"])
        self.assertIsNotNone(manifest["license"]["license_lease"])

    def test_seeded_orbo_runtime_uses_exact_feature_under_required_release_signing(self) -> None:
        product = next(
            product
            for product in self.service.list_products()
            if product["slug"] == "orbo-runtime"
        )
        created = self.service.create_or_update_customer(email="signed-orbo-runtime@example.com")
        self.service.manual_set_entitlement(
            customer_id=created.customer["id"],
            product_id=product["id"],
            status="active",
            expires_at=iso(utc_now() + timedelta(hours=2)),
            reason="signed ORBO2 runtime",
            actor_id="admin",
            ip_address=None,
        )
        artifact = self.artifact_dir / "orbo-runtime-0.1.0-windows-x64.zip"
        artifact.write_bytes(b"signed ORBO2 runtime artifact")
        envelope = release_envelope_payload(
            release_type="strategy_package",
            package_id="orbo-runtime",
            feature_id="strategy.orbo.runtime",
            channel="stable",
            platform="windows-x64",
            version="0.1.0",
            minimum_trader_version="0.1.182",
            filename=artifact.name,
            size_bytes=artifact.stat().st_size,
            sha256=sha256(artifact.read_bytes()).hexdigest(),
        )
        signature = self.release_signer.sign(envelope, token_type=RELEASE_TOKEN_TYPE)
        required_service = LicensingService(
            self.database,
            license_signer=self.license_signer,
            release_public_keys={"release-test-1": self.release_private.public_key()},
            require_release_signatures=True,
            license_issuer="solidparts.se",
            license_audience="traderpro",
        )
        release = required_service.upsert_release(
            release_id=None,
            scope="strategy",
            release_type="strategy_package",
            product_key="orbo-runtime",
            product_id=product["id"],
            channel="stable",
            platform="windows-x64",
            version="0.1.0",
            nt8_version="2.0.2.1",
            trader_revision=0,
            min_supported_version="0.1.182",
            is_required=False,
            is_active=True,
            artifact_path=artifact.name,
            artifact_filename=artifact.name,
            size_bytes=None,
            sha256_value=None,
            signature=signature,
            signature_key_id="release-test-1",
            release_notes="Signed ORBO2 runtime",
            artifact_dir=str(self.artifact_dir),
        )
        manifest = required_service.release_manifest(
            license_key=created.license_key,
            email=None,
            customer_id=None,
            whop_user_id=None,
            machine_fingerprint="signed-orbo-runtime-machine",
            app_version="0.1.0",
            channel="stable",
            platform="windows-x64",
            include_types=["strategy_package"],
            ip_address=None,
            user_agent=None,
            check_interval_seconds=600,
            grace_period_seconds=3600,
        )
        token = required_service.create_release_download_token(
            release_id=release["id"],
            license_key=created.license_key,
            email=None,
            customer_id=None,
            whop_user_id=None,
            machine_fingerprint="signed-orbo-runtime-machine",
            app_version="0.1.0",
            channel="stable",
            platform="windows-x64",
            ip_address=None,
            user_agent=None,
            check_interval_seconds=600,
            grace_period_seconds=3600,
            token_seconds=600,
        )

        self.assertEqual(["orbo-runtime"], [item["package_id"] for item in manifest["releases"]])
        self.assertEqual(
            ["strategy.orbo.runtime"],
            manifest["releases"][0]["required_features"],
        )
        self.assertEqual(signature, manifest["releases"][0]["artifact"]["signature"])
        self.assertEqual("0.1.182", manifest["releases"][0]["min_supported_version"])
        self.assertEqual("2.0.2.1", manifest["releases"][0]["nt8_version"])
        self.assertEqual(0, manifest["releases"][0]["trader_revision"])
        self.assertEqual("ok", token["status"])
        self.assertEqual(["strategy.orbo.runtime"], token["release"]["required_features"])
        self.assertEqual(signature, token["release"]["artifact"]["signature"])

    def test_release_registration_rejects_metadata_mismatches_and_key_id(self) -> None:
        artifact = self.artifact_dir / "duo-1.2.3.zip"
        artifact.write_bytes(b"signed release artifact")
        mismatches = {
            "hash": {"sha256": "0" * 64},
            "size": {"size_bytes": artifact.stat().st_size + 1},
            "platform": {"platform": "linux-x64"},
            "version": {"version": "9.9.9"},
            "package": {"package_id": "other-package"},
            "feature": {"feature_id": "strategy.other.runtime"},
            "channel": {"channel": "beta"},
            "filename": {"filename": "other.zip"},
        }
        for label, override in mismatches.items():
            signature = self.release_signer.sign(self.envelope(artifact, **override), token_type=RELEASE_TOKEN_TYPE)
            with self.subTest(label=label), self.assertRaises(ValueError):
                self.register(artifact, signature)
        valid = self.release_signer.sign(self.envelope(artifact), token_type=RELEASE_TOKEN_TYPE)
        with self.assertRaises(ValueError):
            self.register(artifact, valid, signature_key_id="release-other")

    def test_real_artifact_hash_and_size_overrides_must_match(self) -> None:
        artifact = self.artifact_dir / "duo-1.2.3.zip"
        artifact.write_bytes(b"actual artifact")
        common = dict(
            release_id=None,
            scope="strategy",
            product_id=self.product["id"],
            channel="stable",
            platform="windows-x64",
            version="1.2.3",
            min_supported_version=None,
            is_required=False,
            is_active=False,
            artifact_path=artifact.name,
            artifact_filename=None,
            signature=None,
            release_notes=None,
            artifact_dir=str(self.artifact_dir),
        )
        with self.assertRaises(ValueError):
            self.service.upsert_release(size_bytes=999, sha256_value=None, **common)
        with self.assertRaises(ValueError):
            self.service.upsert_release(size_bytes=None, sha256_value="0" * 64, **common)

    def test_invalid_signature_rejected_when_optional_and_unsigned_transition_modes(self) -> None:
        artifact = self.artifact_dir / "duo-1.2.3.zip"
        artifact.write_bytes(b"signed release artifact")
        valid = self.release_signer.sign(self.envelope(artifact), token_type=RELEASE_TOKEN_TYPE)
        invalid = valid[:-1] + ("A" if valid[-1] != "A" else "B")
        with self.assertRaises(ValueError):
            self.register(artifact, invalid)

        unsigned = self.register(artifact, None)
        self.assertIsNone(unsigned["signature"])

        required_service = LicensingService(
            self.database,
            release_public_keys={"release-test-1": self.release_private.public_key()},
            require_release_signatures=True,
        )
        with self.assertRaises(ValueError):
            self.register(artifact, None, service=required_service)
        inactive = required_service.upsert_release(
            release_id=None,
            scope="strategy",
            product_id=self.product["id"],
            channel="stable",
            platform="windows-x64",
            version="1.2.4",
            min_supported_version=None,
            is_required=False,
            is_active=False,
            artifact_path=artifact.name,
            artifact_filename=None,
            size_bytes=None,
            sha256_value=None,
            signature=None,
            release_notes=None,
            artifact_dir=str(self.artifact_dir),
        )
        self.assertFalse(inactive["is_active"])


if __name__ == "__main__":
    unittest.main()
