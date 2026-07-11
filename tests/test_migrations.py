from __future__ import annotations

import tempfile
import unittest
from datetime import timedelta

from autoedge_licensing.db import Database, apply_migrations, migration_dir
from autoedge_licensing.service import iso, utc_now


class EntitlementSourceMigrationTests(unittest.TestCase):
    def test_legacy_multi_package_entitlement_is_split_and_future_expiry_reactivated(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Database(f"{directory}/legacy.db")
            migrations = sorted(migration_dir().glob("*.sql"))
            apply_migrations(database, [migration for migration in migrations if migration.name < "013_entitlement_sources.sql"])

            now = utc_now().replace(microsecond=0)
            trial_end = now + timedelta(days=7)
            paid_end = now + timedelta(days=60)
            with database.session() as connection:
                connection.execute(
                    """
                    INSERT INTO customers(id, email, email_normalized, created_at, updated_at)
                    VALUES ('customer-legacy', 'legacy@example.com', 'legacy@example.com', ?, ?)
                    """,
                    (iso(now), iso(now)),
                )
                connection.execute(
                    """
                    INSERT INTO products(id, slug, name, feature_id, created_at, updated_at)
                    VALUES ('product-legacy', 'legacy-runtime', 'Legacy Runtime', 'strategy.legacy.runtime', ?, ?)
                    """,
                    (iso(now), iso(now)),
                )
                connection.executemany(
                    """
                    INSERT INTO whop_packages(
                        id, whop_id, whop_id_type, name, default_days, is_active,
                        is_ignored, created_at, updated_at
                    )
                    VALUES (?, ?, 'plan', ?, 30, 1, 0, ?, ?)
                    """,
                    [
                        ("package-trial", "plan_trial", "Trial", iso(now), iso(now)),
                        ("package-paid", "plan_paid", "Paid", iso(now), iso(now)),
                    ],
                )
                connection.execute(
                    """
                    INSERT INTO subscriptions(
                        id, customer_id, whop_membership_id, status, raw_status,
                        current_period_start, current_period_end, created_at, updated_at
                    )
                    VALUES ('subscription-legacy', 'customer-legacy', 'membership-legacy',
                            'active', 'active', ?, ?, ?, ?)
                    """,
                    (iso(now), iso(paid_end), iso(now), iso(now)),
                )
                connection.execute(
                    """
                    INSERT INTO entitlements(
                        id, customer_id, product_id, subscription_id, external_id, source,
                        status, starts_at, expires_at, whop_event_id, created_at, updated_at
                    )
                    VALUES ('entitlement-legacy', 'customer-legacy', 'product-legacy',
                            'subscription-legacy', 'membership-legacy:product-legacy', 'whop',
                            'expired', ?, ?, 'event-stale-expiry', ?, ?)
                    """,
                    (iso(now), iso(paid_end), iso(now), iso(now)),
                )
                connection.executemany(
                    """
                    INSERT INTO license_grant_ledger(
                        id, customer_id, package_id, product_id, subscription_id,
                        entitlement_id, whop_event_id, event_fingerprint, grant_kind,
                        days_applied, period_start, period_end, expires_at_before,
                        expires_at_after, applied_at
                    )
                    VALUES (?, 'customer-legacy', ?, 'product-legacy', 'subscription-legacy',
                            'entitlement-legacy', ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    [
                        (
                            "ledger-trial",
                            "package-trial",
                            "event-trial",
                            "fingerprint-trial",
                            "trial",
                            7,
                            iso(now),
                            iso(trial_end),
                            None,
                            iso(trial_end),
                            iso(now - timedelta(seconds=3)),
                        ),
                        (
                            "ledger-paid",
                            "package-paid",
                            "event-paid",
                            "fingerprint-paid",
                            "paid",
                            30,
                            iso(trial_end),
                            iso(paid_end),
                            iso(trial_end),
                            iso(paid_end),
                            iso(now - timedelta(seconds=2)),
                        ),
                        (
                            "ledger-expired",
                            "package-paid",
                            "event-stale-expiry",
                            "fingerprint-expired",
                            "expire",
                            0,
                            None,
                            iso(trial_end),
                            iso(paid_end),
                            iso(paid_end),
                            iso(now - timedelta(seconds=1)),
                        ),
                    ],
                )

            apply_migrations(database)

            with database.session() as connection:
                rows = connection.execute(
                    "SELECT package_id, status, expires_at FROM entitlements ORDER BY package_id"
                ).fetchall()

            self.assertEqual(["package-paid", "package-trial"], [row["package_id"] for row in rows])
            self.assertEqual("active", rows[0]["status"])
            self.assertEqual(iso(paid_end), rows[0]["expires_at"])
            self.assertEqual("trialing", rows[1]["status"])
            self.assertEqual(iso(trial_end), rows[1]["expires_at"])


class StrategyReleaseIdentityMigrationTests(unittest.TestCase):
    def test_existing_release_gains_nullable_identity_columns_without_backfill(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Database(f"{directory}/legacy-release.db")
            migrations = sorted(migration_dir().glob("*.sql"))
            apply_migrations(database, [migration for migration in migrations if migration.name < "014_strategy_release_identity.sql"])
            now = iso(utc_now().replace(microsecond=0))
            with database.session() as connection:
                connection.execute(
                    """
                    INSERT INTO products(id, slug, name, feature_id, created_at, updated_at)
                    VALUES ('product-legacy-release', 'legacy-runtime', 'Legacy Runtime',
                            'strategy.legacy.runtime', ?, ?)
                    """,
                    (now, now),
                )
                connection.execute(
                    """
                    INSERT INTO trader_releases(
                        id, product_id, scope, release_type, product_key, channel,
                        platform, version, is_required, is_active, artifact_path,
                        artifact_filename, created_at, updated_at
                    )
                    VALUES ('release-legacy', 'product-legacy-release', 'strategy',
                            'strategy_package', 'legacy-runtime', 'stable',
                            'windows-x64', '1.0.0', 0, 1, 'legacy.zip',
                            'legacy.zip', ?, ?)
                    """,
                    (now, now),
                )

            apply_migrations(database)

            with database.session() as connection:
                columns = {row["name"] for row in connection.execute("PRAGMA table_info(trader_releases)")}
                release = connection.execute(
                    "SELECT nt8_version, trader_revision FROM trader_releases WHERE id = 'release-legacy'"
                ).fetchone()
                migration = connection.execute(
                    "SELECT name FROM schema_migrations WHERE name = '014_strategy_release_identity.sql'"
                ).fetchone()

            self.assertIn("nt8_version", columns)
            self.assertIn("trader_revision", columns)
            self.assertIsNone(release["nt8_version"])
            self.assertIsNone(release["trader_revision"])
            self.assertIsNotNone(migration)


class LinuxReleasePlatformMigrationTests(unittest.TestCase):
    def test_existing_mich_metadata_adds_linux_without_creating_release_rows(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Database(f"{directory}/pre-linux.db")
            migrations = sorted(migration_dir().glob("*.sql"))
            apply_migrations(
                database,
                [migration for migration in migrations if migration.name < "015_linux_x64_release_platform.sql"],
            )

            apply_migrations(database)

            with database.session() as connection:
                product = connection.execute(
                    "SELECT metadata_json FROM products WHERE slug = 'mich-runtime'"
                ).fetchone()
                release_count = connection.execute(
                    "SELECT COUNT(*) FROM trader_releases WHERE platform = 'linux-x64'"
                ).fetchone()[0]
                migration = connection.execute(
                    "SELECT name FROM schema_migrations WHERE name = '015_linux_x64_release_platform.sql'"
                ).fetchone()

            self.assertIn(
                '"supported_platforms":["macos-arm64","windows-x64","linux-x64"]',
                product["metadata_json"],
            )
            self.assertEqual(0, release_count)
            self.assertIsNotNone(migration)


if __name__ == "__main__":
    unittest.main()
