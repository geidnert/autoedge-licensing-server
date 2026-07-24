from __future__ import annotations

import json
import tempfile
import unittest
from datetime import timedelta

from autoedge_licensing.db import Database, apply_migrations, migration_dir
from autoedge_licensing.service import LicensingService, iso, utc_now
from scripts.seed_products import seed_default_products


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


class ProductSubscriptionUrlMigrationTests(unittest.TestCase):
    def test_existing_products_gain_nullable_url_and_duo_mapping(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Database(f"{directory}/pre-subscription-url.db")
            migrations = sorted(migration_dir().glob("*.sql"))
            apply_migrations(
                database,
                [migration for migration in migrations if migration.name < "016_product_subscription_urls.sql"],
            )
            now = iso(utc_now().replace(microsecond=0))
            with database.session() as connection:
                connection.executemany(
                    """
                    INSERT INTO products(id, slug, name, feature_id, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    [
                        ("product-legacy", "legacy-runtime", "Legacy Runtime", "strategy.legacy.runtime", now, now),
                        ("product-duo", "duo-runtime", "DUO Runtime", "strategy.duo.runtime", now, now),
                        ("product-duorc", "duorc-runtime", "DUOrc Runtime", "strategy.duorc.runtime", now, now),
                    ],
                )

            apply_migrations(database)

            with database.session() as connection:
                columns = {row["name"] for row in connection.execute("PRAGMA table_info(products)")}
                products = {
                    row["slug"]: row["subscription_url"]
                    for row in connection.execute(
                        "SELECT slug, subscription_url FROM products "
                        "WHERE id IN ('product-legacy', 'product-duo', 'product-duorc')"
                    )
                }
                migration = connection.execute(
                    "SELECT name FROM schema_migrations WHERE name = '016_product_subscription_urls.sql'"
                ).fetchone()

            self.assertIn("subscription_url", columns)
            self.assertIsNone(products["legacy-runtime"])
            self.assertEqual(
                "https://whop.com/auto-edge/duo-nasdaq-futures-bot/",
                products["duo-runtime"],
            )
            self.assertEqual(
                "https://whop.com/auto-edge/duo-nasdaq-futures-bot/",
                products["duorc-runtime"],
            )
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


class TraderProRuntimePackageSeedMigrationTests(unittest.TestCase):
    EXPECTED = {
        "orbo-runtime": {
            "name": "ORBO2 Runtime",
            "feature_id": "strategy.orbo.runtime",
            "strategy_family": "ORBO2",
            "strategy_id": "orbo",
            "entry_assembly": "Trader.Strategies.Orbo.dll",
            "planned_nt8_version": "2.0.2.1",
        },
        "orboib-runtime": {
            "name": "ORBO2ib Runtime",
            "feature_id": "strategy.orboib.runtime",
            "strategy_family": "ORBO2ib",
            "strategy_id": "orboib",
            "entry_assembly": "Trader.Strategies.Orboib.dll",
            "planned_nt8_version": "2.0.0.8",
        },
        "adam-runtime": {
            "name": "ADAM Runtime",
            "feature_id": "strategy.adam.runtime",
            "strategy_family": "ADAM",
            "strategy_id": "adam",
            "entry_assembly": "Trader.Strategies.Adam.dll",
            "planned_nt8_version": "1.0.1.5",
        },
        "eve-runtime": {
            "name": "EVE Runtime",
            "feature_id": "strategy.eve.runtime",
            "strategy_family": "EVE",
            "strategy_id": "eve",
            "entry_assembly": "Trader.Strategies.Eve.dll",
            "planned_nt8_version": "1.0.2.6",
        },
        "aura-runtime": {
            "name": "AURA Runtime",
            "feature_id": "strategy.aura.runtime",
            "strategy_family": "AURA",
            "strategy_id": "aura",
            "entry_assembly": "Trader.Strategies.Aura.dll",
            "planned_nt8_version": "1.0.0.3",
        },
    }

    def test_migration_backfills_existing_products_without_rekeying_entitlements(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Database(f"{directory}/pre-runtime-packages.db")
            migrations = sorted(migration_dir().glob("*.sql"))
            apply_migrations(
                database,
                [
                    migration
                    for migration in migrations
                    if migration.name < "017_seed_traderpro_runtime_packages.sql"
                ],
            )
            now = iso(utc_now().replace(microsecond=0))
            legacy_products = [
                (
                    "product-orbo",
                    "orbo2-runtime",
                    "ORBO2 Runtime",
                    "strategy.orbo2.runtime",
                    "ORBO2",
                ),
                (
                    "product-orboib",
                    "orboib-runtime",
                    "ORBOib Runtime",
                    "strategy.orboib.runtime",
                    "ORBOib",
                ),
                (
                    "product-adam",
                    "adam-runtime",
                    "ADAM Runtime",
                    "strategy.adam.runtime",
                    "ADAM",
                ),
                (
                    "product-eve",
                    "eve-runtime",
                    "EVE Runtime",
                    "strategy.eve.runtime",
                    "EVE",
                ),
                (
                    "product-aura",
                    "aura-runtime",
                    "AURA Runtime",
                    "strategy.aura.runtime",
                    "AURA",
                ),
            ]
            with database.session() as connection:
                connection.execute(
                    """
                    INSERT INTO customers(id, email, email_normalized, created_at, updated_at)
                    VALUES ('customer-runtime-seeds', 'runtime-seeds@example.com',
                            'runtime-seeds@example.com', ?, ?)
                    """,
                    (now, now),
                )
                connection.executemany(
                    """
                    INSERT INTO products(
                        id, slug, name, feature_id, is_active, metadata_json,
                        created_at, updated_at, nt8_strategy_key, trader_enabled,
                        nt8_enabled, subscription_url
                    )
                    VALUES (?, ?, ?, ?, 1, '{"legacy":true}', ?, ?, ?, 1, 1, NULL)
                    """,
                    [
                        (product_id, slug, name, feature_id, now, now, nt8_key)
                        for product_id, slug, name, feature_id, nt8_key in legacy_products
                    ],
                )
                connection.executemany(
                    """
                    INSERT INTO entitlements(
                        id, customer_id, product_id, source, status, starts_at,
                        created_at, updated_at
                    )
                    VALUES (?, 'customer-runtime-seeds', ?, 'manual', 'active', ?, ?, ?)
                    """,
                    [
                        (f"entitlement-{product_id}", product_id, now, now, now)
                        for product_id, *_ in legacy_products
                    ],
                )

            apply_migrations(database)
            with database.session() as connection:
                first_products = {
                    row["slug"]: dict(row)
                    for row in connection.execute(
                        """
                        SELECT *
                        FROM products
                        WHERE slug IN ('orbo-runtime', 'orboib-runtime', 'adam-runtime',
                                       'eve-runtime', 'aura-runtime')
                        ORDER BY slug
                        """
                    )
                }
                first_entitlement_product_ids = [
                    row["product_id"]
                    for row in connection.execute(
                        """
                        SELECT product_id
                        FROM entitlements
                        WHERE customer_id = 'customer-runtime-seeds'
                        ORDER BY product_id
                        """
                    )
                ]
                release_count = connection.execute(
                    """
                    SELECT COUNT(*)
                    FROM trader_releases
                    WHERE product_id IN (
                        'product-orbo', 'product-orboib', 'product-adam',
                        'product-eve', 'product-aura'
                    )
                    """
                ).fetchone()[0]

            apply_migrations(database)
            with database.session() as connection:
                repeated_products = {
                    row["slug"]: dict(row)
                    for row in connection.execute(
                        """
                        SELECT *
                        FROM products
                        WHERE slug IN ('orbo-runtime', 'orboib-runtime', 'adam-runtime',
                                       'eve-runtime', 'aura-runtime')
                        ORDER BY slug
                        """
                    )
                }
                migration_count = connection.execute(
                    """
                    SELECT COUNT(*)
                    FROM schema_migrations
                    WHERE name = '017_seed_traderpro_runtime_packages.sql'
                    """
                ).fetchone()[0]
                legacy_orbo_count = connection.execute(
                    """
                    SELECT COUNT(*)
                    FROM products
                    WHERE slug = 'orbo2-runtime'
                       OR feature_id = 'strategy.orbo2.runtime'
                    """
                ).fetchone()[0]

            self.assertEqual(set(self.EXPECTED), set(first_products))
            self.assertEqual(first_products, repeated_products)
            self.assertEqual(
                sorted(product_id for product_id, *_ in legacy_products),
                first_entitlement_product_ids,
            )
            self.assertEqual(0, release_count)
            self.assertEqual(1, migration_count)
            self.assertEqual(0, legacy_orbo_count)
            for slug, expected in self.EXPECTED.items():
                with self.subTest(slug=slug):
                    product = first_products[slug]
                    metadata = json.loads(product["metadata_json"])
                    expected_id = next(
                        product_id
                        for product_id, legacy_slug, *_ in legacy_products
                        if legacy_slug in {slug, "orbo2-runtime" if slug == "orbo-runtime" else slug}
                    )
                    self.assertEqual(expected_id, product["id"])
                    self.assertEqual(expected["name"], product["name"])
                    self.assertEqual(expected["feature_id"], product["feature_id"])
                    self.assertEqual("strategy_package", metadata["package_kind"])
                    self.assertEqual("strategy_package", metadata["release_type"])
                    self.assertEqual(slug, metadata["runtime_package_id"])
                    self.assertEqual(expected["strategy_id"], metadata["strategy_id"])
                    self.assertEqual(expected["strategy_family"], metadata["strategy_family"])
                    self.assertEqual("Runtime", metadata["variant"])
                    self.assertEqual(expected["entry_assembly"], metadata["entry_assembly"])
                    self.assertEqual("0.1.0", metadata["initial_runtime_version"])
                    self.assertEqual("0.1.182", metadata["minimum_trader_version"])
                    self.assertEqual(
                        expected["planned_nt8_version"],
                        metadata["planned_nt8_version"],
                    )
                    self.assertEqual(
                        ["macos-arm64", "windows-x64", "linux-x64"],
                        metadata["supported_platforms"],
                    )
                    self.assertEqual(
                        {"algorithm": "Ed25519", "key_id": "main-2026-01"},
                        metadata["package_signature"],
                    )

    def test_script_seed_is_idempotent_and_creates_no_release_or_whop_mapping_rows(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Database(f"{directory}/script-seeds.db")
            apply_migrations(database)
            service = LicensingService(database)

            first = {
                product["slug"]: product["id"]
                for product in seed_default_products(service)
                if product["slug"] in self.EXPECTED
            }
            second = {
                product["slug"]: product["id"]
                for product in seed_default_products(service)
                if product["slug"] in self.EXPECTED
            }

            with database.session() as connection:
                counts = {
                    row["slug"]: row["product_count"]
                    for row in connection.execute(
                        """
                        SELECT slug, COUNT(*) AS product_count
                        FROM products
                        WHERE slug IN ('orbo-runtime', 'orboib-runtime', 'adam-runtime',
                                       'eve-runtime', 'aura-runtime')
                        GROUP BY slug
                        """
                    )
                }
                release_count = connection.execute(
                    "SELECT COUNT(*) FROM trader_releases"
                ).fetchone()[0]
                package_count = connection.execute(
                    "SELECT COUNT(*) FROM whop_packages"
                ).fetchone()[0]
                grant_count = connection.execute(
                    "SELECT COUNT(*) FROM whop_package_grants"
                ).fetchone()[0]

            self.assertEqual(first, second)
            self.assertEqual({slug: 1 for slug in self.EXPECTED}, counts)
            self.assertEqual(0, release_count)
            self.assertEqual(0, package_count)
            self.assertEqual(0, grant_count)


if __name__ == "__main__":
    unittest.main()
