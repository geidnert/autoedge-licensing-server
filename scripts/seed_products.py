#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from autoedge_licensing.config import Settings
from autoedge_licensing.db import Database, apply_migrations
from autoedge_licensing.service import LicensingService


DEFAULT_PRODUCTS = [
    {
        "slug": "duo-runtime",
        "name": "DUO Runtime",
        "feature_id": "strategy.duo.runtime",
        "subscription_url": "https://whop.com/auto-edge/duo-nasdaq-futures-bot/",
    },
    {
        "slug": "duorc-runtime",
        "name": "DUOrc Runtime",
        "feature_id": "strategy.duorc.runtime",
        "subscription_url": "https://whop.com/auto-edge/duo-nasdaq-futures-bot/",
    },
    {
        "slug": "orbo-runtime",
        "name": "ORBO2 Runtime",
        "feature_id": "strategy.orbo.runtime",
        "nt8_strategy_key": "ORBO2",
        "metadata": {
            "seeded": True,
            "strategy_id": "orbo",
            "strategy_family": "ORBO2",
            "variant": "Runtime",
            "package_kind": "strategy_package",
            "release_type": "strategy_package",
            "runtime_package_id": "orbo-runtime",
            "entry_assembly": "Trader.Strategies.Orbo.dll",
            "initial_runtime_version": "0.1.0",
            "minimum_trader_version": "0.1.182",
            "planned_nt8_version": "2.0.2.1",
            "supported_platforms": ["macos-arm64", "windows-x64", "linux-x64"],
            "package_signature": {"algorithm": "Ed25519", "key_id": "main-2026-01"},
        },
    },
    {
        "slug": "orboib-runtime",
        "name": "ORBO2ib Runtime",
        "feature_id": "strategy.orboib.runtime",
        "nt8_strategy_key": "ORBOib",
        "metadata": {
            "seeded": True,
            "strategy_id": "orboib",
            "strategy_family": "ORBO2ib",
            "variant": "Runtime",
            "package_kind": "strategy_package",
            "release_type": "strategy_package",
            "runtime_package_id": "orboib-runtime",
            "entry_assembly": "Trader.Strategies.Orboib.dll",
            "initial_runtime_version": "0.1.0",
            "minimum_trader_version": "0.1.182",
            "planned_nt8_version": "2.0.0.8",
            "supported_platforms": ["macos-arm64", "windows-x64", "linux-x64"],
            "package_signature": {"algorithm": "Ed25519", "key_id": "main-2026-01"},
        },
    },
    {
        "slug": "adam-runtime",
        "name": "ADAM Runtime",
        "feature_id": "strategy.adam.runtime",
        "nt8_strategy_key": "ADAM",
        "metadata": {
            "seeded": True,
            "strategy_id": "adam",
            "strategy_family": "ADAM",
            "variant": "Runtime",
            "package_kind": "strategy_package",
            "release_type": "strategy_package",
            "runtime_package_id": "adam-runtime",
            "entry_assembly": "Trader.Strategies.Adam.dll",
            "initial_runtime_version": "0.1.0",
            "minimum_trader_version": "0.1.182",
            "planned_nt8_version": "1.0.1.5",
            "supported_platforms": ["macos-arm64", "windows-x64", "linux-x64"],
            "package_signature": {"algorithm": "Ed25519", "key_id": "main-2026-01"},
        },
    },
    {
        "slug": "eve-runtime",
        "name": "EVE Runtime",
        "feature_id": "strategy.eve.runtime",
        "nt8_strategy_key": "EVE",
        "metadata": {
            "seeded": True,
            "strategy_id": "eve",
            "strategy_family": "EVE",
            "variant": "Runtime",
            "package_kind": "strategy_package",
            "release_type": "strategy_package",
            "runtime_package_id": "eve-runtime",
            "entry_assembly": "Trader.Strategies.Eve.dll",
            "initial_runtime_version": "0.1.0",
            "minimum_trader_version": "0.1.182",
            "planned_nt8_version": "1.0.2.6",
            "supported_platforms": ["macos-arm64", "windows-x64", "linux-x64"],
            "package_signature": {"algorithm": "Ed25519", "key_id": "main-2026-01"},
        },
    },
    {
        "slug": "mich-runtime",
        "name": "MICH Runtime",
        "feature_id": "strategy.mich.runtime",
        "metadata": {
            "seeded": True,
            "strategy_id": "mich",
            "package_kind": "strategy_package",
            "release_type": "strategy_package",
            "runtime_package_id": "mich-runtime",
            "entry_assembly": "Trader.Strategies.Mich.dll",
            "initial_runtime_version": "0.1.0",
            "supported_platforms": ["macos-arm64", "windows-x64", "linux-x64"],
        },
    },
    {"slug": "hugo-runtime", "name": "HUGO Runtime", "feature_id": "strategy.hugo.runtime"},
    {
        "slug": "aura-runtime",
        "name": "AURA Runtime",
        "feature_id": "strategy.aura.runtime",
        "nt8_strategy_key": "AURA",
        "metadata": {
            "seeded": True,
            "strategy_id": "aura",
            "strategy_family": "AURA",
            "variant": "Runtime",
            "package_kind": "strategy_package",
            "release_type": "strategy_package",
            "runtime_package_id": "aura-runtime",
            "entry_assembly": "Trader.Strategies.Aura.dll",
            "initial_runtime_version": "0.1.0",
            "minimum_trader_version": "0.1.182",
            "planned_nt8_version": "1.0.0.3",
            "supported_platforms": ["macos-arm64", "windows-x64", "linux-x64"],
            "package_signature": {"algorithm": "Ed25519", "key_id": "main-2026-01"},
        },
    },
    {
        "slug": "discord-notifier",
        "name": "Discord Notifier",
        "feature_id": "trader.notifications.discord",
        "nt8_enabled": False,
        "metadata": {"seeded": True, "package_kind": "extension", "release_type": "extension_package"},
    },
]


def seed_default_products(
    service: LicensingService,
    whop_product_ids: dict[str, str | None] | None = None,
) -> list[dict[str, object]]:
    whop_ids = whop_product_ids or {}
    existing_slugs = {product["slug"] for product in service.list_products()}
    seeded: list[dict[str, object]] = []
    for definition in DEFAULT_PRODUCTS:
        slug = definition["slug"]
        subscription_fields = (
            {"subscription_url": definition["subscription_url"]}
            if slug not in existing_slugs and definition.get("subscription_url")
            else {}
        )
        seeded.append(
            service.upsert_product(
                slug=slug,
                name=definition["name"],
                feature_id=definition["feature_id"],
                whop_product_id=whop_ids.get(slug),
                nt8_strategy_key=definition.get("nt8_strategy_key"),
                trader_enabled=definition.get("trader_enabled", True),
                nt8_enabled=definition.get("nt8_enabled", True),
                metadata=definition.get("metadata", {"seeded": True, "package_kind": "strategy"}),
                **subscription_fields,
            )
        )
    return seeded


def main() -> int:
    parser = argparse.ArgumentParser(description="Seed AutoEdge strategy products.")
    parser.add_argument("--duo-whop-product-id")
    parser.add_argument("--duorc-whop-product-id")
    parser.add_argument("--orbo2-whop-product-id")
    parser.add_argument("--orboib-whop-product-id")
    parser.add_argument("--adam-whop-product-id")
    parser.add_argument("--eve-whop-product-id")
    parser.add_argument("--mich-whop-product-id")
    parser.add_argument("--hugo-whop-product-id")
    parser.add_argument("--aura-whop-product-id")
    parser.add_argument("--discord-notifier-whop-product-id")
    args = parser.parse_args()

    whop_ids = {
        "duo-runtime": args.duo_whop_product_id,
        "duorc-runtime": args.duorc_whop_product_id,
        "orbo-runtime": args.orbo2_whop_product_id,
        "orboib-runtime": args.orboib_whop_product_id,
        "adam-runtime": args.adam_whop_product_id,
        "eve-runtime": args.eve_whop_product_id,
        "mich-runtime": args.mich_whop_product_id,
        "hugo-runtime": args.hugo_whop_product_id,
        "aura-runtime": args.aura_whop_product_id,
        "discord-notifier": args.discord_notifier_whop_product_id,
    }
    settings = Settings.from_env()
    database = Database(settings.database_path)
    apply_migrations(database)
    service = LicensingService(database)
    for product in seed_default_products(service, whop_ids):
        print(f"Seeded {product['slug']} -> {product['feature_id']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
