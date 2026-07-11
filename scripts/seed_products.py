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
    {"slug": "duo-runtime", "name": "DUO Runtime", "feature_id": "strategy.duo.runtime"},
    {"slug": "duorc-runtime", "name": "DUOrc Runtime", "feature_id": "strategy.duorc.runtime"},
    {"slug": "orbo2-runtime", "name": "ORBO2 Runtime", "feature_id": "strategy.orbo2.runtime"},
    {"slug": "orboib-runtime", "name": "ORBOib Runtime", "feature_id": "strategy.orboib.runtime"},
    {"slug": "adam-runtime", "name": "ADAM Runtime", "feature_id": "strategy.adam.runtime"},
    {"slug": "eve-runtime", "name": "EVE Runtime", "feature_id": "strategy.eve.runtime"},
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
        "slug": "discord-notifier",
        "name": "Discord Notifier",
        "feature_id": "trader.notifications.discord",
        "nt8_enabled": False,
        "metadata": {"seeded": True, "package_kind": "extension", "release_type": "extension_package"},
    },
]


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
    parser.add_argument("--discord-notifier-whop-product-id")
    args = parser.parse_args()

    whop_ids = {
        "duo-runtime": args.duo_whop_product_id,
        "duorc-runtime": args.duorc_whop_product_id,
        "orbo2-runtime": args.orbo2_whop_product_id,
        "orboib-runtime": args.orboib_whop_product_id,
        "adam-runtime": args.adam_whop_product_id,
        "eve-runtime": args.eve_whop_product_id,
        "mich-runtime": args.mich_whop_product_id,
        "hugo-runtime": args.hugo_whop_product_id,
        "discord-notifier": args.discord_notifier_whop_product_id,
    }
    settings = Settings.from_env()
    database = Database(settings.database_path)
    apply_migrations(database)
    service = LicensingService(database)
    for definition in DEFAULT_PRODUCTS:
        slug = definition["slug"]
        product = service.upsert_product(
            slug=slug,
            name=definition["name"],
            feature_id=definition["feature_id"],
            whop_product_id=whop_ids.get(slug),
            trader_enabled=definition.get("trader_enabled", True),
            nt8_enabled=definition.get("nt8_enabled", True),
            metadata=definition.get("metadata", {"seeded": True, "package_kind": "strategy"}),
        )
        print(f"Seeded {product['slug']} -> {product['feature_id']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
