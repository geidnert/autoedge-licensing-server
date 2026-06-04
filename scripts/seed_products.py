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
    ("duo-runtime", "DUO Runtime", "strategy.duo.runtime"),
    ("duorc-runtime", "DUOrc Runtime", "strategy.duorc.runtime"),
    ("orbo2-runtime", "ORBO2 Runtime", "strategy.orbo2.runtime"),
    ("orboib-runtime", "ORBOib Runtime", "strategy.orboib.runtime"),
    ("adam-runtime", "ADAM Runtime", "strategy.adam.runtime"),
    ("eve-runtime", "EVE Runtime", "strategy.eve.runtime"),
    ("mich-runtime", "MICH Runtime", "strategy.mich.runtime"),
    ("hugo-runtime", "HUGO Runtime", "strategy.hugo.runtime"),
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
    }
    settings = Settings.from_env()
    database = Database(settings.database_path)
    apply_migrations(database)
    service = LicensingService(database)
    for slug, name, feature_id in DEFAULT_PRODUCTS:
        product = service.upsert_product(
            slug=slug,
            name=name,
            feature_id=feature_id,
            whop_product_id=whop_ids.get(slug),
            metadata={"seeded": True},
        )
        print(f"Seeded {product['slug']} -> {product['feature_id']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
