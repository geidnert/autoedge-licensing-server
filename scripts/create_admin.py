#!/usr/bin/env python3
from __future__ import annotations

import argparse
import getpass
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from autoedge_licensing.config import Settings
from autoedge_licensing.db import Database, apply_migrations
from autoedge_licensing.service import LicensingService


def main() -> int:
    parser = argparse.ArgumentParser(description="Create an AutoEdge licensing admin user.")
    parser.add_argument("username")
    parser.add_argument("--password", help="Use only for automation; otherwise an interactive prompt is safer.")
    args = parser.parse_args()

    password = args.password or getpass.getpass("Admin password: ")
    if len(password) < 12:
        raise SystemExit("Password must be at least 12 characters.")

    settings = Settings.from_env()
    database = Database(settings.database_path)
    apply_migrations(database)
    service = LicensingService(database)
    admin_id = service.create_admin_user(args.username, password)
    print(f"Created admin user {args.username} ({admin_id})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
