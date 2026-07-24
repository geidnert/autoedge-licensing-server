#!/usr/bin/env python3
"""Create and verify a transactionally consistent online SQLite backup."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import tempfile
from urllib.parse import quote


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def backup_database(source: Path, destination: Path) -> dict[str, object]:
    source = source.resolve()
    destination = destination.resolve()
    if not source.is_file():
        raise FileNotFoundError(f"SQLite source does not exist: {source}")
    if source == destination:
        raise ValueError("SQLite source and destination must be different files.")

    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            prefix=f".{destination.name}.",
            suffix=".tmp",
            dir=destination.parent,
            delete=False,
        ) as temporary:
            temporary_path = Path(temporary.name)
        os.chmod(temporary_path, 0o600)

        source_uri = f"file:{quote(str(source), safe='/')}?mode=ro"
        with sqlite3.connect(source_uri, uri=True) as source_connection:
            with sqlite3.connect(temporary_path) as destination_connection:
                source_connection.backup(destination_connection)
                result = destination_connection.execute("PRAGMA quick_check").fetchone()
                quick_check = str(result[0]) if result else "missing result"
                if quick_check != "ok":
                    raise RuntimeError(f"Backup PRAGMA quick_check failed: {quick_check}")

        os.replace(temporary_path, destination)
        temporary_path = None
        os.chmod(destination, 0o600)
        return {
            "source": str(source),
            "destination": str(destination),
            "quick_check": "ok",
            "size_bytes": destination.stat().st_size,
            "sha256": sha256_file(destination),
        }
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="Live SQLite database path")
    parser.add_argument("destination", type=Path, help="Backup snapshot path")
    arguments = parser.parse_args()
    print(json.dumps(backup_database(arguments.source, arguments.destination), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
