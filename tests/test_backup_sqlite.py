from __future__ import annotations

import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
BACKUP_SCRIPT = REPOSITORY_ROOT / "scripts" / "backup_sqlite.py"


class BackupSqliteTests(unittest.TestCase):
    def test_online_backup_is_consistent_and_verified(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            source = root / "live.db"
            destination = root / "backup" / "autoedge.db"
            with sqlite3.connect(source) as connection:
                connection.execute("PRAGMA journal_mode=WAL")
                connection.execute("CREATE TABLE events (id INTEGER PRIMARY KEY, value TEXT)")
                connection.executemany(
                    "INSERT INTO events(value) VALUES (?)",
                    [("first",), ("second",), ("third",)],
                )
                connection.commit()

            result = subprocess.run(
                [sys.executable, str(BACKUP_SCRIPT), str(source), str(destination)],
                check=True,
                capture_output=True,
                text=True,
            )

            report = json.loads(result.stdout)
            self.assertEqual("ok", report["quick_check"])
            self.assertEqual(64, len(report["sha256"]))
            self.assertEqual(0o600, destination.stat().st_mode & 0o777)
            with sqlite3.connect(destination) as connection:
                self.assertEqual("ok", connection.execute("PRAGMA quick_check").fetchone()[0])
                self.assertEqual(3, connection.execute("SELECT COUNT(*) FROM events").fetchone()[0])

    def test_failed_backup_does_not_replace_existing_destination(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            source = root / "broken.db"
            destination = root / "existing.db"
            source.write_text("not a sqlite database", encoding="utf-8")
            destination.write_bytes(b"known-good-placeholder")

            result = subprocess.run(
                [sys.executable, str(BACKUP_SCRIPT), str(source), str(destination)],
                check=False,
                capture_output=True,
                text=True,
            )

            self.assertNotEqual(0, result.returncode)
            self.assertEqual(b"known-good-placeholder", destination.read_bytes())


if __name__ == "__main__":
    unittest.main()
