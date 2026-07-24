from __future__ import annotations

import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
BACKUP_SCRIPT = REPOSITORY_ROOT / "scripts" / "backup_production.sh"


class BackupProductionTests(unittest.TestCase):
    def test_script_snapshots_database_and_runs_backup_retention_and_check(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            source = root / "live.db"
            snapshot_dir = root / "snapshots"
            password_file = root / "restic-password"
            fake_bin = root / "bin"
            fake_restic = fake_bin / "restic"
            restic_log = root / "restic.log"

            with sqlite3.connect(source) as connection:
                connection.execute("CREATE TABLE customers (id TEXT PRIMARY KEY)")
                connection.execute("INSERT INTO customers(id) VALUES ('customer-1')")
                connection.commit()
            password_file.write_text("test-only-password\n", encoding="utf-8")
            fake_bin.mkdir()
            fake_restic.write_text(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$FAKE_RESTIC_LOG\"\n",
                encoding="utf-8",
            )
            fake_restic.chmod(0o700)

            environment = os.environ.copy()
            environment.update(
                {
                    "PATH": f"{fake_bin}:{environment['PATH']}",
                    "FAKE_RESTIC_LOG": str(restic_log),
                    "RESTIC_REPOSITORY": "test:off-host-repository",
                    "RESTIC_PASSWORD_FILE": str(password_file),
                    "AUTOEDGE_BACKUP_DATABASE_PATH": str(source),
                    "AUTOEDGE_BACKUP_SNAPSHOT_DIR": str(snapshot_dir),
                    "AUTOEDGE_BACKUP_PYTHON": sys.executable,
                    "AUTOEDGE_BACKUP_KEEP_DAILY": "3",
                    "AUTOEDGE_BACKUP_KEEP_WEEKLY": "2",
                    "AUTOEDGE_BACKUP_KEEP_MONTHLY": "1",
                }
            )

            subprocess.run(
                [str(BACKUP_SCRIPT)],
                cwd=REPOSITORY_ROOT,
                env=environment,
                check=True,
                capture_output=True,
                text=True,
            )

            snapshot = snapshot_dir / "autoedge.db"
            with sqlite3.connect(snapshot) as connection:
                self.assertEqual("ok", connection.execute("PRAGMA quick_check").fetchone()[0])
                self.assertEqual(
                    "customer-1",
                    connection.execute("SELECT id FROM customers").fetchone()[0],
                )
            calls = restic_log.read_text(encoding="utf-8").splitlines()
            self.assertTrue(calls[0].startswith("backup --tag autoedge-production "))
            self.assertIn(str(snapshot), calls[0])
            self.assertEqual(
                "forget --tag autoedge-production --keep-daily 3 "
                "--keep-weekly 2 --keep-monthly 1 --prune",
                calls[1],
            )
            self.assertEqual("check", calls[2])
            self.assertEqual("snapshots --tag autoedge-production", calls[3])


if __name__ == "__main__":
    unittest.main()
