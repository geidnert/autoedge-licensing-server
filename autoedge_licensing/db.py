from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Iterable


class Database:
    def __init__(self, path: str):
        self.path = Path(path)

    def connect(self) -> sqlite3.Connection:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = WAL")
        return connection


def migration_dir() -> Path:
    return Path(__file__).resolve().parent.parent / "migrations"


def apply_migrations(database: Database, migrations: Iterable[Path] | None = None) -> None:
    with database.connect() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS schema_migrations (
                name TEXT PRIMARY KEY,
                applied_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
            )
            """
        )
        applied = {
            row["name"]
            for row in connection.execute("SELECT name FROM schema_migrations").fetchall()
        }
        migration_files = list(migrations) if migrations is not None else sorted(migration_dir().glob("*.sql"))
        for migration in migration_files:
            if migration.name in applied:
                continue
            connection.executescript(migration.read_text(encoding="utf-8"))
            connection.execute("INSERT INTO schema_migrations(name) VALUES (?)", (migration.name,))
