#!/usr/bin/env python3
from __future__ import annotations

import hmac
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from autoedge_licensing.config import Settings
from autoedge_licensing.db import Database
from autoedge_licensing.service import TRADER_DESKTOP_PRODUCT_ID, file_sha256, release_type_from_scope
from autoedge_licensing.signing import (
    SigningError,
    load_public_key_mapping,
    release_envelope_payload,
    verify_release_envelope,
)


def main() -> int:
    settings = Settings.from_env()
    database = Database(settings.database_path)
    keys = load_public_key_mapping(settings.release_verification_key_paths)
    with database.session() as connection:
        rows = connection.execute(
            """
            SELECT trader_releases.*, products.slug AS product_slug, products.feature_id AS feature_id
            FROM trader_releases
            LEFT JOIN products ON products.id = trader_releases.product_id
            WHERE trader_releases.is_active = 1
              AND COALESCE(trader_releases.is_published, trader_releases.is_active) = 1
            ORDER BY trader_releases.id
            """
        ).fetchall()
    failures = 0
    artifact_root = Path(settings.release_artifact_dir).resolve()
    for row in rows:
        problems: list[str] = []
        artifact = (artifact_root / row["artifact_path"]).resolve()
        if not artifact.is_relative_to(artifact_root) or not artifact.is_file():
            problems.append("artifact missing or outside artifact root")
        else:
            actual_size = artifact.stat().st_size
            actual_sha = file_sha256(artifact)
            if row["size_bytes"] != actual_size:
                problems.append("size mismatch")
            if not row["sha256"] or not hmac.compare_digest(str(row["sha256"]).lower(), actual_sha):
                problems.append("SHA-256 mismatch")
            if row["signature"]:
                try:
                    expected = release_envelope_payload(
                        release_type=row["release_type"] or release_type_from_scope(row["scope"]),
                        package_id=row["product_key"] or row["product_slug"] or TRADER_DESKTOP_PRODUCT_ID,
                        feature_id=row["feature_id"],
                        channel=row["channel"],
                        platform=row["platform"],
                        version=row["version"],
                        minimum_trader_version=row["min_supported_version"],
                        filename=row["artifact_filename"],
                        size_bytes=row["size_bytes"],
                        sha256=row["sha256"],
                    )
                    verified = verify_release_envelope(row["signature"], keys, expected)
                    if not row["signature_key_id"] or not hmac.compare_digest(
                        verified.header["kid"], row["signature_key_id"]
                    ):
                        problems.append("signature key ID mismatch")
                except (SigningError, TypeError) as exc:
                    problems.append(f"invalid signature: {exc}")
            elif settings.require_release_signatures:
                problems.append("signature required but absent")
        if problems:
            failures += 1
            print(f"FAIL {row['id']} {row['artifact_path']}: {'; '.join(problems)}")
        else:
            signature_status = "signed" if row["signature"] else "unsigned-transition"
            print(f"OK   {row['id']} {row['artifact_path']} ({signature_status})")
    print(f"Audited {len(rows)} active releases; failures={failures}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
