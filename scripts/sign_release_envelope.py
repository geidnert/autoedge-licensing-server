#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from autoedge_licensing.signing import (
    RELEASE_TOKEN_TYPE,
    CompactES256Signer,
    release_envelope_payload,
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Sign an AutoEdge release-envelope JSON file with ES256.")
    parser.add_argument("envelope", help="Path to the release-envelope JSON file.")
    parser.add_argument("--output", help="Optional token output file; defaults to stdout.")
    args = parser.parse_args()
    private_key_path = os.environ.get("AUTOEDGE_RELEASE_SIGNING_PRIVATE_KEY_PATH", "").strip()
    key_id = os.environ.get("AUTOEDGE_RELEASE_SIGNING_KEY_ID", "").strip()
    if not private_key_path or not key_id:
        raise SystemExit(
            "Set AUTOEDGE_RELEASE_SIGNING_PRIVATE_KEY_PATH and AUTOEDGE_RELEASE_SIGNING_KEY_ID on the release workstation."
        )
    source = json.loads(Path(args.envelope).read_text(encoding="utf-8"))
    if not isinstance(source, dict):
        raise SystemExit("Release envelope must be a JSON object.")
    payload = release_envelope_payload(
        release_type=source.get("release_type"),
        package_id=source.get("package_id"),
        feature_id=source.get("feature_id"),
        channel=source.get("channel"),
        platform=source.get("platform"),
        version=source.get("version"),
        minimum_trader_version=source.get("minimum_trader_version"),
        filename=source.get("filename"),
        size_bytes=source.get("size_bytes"),
        sha256=source.get("sha256"),
    )
    if source != payload:
        raise SystemExit("Release envelope fields must exactly match the documented v1 contract.")
    token = CompactES256Signer.from_pem_path(private_key_path, key_id).sign(payload, token_type=RELEASE_TOKEN_TYPE)
    if args.output:
        Path(args.output).write_text(token + "\n", encoding="ascii")
    else:
        print(token)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
