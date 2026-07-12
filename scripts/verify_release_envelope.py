#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from autoedge_licensing.config import Settings
from autoedge_licensing.signing import load_public_key_mapping, verify_release_envelope


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify an AutoEdge signed release envelope.")
    parser.add_argument("token_file", help="File containing one compact release token.")
    args = parser.parse_args()
    keys = load_public_key_mapping(Settings.from_env().release_verification_key_paths)
    if not keys:
        raise SystemExit("Set AUTOEDGE_RELEASE_VERIFICATION_KEYS to a JSON key-ID/path mapping.")
    token = Path(args.token_file).read_text(encoding="ascii").strip()
    verified = verify_release_envelope(token, keys)
    print(json.dumps({"header": verified.header, "payload": verified.payload}, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
