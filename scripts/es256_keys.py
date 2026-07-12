#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from autoedge_licensing.signing import load_private_key, load_public_key, public_key_fingerprint, public_key_pem


def required_path(name: str) -> Path:
    value = os.environ.get(name, "").strip()
    if not value:
        raise SystemExit(f"Set {name} to a protected filesystem path.")
    return Path(value)


def write_new(path: Path, contents: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(descriptor, "wb") as output:
        output.write(contents)


def generate() -> None:
    private_path = required_path("AUTOEDGE_ES256_PRIVATE_KEY_PATH")
    public_path = required_path("AUTOEDGE_ES256_PUBLIC_KEY_PATH")
    private_key = ec.generate_private_key(ec.SECP256R1())
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    write_new(private_path, private_pem, 0o600)
    try:
        write_new(public_path, public_key_pem(private_key.public_key()), 0o644)
    except Exception:
        private_path.unlink(missing_ok=True)
        raise
    print(f"Generated ES256 keypair; public-key SHA-256: {public_key_fingerprint(private_key.public_key())}")


def export_public() -> None:
    private_path = required_path("AUTOEDGE_ES256_PRIVATE_KEY_PATH")
    public_path = required_path("AUTOEDGE_ES256_PUBLIC_KEY_PATH")
    private_key = load_private_key(private_path)
    write_new(public_path, public_key_pem(private_key.public_key()), 0o644)
    print(f"Exported ES256 public key; SHA-256: {public_key_fingerprint(private_key.public_key())}")


def fingerprint() -> None:
    public_path = required_path("AUTOEDGE_ES256_PUBLIC_KEY_PATH")
    print(public_key_fingerprint(load_public_key(public_path)))


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate, export, or fingerprint ES256 keys without printing private PEM data.")
    parser.add_argument("action", choices=("generate", "export-public", "fingerprint"))
    action = parser.parse_args().action
    {"generate": generate, "export-public": export_public, "fingerprint": fingerprint}[action]()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
