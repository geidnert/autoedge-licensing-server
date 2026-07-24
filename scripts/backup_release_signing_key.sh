#!/usr/bin/env bash
set -euo pipefail
umask 077

if [[ "$#" -ne 2 ]]; then
  echo "Usage: $0 PRIVATE_PEM PUBLIC_PEM" >&2
  exit 2
fi

private_key_path="$1"
public_key_path="$2"

if [[ ! -f "${private_key_path}" || ! -f "${public_key_path}" ]]; then
  echo "Both the release private and public PEM files must exist." >&2
  exit 1
fi

if ! command -v restic >/dev/null 2>&1; then
  echo "restic is required. On macOS with Homebrew: brew install restic" >&2
  exit 1
fi

: "${RESTIC_REPOSITORY:?Set RESTIC_REPOSITORY to the off-host key-backup repository}"
: "${RESTIC_PASSWORD_FILE:?Set RESTIC_PASSWORD_FILE to its recovery password file}"

restic backup \
  --tag autoedge-offline-release-key \
  "${private_key_path}" \
  "${public_key_path}"
restic check
restic snapshots --tag autoedge-offline-release-key
