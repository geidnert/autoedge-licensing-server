#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/.." && pwd)"
fetch_remote=true
backup_tags=()
failures=0
warnings=0

for argument in "$@"; do
  case "${argument}" in
    --no-fetch) fetch_remote=false ;;
    --check-production-backup) backup_tags+=("autoedge-production") ;;
    --check-release-key-backup) backup_tags+=("autoedge-offline-release-key") ;;
    *)
      echo "Usage: $0 [--no-fetch] [--check-production-backup] [--check-release-key-backup]" >&2
      exit 2
      ;;
  esac
done

pass() {
  echo "PASS: $1"
}

fail() {
  echo "FAIL: $1" >&2
  failures=$((failures + 1))
}

warn() {
  echo "WARN: $1" >&2
  warnings=$((warnings + 1))
}

cd "${repo_root}"

required_files=(
  ".env.example"
  "AGENTS.md"
  "README.md"
  "deploy/autoedge-backup.env.example"
  "docs/codex/project-memory.md"
  "docs/disaster-recovery.md"
  "requirements.txt"
  "scripts/backup_production.sh"
  "scripts/backup_release_signing_key.sh"
  "scripts/backup_sqlite.py"
  "scripts/bootstrap_development.sh"
  "systemd/autoedge-backup.service"
  "systemd/autoedge-backup.timer"
  "systemd/autoedge-licensing.service"
)

for required_file in "${required_files[@]}"; do
  if git ls-files --error-unmatch "${required_file}" >/dev/null 2>&1; then
    pass "${required_file} is tracked"
  else
    fail "${required_file} is not tracked"
  fi
done

if git ls-files '.github/workflows/**' | grep -q .; then
  fail "GitHub Actions workflows are tracked; validation must remain local"
else
  pass "no GitHub Actions workflows are tracked"
fi

if git ls-files --error-unmatch .env >/dev/null 2>&1; then
  fail ".env is tracked and may expose secrets"
else
  pass ".env is not tracked"
fi

if git ls-files 'data/**' '*.db' '*.db-wal' '*.db-shm' | grep -q .; then
  fail "runtime database/data files are tracked"
else
  pass "runtime database/data files are not tracked"
fi

if [[ -n "$(git status --porcelain)" ]]; then
  fail "working tree has uncommitted files"
else
  pass "working tree is clean"
fi

if upstream="$(git rev-parse --abbrev-ref --symbolic-full-name '@{upstream}' 2>/dev/null)"; then
  if [[ "${fetch_remote}" == true ]]; then
    git fetch --quiet "${upstream%%/*}"
  fi
  read -r ahead behind < <(git rev-list --left-right --count "HEAD...${upstream}")
  if [[ "${ahead}" -eq 0 && "${behind}" -eq 0 ]]; then
    pass "HEAD matches ${upstream}"
  else
    fail "HEAD differs from ${upstream} (ahead ${ahead}, behind ${behind})"
  fi
else
  fail "current branch has no upstream"
fi

config_base="${XDG_CONFIG_HOME:-${HOME}/.config}"
default_private_key="${config_base}/autoedge/signing/release-2026-01-private.pem"
default_public_key="${config_base}/autoedge/signing/release-2026-01-public.pem"
expected_public_fingerprint="b7057a866d42ebe0e0e14ef108a2103ccca68540b29503ab16deedece8fdd87c"
if [[ -f "${default_private_key}" && -f "${default_public_key}" ]]; then
  if [[ -x .venv/bin/python ]]; then
    actual_public_fingerprint="$(
      AUTOEDGE_ES256_PUBLIC_KEY_PATH="${default_public_key}" \
        .venv/bin/python scripts/es256_keys.py fingerprint
    )"
    if [[ "${actual_public_fingerprint}" == "${expected_public_fingerprint}" ]]; then
      pass "offline release signing keypair exists and its public fingerprint matches"
    else
      fail "offline release public fingerprint does not match the expected key"
    fi
  else
    warn "offline release keypair exists, but .venv is unavailable for fingerprint verification"
  fi
else
  warn "offline release signing keypair is not present at ${config_base}/autoedge/signing"
fi

if [[ "${#backup_tags[@]}" -gt 0 ]]; then
  if ! command -v restic >/dev/null 2>&1; then
    fail "restic is unavailable, so off-host snapshots cannot be checked"
  elif [[ -z "${RESTIC_REPOSITORY:-}" || -z "${RESTIC_PASSWORD_FILE:-}" ]]; then
    fail "RESTIC_REPOSITORY and RESTIC_PASSWORD_FILE are required for backup checks"
  else
    for backup_tag in "${backup_tags[@]}"; do
      restic snapshots --tag "${backup_tag}"
      pass "${backup_tag} snapshots are reachable"
    done
  fi
else
  warn "off-host backup freshness was not checked; use a configured backup-check option"
fi

echo "Recovery readiness: ${failures} failure(s), ${warnings} warning(s)."
if [[ "${failures}" -ne 0 ]]; then
  exit 1
fi
