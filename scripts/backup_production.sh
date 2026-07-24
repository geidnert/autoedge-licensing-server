#!/usr/bin/env bash
set -euo pipefail
umask 077

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/.." && pwd)"

if ! command -v restic >/dev/null 2>&1; then
  echo "restic is required. On Debian: apt install restic" >&2
  exit 1
fi

: "${RESTIC_REPOSITORY:?Set RESTIC_REPOSITORY in /etc/autoedge-backup.env}"
: "${RESTIC_PASSWORD_FILE:?Set RESTIC_PASSWORD_FILE in /etc/autoedge-backup.env}"

if [[ ! -r "${RESTIC_PASSWORD_FILE}" ]]; then
  echo "Restic password file is not readable: ${RESTIC_PASSWORD_FILE}" >&2
  exit 1
fi

database_path="${AUTOEDGE_BACKUP_DATABASE_PATH:-/var/lib/autoedge-licensing/autoedge.db}"
snapshot_dir="${AUTOEDGE_BACKUP_SNAPSHOT_DIR:-/var/backups/autoedge-licensing/current}"
snapshot_path="${snapshot_dir}/autoedge.db"
keep_daily="${AUTOEDGE_BACKUP_KEEP_DAILY:-7}"
keep_weekly="${AUTOEDGE_BACKUP_KEEP_WEEKLY:-5}"
keep_monthly="${AUTOEDGE_BACKUP_KEEP_MONTHLY:-12}"
python_bin="${AUTOEDGE_BACKUP_PYTHON:-${repo_root}/.venv/bin/python}"

for retention_value in "${keep_daily}" "${keep_weekly}" "${keep_monthly}"; do
  if [[ ! "${retention_value}" =~ ^[0-9]+$ ]]; then
    echo "Backup retention values must be non-negative integers." >&2
    exit 1
  fi
done

if [[ ! -x "${python_bin}" ]]; then
  python_bin="$(command -v python3)"
fi

install -d -m 0700 "${snapshot_dir}"
if [[ -n "${RESTIC_CACHE_DIR:-}" ]]; then
  install -d -m 0700 "${RESTIC_CACHE_DIR}"
fi

"${python_bin}" "${repo_root}/scripts/backup_sqlite.py" \
  "${database_path}" "${snapshot_path}"

backup_paths=("${snapshot_path}")
candidate_paths=(
  "/var/lib/autoedge-licensing/artifacts"
  "/etc/autoedge-licensing.env"
  "/etc/autoedge-licensing"
  "/etc/systemd/system/autoedge-licensing.service"
  "/etc/systemd/system/autoedge-backup.service"
  "/etc/systemd/system/autoedge-backup.timer"
  "/etc/nginx/snippets/autoedge-licensing.conf"
  "/etc/nginx/sites-available"
  "/opt/autoedge-licensing"
)

for candidate_path in "${candidate_paths[@]}"; do
  if [[ -e "${candidate_path}" ]]; then
    backup_paths+=("${candidate_path}")
  fi
done

restic backup \
  --tag autoedge-production \
  --exclude "/opt/autoedge-licensing/.venv" \
  --exclude "/opt/autoedge-licensing/.git" \
  --exclude "**/__pycache__" \
  "${backup_paths[@]}"

restic forget \
  --tag autoedge-production \
  --keep-daily "${keep_daily}" \
  --keep-weekly "${keep_weekly}" \
  --keep-monthly "${keep_monthly}" \
  --prune

restic check
restic snapshots --tag autoedge-production
