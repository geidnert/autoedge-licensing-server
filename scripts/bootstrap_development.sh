#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/.." && pwd)"
python_bin="${PYTHON_BIN:-python3}"
skip_install=false
skip_tests=false

for argument in "$@"; do
  case "${argument}" in
    --skip-install) skip_install=true ;;
    --skip-tests) skip_tests=true ;;
    *)
      echo "Usage: $0 [--skip-install] [--skip-tests]" >&2
      exit 2
      ;;
  esac
done

cd "${repo_root}"

"${python_bin}" -c '
import sys
if sys.version_info < (3, 11):
    raise SystemExit(f"Python 3.11+ is required; found {sys.version.split()[0]}")
print(f"Using Python {sys.version.split()[0]}")
'

if [[ ! -d .venv ]]; then
  "${python_bin}" -m venv .venv
fi

if [[ "${skip_install}" == false ]]; then
  .venv/bin/python -m pip install -r requirements.txt
fi

mkdir -p data/artifacts
if [[ ! -f .env ]]; then
  cp .env.example .env
  echo "Created ignored .env from .env.example; replace placeholders before a real local run."
fi

if [[ "${skip_tests}" == false ]]; then
  .venv/bin/python -m unittest discover -s tests
fi

echo "Development checkout is ready at ${repo_root}."
