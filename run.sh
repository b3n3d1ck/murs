#!/usr/bin/env bash
# MURS launcher for Linux / macOS / WSL / Kali / Ubuntu.
set -euo pipefail
cd "$(dirname "$0")"

PY="${PYTHON:-python3}"
if ! command -v "$PY" >/dev/null 2>&1; then
  echo "error: python3 not found. Install Python 3.10+." >&2
  exit 1
fi

if ! "$PY" -c "import reportlab" >/dev/null 2>&1; then
  echo "note: reportlab not installed — PDF output will be skipped." >&2
  echo "      install it with: $PY -m pip install -r requirements.txt" >&2
fi

if ! command -v php >/dev/null 2>&1; then
  echo "note: php CLI not found — the local lab (--lab) will be unavailable." >&2
fi

exec "$PY" -m murs "$@"
