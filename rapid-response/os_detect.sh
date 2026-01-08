#!/usr/bin/env bash
set -euo pipefail

if [[ -r /etc/os-release ]]; then
  # shellcheck disable=SC1091
  source /etc/os-release
  echo "id=${ID:-unknown}"
  echo "version_id=${VERSION_ID:-unknown}"
  echo "name=${NAME:-unknown}"
  exit 0
fi

echo "id=unknown"
echo "version_id=unknown"
echo "name=unknown"
