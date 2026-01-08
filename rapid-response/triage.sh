#!/usr/bin/env bash
set -euo pipefail

OUTPUT_DIR="${1:-./evidence}"
IOC_FILE="${2:-}"

BIN="iron-sentinel"
if [[ -x "./iron-sentinel" ]]; then
  BIN="./iron-sentinel"
elif [[ -x "./core/cmd/iron-sentinel/iron-sentinel" ]]; then
  BIN="./core/cmd/iron-sentinel/iron-sentinel"
fi

ARGS=(triage --output "${OUTPUT_DIR}")
if [[ -n "${IOC_FILE}" ]]; then
  ARGS+=(--ioc-file "${IOC_FILE}")
fi

"${BIN}" "${ARGS[@]}"
