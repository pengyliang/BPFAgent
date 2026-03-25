#!/usr/bin/env bash
set -euo pipefail

sleep 0.2
CASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CASE_KEY="$(basename "$(dirname "${CASE_DIR}")")_$(basename "${CASE_DIR}")"
BIN="/tmp/ebpf_agent_open_loop_${CASE_KEY}"
SRC_DIR="$(cd "${CASE_DIR}"/../../_common && pwd)"
SRC="${SRC_DIR}/open_loop.c"
if [[ ! -x "${BIN}" ]]; then
  cc -O2 "${SRC}" -o "${BIN}"
fi
exec "${BIN}" /etc/hostname 3
