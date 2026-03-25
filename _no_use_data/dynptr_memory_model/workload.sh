#!/usr/bin/env bash
set -euo pipefail

sleep 0.2
BIN="/tmp/ebpf_agent_write_loop"
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")"/../../_common && pwd)"
SRC="${SRC_DIR}/write_loop.c"
if [[ ! -x "${BIN}" ]]; then
  cc -O2 "${SRC}" -o "${BIN}"
fi
exec "${BIN}" /tmp/ebpf_dynptr_test.txt 1
