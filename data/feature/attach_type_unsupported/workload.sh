#!/usr/bin/env bash
set -euo pipefail

sleep 0.2 # allow runtime_tester to write cfg[tgid]

BIN="/tmp/ebpf_agent_openat2_loop"
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="${SRC_DIR}/openat2_loop.c"

if [[ ! -x "${BIN}" ]]; then
  cc -O2 "${SRC}" -o "${BIN}"
fi

exec "${BIN}" /etc/hostname 3
