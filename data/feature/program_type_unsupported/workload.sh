#!/usr/bin/env bash
set -euo pipefail

exec python3 - <<'PY'
import time
time.sleep(0.2)  # allow runtime_tester to write cfg[tgid]
for _ in range(3):
    time.sleep(0.001)
PY
