#!/usr/bin/env python3
"""
Collect agent_mode_report.json from multiple kernel output dirs.

Copies:
  output/<kernel_version>/log/agent_mode_report.json

Into:
  <out_dir>/agent_mode_report_<kernel_version>.json

Example:
  python3 scripts/collect_agent_mode_reports.py \
    --out-dir experiments/不同LLM对比/deepseek \
    --versions 4.19 5.4 5.19 6.6
"""

from __future__ import annotations

import argparse
import shutil
from pathlib import Path


DEFAULT_VERSIONS = ["4.19", "5.4", "5.19", "6.6"]


def _normalize_version(v: str) -> str:
    # Be tolerant for inputs like "5,19"
    v = v.strip().replace(",", ".")
    return v


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out-dir", required=True, help="Destination folder")
    parser.add_argument(
        "--versions",
        nargs="*",
        default=DEFAULT_VERSIONS,
        help="Kernel versions to collect (e.g. 4.19 5.4 5.19 6.6). Also accepts commas.",
    )
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parents[1]
    out_dir = Path(args.out_dir).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    versions = [_normalize_version(v) for v in args.versions]

    ok = 0
    missing: list[str] = []

    for ver in versions:
        src = repo_root / "output" / ver / "log" / "agent_mode_report.json"
        dst = out_dir / f"agent_mode_report_{ver}.json"

        if not src.exists():
            missing.append(str(src))
            continue

        shutil.copy2(str(src), str(dst))
        ok += 1
        print(f"[OK] {src} -> {dst}")

    if missing:
        print(f"[WARN] Missing {len(missing)} files:")
        for m in missing:
            print(" -", m)

    print(f"Done. Copied {ok}/{len(versions)} files into: {out_dir}")


if __name__ == "__main__":
    main()

