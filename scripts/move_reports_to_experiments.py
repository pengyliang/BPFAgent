#!/usr/bin/env python3
"""
Move output/<version>/reports into experiments/<target>/<version>/reports.

It supports both source layouts:
  - output/<version>/reports
  - output/<version>/log/reports

Usage examples:
  python3 scripts/move_reports_to_experiments.py \
    --target "experiments/不同LLM对比/deepseek-v3.2" \
    --dry-run

  python3 scripts/move_reports_to_experiments.py \
    --target "experiments/不同LLM对比/deepseek-v3.2" \
    --versions 5.4 5.15 \
    --overwrite
"""

from __future__ import annotations

import argparse
import re
import shutil
from pathlib import Path


VERSION_RE = re.compile(r"^\d+\.\d+")


def _iter_versions(output_root: Path, *, versions: list[str] | None) -> list[str]:
    if versions:
        return versions
    out: list[str] = []
    if not output_root.exists():
        return out
    for child in sorted(output_root.iterdir(), key=lambda p: p.name):
        if child.is_dir() and VERSION_RE.match(child.name):
            out.append(child.name)
    return out


def _find_reports_dir(version_dir: Path) -> Path | None:
    # Prefer layout requested by user, but keep compatibility with current repo layout.
    cand1 = version_dir / "reports"
    cand2 = version_dir / "log" / "reports"
    if cand1.exists() and cand1.is_dir():
        return cand1
    if cand2.exists() and cand2.is_dir():
        return cand2
    return None


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--target",
        required=True,
        help="experiments 内的目标文件夹（例如: experiments/不同LLM对比/deepseek-v3.2）",
    )
    parser.add_argument(
        "--versions",
        nargs="*",
        default=None,
        help="可选：只处理指定版本，如 --versions 5.4 5.15；默认处理所有 output/<version>。",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="若目标目录已存在对应版本，则先删除再移动（有破坏性）。默认：跳过已存在的版本目录。",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="只打印将要执行的操作，不实际移动。",
    )
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parents[1]
    output_root = repo_root / "output"
    experiments_root = repo_root / Path(args.target)
    experiments_root.parent.mkdir(parents=True, exist_ok=True)
    experiments_root.mkdir(parents=True, exist_ok=True)

    versions = _iter_versions(output_root, versions=args.versions)
    if not versions:
        print("No versions found under output/. Nothing to do.")
        return

    moved = 0
    skipped = 0
    missing = 0

    for ver in versions:
        ver_dir = output_root / ver
        reports_src = _find_reports_dir(ver_dir)
        if not reports_src:
            print(f"[MISSING] {ver}: reports dir not found under {ver_dir}")
            missing += 1
            continue

        reports_dst = experiments_root / ver / "reports"
        # Note: we move the whole reports directory.
        if reports_dst.exists():
            if not args.overwrite:
                print(f"[SKIP] {ver}: dst exists -> {reports_dst}")
                skipped += 1
                continue
            print(f"[OVERWRITE] {ver}: removing dst -> {reports_dst}")
            if not args.dry_run:
                shutil.rmtree(str(reports_dst), ignore_errors=True)

        print(f"[MOVE] {ver}: {reports_src} -> {reports_dst}")
        if not args.dry_run:
            reports_dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(reports_src), str(reports_dst))
        moved += 1

    print(f"Done. moved={moved}, skipped={skipped}, missing={missing}, target={experiments_root}")


if __name__ == "__main__":
    main()

