#!/usr/bin/env python3
"""
Aggregate all LLM versions' case_summary.csv into one file.

Input pattern:
  experiments/llm/<llm_name>/<kernel_version>/reports/case_summary.csv

Output:
  experiments/processed_data/llm_case_summary.csv

Extra columns added:
  - llm_name
  - kernel_version
"""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple


def _repo_root_from_script() -> Path:
    # experiments/data_process/scripts/* -> repo root
    return Path(__file__).resolve().parents[3]


def _version_sort_key(v: str) -> Tuple:
    parts: List = []
    for p in str(v).replace("_", ".").split("."):
        if p.isdigit():
            parts.append(int(p))
        else:
            parts.append(p)
    return tuple(parts)


def _discover_case_summary_csvs(llm_root: Path) -> List[Tuple[str, str, Path]]:
    out: List[Tuple[str, str, Path]] = []
    if not llm_root.is_dir():
        return out

    for llm_dir in sorted(llm_root.iterdir(), key=lambda p: p.name):
        if not llm_dir.is_dir():
            continue
        llm_name = llm_dir.name
        if llm_name.startswith(".") or llm_name in {"original_logs", "__pycache__"}:
            continue

        for ver_dir in llm_dir.iterdir():
            if not ver_dir.is_dir():
                continue
            kernel_version = ver_dir.name
            if kernel_version in {"original_logs", "__pycache__"}:
                continue

            csv_path = ver_dir / "reports" / "case_summary.csv"
            if csv_path.is_file():
                out.append((llm_name, kernel_version, csv_path))
    out.sort(key=lambda t: (t[0], _version_sort_key(t[1])))
    return out


def _read_csv_rows(path: Path) -> Tuple[List[str], List[Dict[str, str]]]:
    with path.open("r", encoding="utf-8", errors="replace", newline="") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames:
            raise ValueError(f"Missing header: {path}")
        rows = list(reader)
        return list(reader.fieldnames), rows


def _write_merged_csv(
    output_path: Path, fieldnames: List[str], rows: Iterable[Dict[str, str]]
) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def main() -> None:
    default_llm_root = _repo_root_from_script() / "experiments" / "llm"
    default_processed_dir = _repo_root_from_script() / "experiments" / "processed_data"
    parser = argparse.ArgumentParser(description="Aggregate LLM case_summary.csv files.")
    parser.add_argument("--llm-root", type=Path, default=default_llm_root, help="experiments/llm root")
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=default_processed_dir / "llm_case_summary.csv",
        help="output csv file path",
    )
    args = parser.parse_args()

    csvs = _discover_case_summary_csvs(args.llm_root.resolve())
    if not csvs:
        print(f"No case_summary.csv found under {args.llm_root}", file=sys.stderr)
        sys.exit(1)

    base_header: Optional[List[str]] = None
    merged_rows: List[Dict[str, str]] = []
    # Put these two cols at the very beginning to make it easy to group/filter.
    added_cols = ["llm_name", "kernel_version"]

    for llm_name, kernel_version, csv_path in csvs:
        header, rows = _read_csv_rows(csv_path)
        if base_header is None:
            base_header = header
        else:
            # Ensure headers are compatible. We don't require exact equality, but we keep a consistent output header.
            if header != base_header:
                # If there are differences, align by keys (missing fields will be left blank).
                # This keeps the script robust to accidental column changes.
                pass

        for r in rows:
            rr: Dict[str, str] = dict(r or {})
            rr["llm_name"] = llm_name
            rr["kernel_version"] = kernel_version
            merged_rows.append(rr)

    assert base_header is not None
    out_fieldnames = list(added_cols) + list(base_header)
    _write_merged_csv(args.output.resolve(), out_fieldnames, merged_rows)
    print(f"Wrote {args.output} ({len(merged_rows)} rows, {len(csvs)} source csvs)")


if __name__ == "__main__":
    main()

