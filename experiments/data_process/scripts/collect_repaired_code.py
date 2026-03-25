#!/usr/bin/env python3
"""
Collect source code + all repaired eBPF codes into one folder per (case_id, llm_name).

Input:
  experiments/llm/<llm_name>/original_logs/<kernel_version>/log/agent_mode/<case_id>/repair/repair_*/**/*.bpf.c

Source code:
  data/<category>/<case_dir>/<case_dir>.bpf.c
  (fallback: first *.bpf.c in that directory)

Output:
  experiments/processed_data/repair_codes/<case_id>/<llm_name>/*.bpf.c

Note:
  - source and repair codes are placed in the same directory level
  - repair codes include kernel_version suffix in filename to avoid overwriting
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import sys
from pathlib import Path
from typing import Iterable, List, Optional, Tuple


def _repo_root_from_script() -> Path:
    # experiments/data_process/scripts/* -> repo root
    return Path(__file__).resolve().parents[3]


def _strip_bpf_c_ext(name: str) -> Tuple[str, str]:
    if name.endswith(".bpf.c"):
        return name[: -len(".bpf.c")], ".bpf.c"
    stem, ext = os.path.splitext(name)
    return stem, ext or ""


def _parse_repair_idx(dir_name: str) -> Optional[str]:
    m = re.match(r"repair_(\d+)$", dir_name.strip())
    return m.group(1) if m else None


def _pick_source_code(data_dir: Path, category: str, case_dir: str) -> Optional[Path]:
    src_dir = data_dir / category / case_dir
    if not src_dir.is_dir():
        return None
    direct = src_dir / f"{case_dir}.bpf.c"
    if direct.is_file():
        return direct
    candidates = sorted(src_dir.glob("*.bpf.c"))
    if not candidates:
        return None
    return candidates[0]


def _iter_case_dirs(agent_mode_root: Path) -> Iterable[Tuple[str, Path]]:
    """
    Yield (case_id, case_root_path) where case_id = <category>/<case_dir>.
    """
    if not agent_mode_root.is_dir():
        return
    for category_dir in sorted(agent_mode_root.iterdir(), key=lambda p: p.name):
        if not category_dir.is_dir():
            continue
        category = category_dir.name
        for case_root in sorted(category_dir.iterdir(), key=lambda p: p.name):
            if not case_root.is_dir():
                continue
            case_dir = case_root.name
            case_id = f"{category}/{case_dir}"
            yield case_id, case_root


def _safe_copy(src: Path, dst: Path) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)


def collect_for_case(
    *,
    case_id: str,
    llm_root: Path,
    data_dir: Path,
    output_root: Path,
    llm_name: Optional[str] = None,
    kernel_version: Optional[str] = None,
    dry_run: bool = False,
) -> Tuple[int, int]:
    """
    Return (copied_repairs, copied_workflows).
    """
    if "/" not in case_id:
        print(f"[WARN] invalid case_id={case_id} (expect category/case)", file=sys.stderr)
        return 0
    category, case_dir = case_id.split("/", 1)

    copied_repairs = 0
    copied_workflows = 0
    case_src = _pick_source_code(data_dir, category=category, case_dir=case_dir)
    if case_src is None:
        print(f"[WARN] source code not found for {case_id} under data/{category}/{case_dir}", file=sys.stderr)
        return 0

    if llm_name is None:
        llm_dirs = [
            p
            for p in llm_root.iterdir()
            if p.is_dir() and not p.name.startswith(".") and p.name not in {"repair_codes"}
        ]
    else:
        llm_dirs = [llm_root / llm_name]

    for each_llm_root in sorted(llm_dirs, key=lambda p: p.name):
        if not each_llm_root.is_dir():
            continue
        llm = each_llm_root.name

        out_dir = output_root / case_id / llm
        src_dst = out_dir / case_src.name  # keep original filename
        if not dry_run:
            _safe_copy(case_src, src_dst)
        else:
            print(f"[DRY] copy source {case_src} -> {src_dst}")

        original_logs_root = each_llm_root / "original_logs"
        if not original_logs_root.is_dir():
            continue

        kernel_dirs = sorted(
            (p for p in original_logs_root.iterdir() if p.is_dir()),
            key=lambda p: p.name,
        )
        for kd in kernel_dirs:
            ver = kd.name
            if kernel_version is not None and ver != kernel_version:
                continue
            agent_mode_root = kd / "log" / "agent_mode" / category / case_dir
            if not agent_mode_root.is_dir():
                continue

            repair_dir = agent_mode_root / "repair"
            if not repair_dir.is_dir():
                continue

            # Copy workflow/summary for this kernel into the same output dir level.
            workflow_src = agent_mode_root / "workflow.json"
            if not workflow_src.is_file():
                workflow_src = agent_mode_root / "workflow_summary.json"
            if workflow_src.is_file():
                dst_workflow = out_dir / f"workflow_k{ver}.json"
                if dry_run:
                    print(f"[DRY] copy workflow {workflow_src} -> {dst_workflow}")
                else:
                    _safe_copy(workflow_src, dst_workflow)
                copied_workflows += 1

            for bpf_c in sorted(repair_dir.rglob("*.bpf.c"), key=lambda p: str(p)):
                # Expect path: .../repair/repair_<n>/<file>.bpf.c
                if bpf_c.parent is None:
                    continue
                repair_parent = bpf_c.parent.name
                repair_idx = _parse_repair_idx(repair_parent) or repair_parent

                stem, ext = _strip_bpf_c_ext(bpf_c.name)
                out_name = f"{stem}_k{ver}{ext}" if ext else f"{stem}_k{ver}{bpf_c.suffix}"
                dst = out_dir / out_name
                if dry_run:
                    print(f"[DRY] copy repair {bpf_c} -> {dst}")
                else:
                    _safe_copy(bpf_c, dst)
                copied_repairs += 1

    return copied_repairs, copied_workflows


def main() -> None:
    repo_root = _repo_root_from_script()
    llm_root = repo_root / "experiments" / "llm"
    data_dir = repo_root / "data"
    output_root = repo_root / "experiments" / "processed_data" / "repair_codes"

    parser = argparse.ArgumentParser(description="Collect repaired codes into llm/repair_codes/")
    parser.add_argument("--case-id", type=str, default=None, help="Only collect one case_id: category/case_dir")
    parser.add_argument("--llm-name", type=str, default=None, help="Only collect one llm folder name")
    parser.add_argument("--kernel-version", type=str, default=None, help="Only collect one kernel version (e.g. 4.19)")
    parser.add_argument("--dry-run", action="store_true", help="Print actions without copying")
    args = parser.parse_args()

    case_ids: List[str] = []

    if args.case_id:
        case_ids = [args.case_id]
    else:
        # Discover all cases from original_logs: log/agent_mode/<category>/<case_dir>
        # across all llm and kernel versions.
        if not llm_root.is_dir():
            print(f"[ERR] missing llm root: {llm_root}", file=sys.stderr)
            sys.exit(1)
        llm_names = (
            [args.llm_name]
            if args.llm_name
            else [p.name for p in llm_root.iterdir() if p.is_dir() and p.name not in {"repair_codes"}]
        )
        for ln in llm_names:
            if not ln or ln.startswith("."):
                continue
            orig_root = llm_root / ln / "original_logs"
            if not orig_root.is_dir():
                continue
            for kd in orig_root.iterdir():
                if not kd.is_dir():
                    continue
                if args.kernel_version and kd.name != args.kernel_version:
                    continue
                agent_mode_root = kd / "log" / "agent_mode"
                for cid, _ in _iter_case_dirs(agent_mode_root):
                    if cid not in case_ids:
                        case_ids.append(cid)

    if not case_ids:
        print("[WARN] No case_id discovered. Nothing to do.", file=sys.stderr)
        sys.exit(1)

    total_repairs = 0
    total_workflows = 0
    for cid in sorted(case_ids):
        repairs, workflows = collect_for_case(
            case_id=cid,
            llm_root=llm_root,
            data_dir=data_dir,
            output_root=output_root,
            llm_name=args.llm_name,
            kernel_version=args.kernel_version,
            dry_run=args.dry_run,
        )
        total_repairs += repairs
        total_workflows += workflows

    print(
        f"Done. case_count={len(case_ids)}, total_repair_files_copied={total_repairs}, "
        f"total_workflows_copied={total_workflows}"
    )


if __name__ == "__main__":
    main()

