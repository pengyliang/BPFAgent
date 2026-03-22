"""Build per-source summaries for static check: try clang AST first, else source-only."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Union


PathLike = Union[str, Path]


def build_static_check_summaries(
    source_files: Sequence[PathLike],
    *,
    artifact_dir: PathLike,
    vmlinux_header_dir: Optional[str] = None,
    bpftool_bin: str = "bpftool",
    kernel_btf_path: str = "/sys/kernel/btf/vmlinux",
) -> List[Dict[str, Any]]:
    """
    For each .bpf.c, run `parse_ebpf_source` (clang JSON AST). On clang/JSON failure,
    the parser returns `ast_fallback=True` with empty helper lists so `static_checker`
    uses regex-based source analysis.
    """
    from scripts.setup.ast_parser import parse_ebpf_source

    base = Path(artifact_dir)
    base.mkdir(parents=True, exist_ok=True)
    summaries: List[Dict[str, Any]] = []
    for sf in source_files:
        src = Path(sf)
        stem = src.stem
        try:
            summary = parse_ebpf_source(
                str(src),
                output_path=str(base / f"{stem}.ast_summary.json"),
                log_path=str(base / f"{stem}.ast_parser.log"),
                vmlinux_header_dir=vmlinux_header_dir,
                bpftool_bin=bpftool_bin,
                kernel_btf_path=kernel_btf_path,
            )
        except Exception:
            summaries.append(
                {
                    "source_file": str(src),
                    "ast_fallback": True,
                    "ast_fallback_reason": "parse_exception",
                    "bpf_helper_calls": [],
                    "struct_field_access_paths": [],
                    "map_operation_sequence": [],
                }
            )
            continue
        summaries.append(summary)
    return summaries
