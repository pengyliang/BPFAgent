from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, cast

from src.util.deploy.compile import compile_bpf_program, maybe_inject_task_tgid_offset
from src.util.stages.types import ToolContext, ToolResult


def _split_lines(text: Any, *, max_lines: int = 2000) -> List[str]:
    s = str(text or "")
    lines = s.splitlines()
    if len(lines) > max_lines:
        return lines[:max_lines] + ["...<truncated>"]
    return lines


@dataclass
class CompilerTool:
    """Compile eBPF C source into .bpf.o and emit compile_result payload."""

    def run(
        self,
        *,
        source_file: str,
        object_file: Optional[str] = None,
        vmlinux_header_dir: Optional[str] = None,
        extra_cflags: Optional[List[str]] = None,
        compile_timeout: int = 60,
        clang_bin: str = "clang",
        bpftool_bin: str = "bpftool",
        ctx: Optional[ToolContext] = None,
    ) -> ToolResult:
        injected = maybe_inject_task_tgid_offset(extra_cflags, source_file=source_file, bpftool_bin=bpftool_bin)
        report = compile_bpf_program(
            source_file=source_file,
            object_file=object_file,
            clang_bin=clang_bin,
            timeout=compile_timeout,
            vmlinux_header_dir=vmlinux_header_dir,
            extra_cflags=injected,
            bpftool_bin=bpftool_bin,
        )
        if isinstance(report, dict):
            report.setdefault("stdout_lines", _split_lines(report.get("stdout")))
            report.setdefault("stderr_lines", _split_lines(report.get("stderr")))
        ok = bool(report.get("success"))
        return ToolResult(
            success=ok,
            stage="compile",
            payload=cast(Dict[str, Any], report),
            error_kind="target_error" if not ok else None,
            error_message=None if ok else "compile_failed",
        )

