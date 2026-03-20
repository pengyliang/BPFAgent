from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Literal, Optional, cast

from src.util.deploy.attach import attach_bpf_program, infer_attach_plan
from src.util.deploy.load import (
    extract_phase_json,
    load_bpf_program_bpftool,
    load_bpf_program_with_libbpf_loader,
    safe_remove_tree,
    start_libbpf_loader_daemon,
)
from src.util.stages.types import ToolContext, ToolResult


LoadBackend = Literal["libbpf_daemon", "libbpf_once", "bpftool"]

def _split_lines(text: Any, *, max_lines: int = 4000) -> list[str]:
    s = str(text or "")
    lines = s.splitlines()
    if len(lines) > max_lines:
        return lines[:max_lines] + ["...<truncated>"]
    return lines

def _daemon_attach_error(stderr: Any) -> Optional[str]:
    s = str(stderr or "").strip()
    if not s:
        return None
    low = s.lower()
    # Loader daemon does load+attach in one process; when attach fails,
    # stderr typically includes "attach failed".
    if "attach failed" in low or "no attachable program found" in low:
        return s
    return None


@dataclass
class LoadAttacherTool:
    """Load and attach a compiled .bpf.o using selected backend."""

    def run(
        self,
        *,
        source_file: str,
        object_file: str,
        pin_path: str,
        program_type: Optional[str] = None,
        backend: LoadBackend = "libbpf_daemon",
        bpftool_bin: str = "bpftool",
        load_timeout: int = 60,
        ctx: Optional[ToolContext] = None,
    ) -> ToolResult:
        attach_plan = infer_attach_plan(source_file=source_file, program_type=program_type)

        proc = None
        if backend == "libbpf_daemon":
            safe_remove_tree(str(pin_path) + "_maps")
            load_result = start_libbpf_loader_daemon(
                object_file=object_file,
                pin_path=pin_path,
                timeout=min(10, max(1, int(load_timeout))),
            )
            proc = load_result.get("_process")
            load_report = dict(load_result or {})
            load_report.pop("_process", None)

            phases = load_report.get("phase_details")
            if not isinstance(phases, dict):
                phases = extract_phase_json(load_report.get("stdout"))
            load_phase = phases.get("load") if isinstance(phases.get("load"), dict) else None
            attach_phase = phases.get("attach") if isinstance(phases.get("attach"), dict) else None
            load_ok = bool(load_result.get("load_success")) or bool(load_result.get("success"))
            attach_ok = bool(load_result.get("attach_success")) or bool(load_result.get("success"))

            # Prefer structured phase logs if available.
            if load_phase:
                load_report["stdout"] = load_phase.get("stdout") or ""
                load_report["stderr"] = load_phase.get("stderr") or ""
                if load_phase.get("error_message"):
                    load_report["error_message"] = load_phase.get("error_message")
            load_report["success"] = load_ok
            load_report["stage"] = "load"
            load_report["phase_details"] = phases
            if load_ok:
                load_report["error_message"] = ""
            if isinstance(load_report, dict):
                load_report.setdefault("stdout_lines", _split_lines(load_report.get("stdout")))
                load_report.setdefault("stderr_lines", _split_lines(load_report.get("stderr")))
            # Attach error message may still appear in daemon stderr; prefer attach phase.
            attach_err = None
            if attach_phase and not bool(attach_phase.get("ok")):
                attach_err = str(attach_phase.get("error_message") or attach_phase.get("stderr") or "").strip() or None
            if not attach_err and load_result.get("stage") == "attach":
                attach_err = str(load_result.get("error_message") or "").strip() or None
            if not attach_err:
                attach_err = _daemon_attach_error(load_report.get("stderr"))

            # If loader stderr indicates attach-phase failure, keep load_report focused
            # on load/READY and surface attach error under attach_result instead.
            daemon_stdout = None
            daemon_stderr = None
            if attach_err:
                # Preserve full daemon logs under attach_result for debugging.
                daemon_stdout = (attach_phase.get("stdout") if attach_phase else None) or load_report.get("stdout")
                daemon_stderr = (attach_phase.get("stderr") if attach_phase else None) or load_report.get("stderr")
                load_report["stderr"] = ""
            attach_result = {
                "success": attach_ok,
                "stage": "attach",
                "attached": attach_ok,
                "skipped": not load_ok,
                "reason": (
                    "attached_with_libbpf_loader_daemon"
                    if attach_ok
                    else ("libbpf_loader_attach_failed" if attach_err else "load_failed")
                ),
                "error_log": attach_err or (None if load_ok else load_report.get("error_message")),
                "error_message": attach_err or (None if load_ok else load_result.get("error_message")),
                "daemon_stdout": daemon_stdout if attach_err else None,
                "daemon_stderr": daemon_stderr if attach_err else None,
                "daemon_returncode": load_report.get("returncode") if attach_err else None,
                "command": load_result.get("command"),
                "plan": attach_plan,
                "pid": load_result.get("pid"),
                "maps_dir": load_result.get("maps_dir"),
                "ready_line": load_result.get("ready_line"),
                "via_libbpf_loader_daemon": True,
            }
            attach_result["error_log_lines"] = _split_lines(attach_result.get("error_log"))
            attach_result["error_message_lines"] = _split_lines(attach_result.get("error_message"))
            if attach_result.get("daemon_stdout") is not None:
                attach_result["daemon_stdout_lines"] = _split_lines(attach_result.get("daemon_stdout"))
            if attach_result.get("daemon_stderr") is not None:
                attach_result["daemon_stderr_lines"] = _split_lines(attach_result.get("daemon_stderr"))
        elif backend == "libbpf_once":
            safe_remove_tree(str(pin_path) + "_maps")
            load_report = load_bpf_program_with_libbpf_loader(
                object_file=object_file,
                pin_path=pin_path,
                timeout=load_timeout,
            )
            attach_result = attach_bpf_program(load_result=load_report, attach_plan=attach_plan)
            safe_remove_tree(str(pin_path) + "_maps")
        elif backend == "bpftool":
            load_report = load_bpf_program_bpftool(
                object_file=object_file,
                pin_path=pin_path,
                bpftool_bin=bpftool_bin,
                program_type=attach_plan.get("program_type") or program_type,
                autoattach=bool(attach_plan.get("autoattach_requested")),
                timeout=load_timeout,
            )
            attach_result = attach_bpf_program(load_result=load_report, attach_plan=attach_plan)
        else:
            return ToolResult(
                success=False,
                stage="load",
                payload={"error": f"unknown_backend:{backend}"},
                error_kind="tool_error",
                error_message="unknown_backend",
            )

        payload: Dict[str, Any] = {
            "backend": backend,
            "attach_plan": attach_plan,
            "load": load_report,
            "attach": attach_result,
        }
        if backend == "libbpf_daemon" and proc is not None:
            payload["_process"] = proc

        ok = bool(load_report.get("success")) and bool(attach_result.get("success"))
        return ToolResult(
            success=ok,
            stage="attach" if ok else ("load" if not load_report.get("success") else "attach"),
            payload=cast(Dict[str, Any], payload),
            error_kind="target_error" if not ok else None,
            error_message=None if ok else "load_or_attach_failed",
        )

