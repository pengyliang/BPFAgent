from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from src.util.deploy.attach import attach_bpf_program, infer_attach_plan
from src.util.deploy.commands import run_command
from src.util.deploy.compile import compile_bpf_program, maybe_inject_task_tgid_offset
from src.util.deploy.detach import detach_bpf_program
from src.util.deploy.load import (
    extract_phase_json,
    load_bpf_program_bpftool,
    load_bpf_program_with_libbpf_loader,
    safe_remove_tree,
    start_libbpf_loader_daemon,
    terminate_loader_daemon,
)
from src.util.deploy.runtime_tester import run_case_runtime_validation


def deploy_bpf_program(
    *,
    source_file: str,
    pin_path: str,
    object_file: Optional[str] = None,
    clang_bin: str = "clang",
    bpftool_bin: str = "bpftool",
    program_type: Optional[str] = None,
    compile_timeout: int = 60,
    load_timeout: int = 60,
    runtime_timeout: int = 30,
    extra_cflags: Optional[List[str]] = None,
    vmlinux_header_dir: Optional[str] = None,
    load_backend: str = "libbpf_daemon",
) -> Dict[str, Any]:
    extra_cflags = maybe_inject_task_tgid_offset(
        extra_cflags,
        source_file=source_file,
        bpftool_bin=bpftool_bin,
    )
    compile_result = compile_bpf_program(
        source_file=source_file,
        object_file=object_file,
        clang_bin=clang_bin,
        extra_cflags=extra_cflags,
        timeout=compile_timeout,
        vmlinux_header_dir=vmlinux_header_dir,
        bpftool_bin=bpftool_bin,
    )

    if not compile_result["success"]:
        return {
            "success": False,
            "stage": "compile_failed",
            "compile": compile_result,
            "load": None,
            "attach": None,
            "runtime": None,
            "detach": None,
        }

    attach_plan = infer_attach_plan(source_file=source_file, program_type=program_type)

    if load_backend not in {"libbpf_daemon", "libbpf_once", "bpftool"}:
        raise ValueError("load_backend must be one of: libbpf_daemon, libbpf_once, bpftool")

    proc = None
    if load_backend == "libbpf_daemon":
        safe_remove_tree(str(pin_path) + "_maps")
        load_result = start_libbpf_loader_daemon(
            object_file=compile_result["object_file"],
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

        if load_phase:
            load_report["stdout"] = load_phase.get("stdout") or ""
            load_report["stderr"] = load_phase.get("stderr") or ""
            load_report["error_message"] = load_phase.get("error_message") or ""
        load_report["success"] = load_ok
        load_report["stage"] = "load"
        load_report["phase_details"] = phases
        if load_ok:
            load_report["error_message"] = ""

        attach_err = None
        if attach_phase and not bool(attach_phase.get("ok")):
            attach_err = str(attach_phase.get("error_message") or attach_phase.get("stderr") or "").strip() or None
        if not attach_err and load_result.get("stage") == "attach":
            attach_err = str(load_result.get("error_message") or "").strip() or None

        daemon_stdout = None
        daemon_stderr = None
        if attach_err:
            daemon_stdout = (attach_phase.get("stdout") if attach_phase else None) or load_report.get("stdout")
            daemon_stderr = (attach_phase.get("stderr") if attach_phase else None) or load_report.get("stderr")
            load_report["stderr"] = ""
        attach_result = {
            "success": attach_ok,
            "stage": "attach",
            "attached": attach_ok,
            "skipped": not load_ok,
            "reason": "attached_with_libbpf_loader_daemon" if attach_ok else ("libbpf_loader_attach_failed" if attach_err else "load_failed"),
            "error_log": attach_err or (None if load_ok else load_report.get("error_message")),
            "error_message": attach_err or (None if load_ok else load_result.get("error_message")),
            "daemon_stdout": daemon_stdout,
            "daemon_stderr": daemon_stderr,
            "daemon_returncode": load_report.get("returncode") if attach_err else None,
            "command": load_result.get("command"),
            "plan": attach_plan,
            "pid": load_result.get("pid"),
            "maps_dir": load_result.get("maps_dir"),
            "ready_line": load_result.get("ready_line"),
            "via_libbpf_loader_daemon": True,
        }
    elif load_backend == "libbpf_once":
        safe_remove_tree(str(pin_path) + "_maps")
        load_report = load_bpf_program_with_libbpf_loader(
            object_file=compile_result["object_file"],
            pin_path=pin_path,
            timeout=load_timeout,
        )
        attach_result = attach_bpf_program(load_result=load_report, attach_plan=attach_plan)
        safe_remove_tree(str(pin_path) + "_maps")
    else:
        load_report = load_bpf_program_bpftool(
            object_file=compile_result["object_file"],
            pin_path=pin_path,
            bpftool_bin=bpftool_bin,
            program_type=attach_plan.get("program_type") or program_type,
            autoattach=bool(attach_plan.get("autoattach_requested")),
            timeout=load_timeout,
        )
        attach_result = attach_bpf_program(load_result=load_report, attach_plan=attach_plan)

    if attach_result.get("success") and attach_result.get("attached"):
        runtime_result = run_case_runtime_validation(
            case_dir=Path(source_file).parent,
            pin_path=pin_path,
            timeout=runtime_timeout,
            run_command=run_command,
        )
    else:
        runtime_result = {
            "success": True,
            "stage": "runtime_test",
            "skipped": True,
            "reason": "attach_not_active",
            "case_dir": str(Path(source_file).parent),
            "pin_path": str(pin_path),
        }

    if load_backend == "libbpf_daemon":
        terminate_loader_daemon(proc)
        safe_remove_tree(str(pin_path) + "_maps")
        detach_result = {
            "success": True,
            "stage": "detach",
            "detached": True,
            "skipped": False,
            "reason": "loader_terminated",
            "pin_path": pin_path,
            "pid": (load_report or {}).get("pid"),
        }
    else:
        detach_result = detach_bpf_program(pin_path=pin_path, attach_result=attach_result)

    if not attach_result["success"] and attach_result.get("reason") == "libbpf_loader_attach_failed":
        stage = "attach_failed"
        success = False
    elif not (load_report or {}).get("success"):
        stage = "load_failed"
        success = False
    elif not attach_result["success"]:
        stage = "attach_failed"
        success = False
    elif not runtime_result["success"]:
        stage = "runtime_test_failed"
        success = False
    else:
        stage = "success"
        success = True

    return {
        "success": success,
        "stage": stage,
        "compile": compile_result,
        "load": load_report,
        "attach": attach_result,
        "runtime": runtime_result,
        "detach": detach_result,
    }


def _trim_error_log(text: Any, *, max_chars: int = 4000) -> Optional[str]:
    if not text:
        return None
    cleaned = str(text).strip()
    if not cleaned:
        return None
    if len(cleaned) <= max_chars:
        return cleaned
    return cleaned[:max_chars] + "\n...<truncated>"


def _step_summary(step_result: Any) -> Dict[str, Any]:
    if not isinstance(step_result, dict):
        return {"status": "unknown", "success": None, "error_log": None}

    if step_result.get("skipped"):
        return {
            "status": "skipped",
            "success": None,
            "error_log": None,
            "reason": step_result.get("reason"),
        }

    success = bool(step_result.get("success"))
    if success:
        return {"status": "success", "success": True, "error_log": None}

    error_text = (
        step_result.get("error_message")
        or step_result.get("error_log")
        or step_result.get("stderr")
        or step_result.get("stdout")
        or step_result.get("reason")
        or "step_failed"
    )
    return {"status": "failed", "success": False, "error_log": _trim_error_log(error_text)}


def make_deploy_result_summary(deploy_report: Dict[str, Any]) -> Dict[str, Any]:
    report = deploy_report or {}
    return {
        "success": bool(report.get("success")),
        "stage": report.get("stage"),
        "steps": {
            "static_check": _step_summary(report.get("static_check")),
            "compile": _step_summary(report.get("compile")),
            "load": _step_summary(report.get("load")),
            "attach": _step_summary(report.get("attach")),
            "runtime": _step_summary(report.get("runtime")),
        },
    }


def save_deploy_report(report: Dict[str, Any], output_path: str) -> None:
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=True)
