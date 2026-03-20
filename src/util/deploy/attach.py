from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, Optional


def _normalize_program_type(sec_value: str) -> Optional[str]:
    prefix = sec_value.split("/", 1)[0]
    if prefix in {"kprobe", "kretprobe", "tracepoint", "xdp", "lsm", "iter", "fentry", "fexit"}:
        return prefix
    if prefix.startswith("raw_tp"):
        return "raw_tracepoint"
    if prefix.startswith("cgroup"):
        return "cgroup_skb"
    return None


def infer_attach_plan(*, source_file: str, program_type: Optional[str] = None) -> Dict[str, Any]:
    source = Path(source_file)
    try:
        source_text = source.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        source_text = ""

    sections = re.findall(r'SEC\("([^"]+)"\)', source_text)
    program_sections = [s for s in sections if s not in {".maps", "license"}]
    selected_section = program_sections[0] if program_sections else None

    inferred_program_type = _normalize_program_type(selected_section) if selected_section else None
    effective_program_type = program_type or inferred_program_type

    attach_target = None
    if selected_section and "/" in selected_section:
        attach_target = selected_section.split("/", 1)[1]

    autoattach_supported = effective_program_type in {
        "kprobe",
        "kretprobe",
        "tracepoint",
        "raw_tracepoint",
        "fentry",
        "fexit",
        "lsm",
        "iter",
    }

    return {
        "source_file": str(source),
        "section": selected_section,
        "program_type": effective_program_type,
        "attach_target": attach_target,
        "autoattach_supported": autoattach_supported,
        "autoattach_requested": autoattach_supported and bool(attach_target),
    }


def _classify_libbpf_loader_failure(load_result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if not load_result or not load_result.get("via_libbpf_loader") or load_result.get("success"):
        return None

    stderr = str(load_result.get("stderr") or "")
    low = stderr.lower()
    if load_result.get("loader_build_failed"):
        return {
            "phase": "build",
            "reason": "loader_build_failed",
            "error_log": stderr or str(load_result.get("stdout") or ""),
        }
    if "attach failed" in low or "pin link failed" in low or "pin program failed" in low:
        return {
            "phase": "attach",
            "reason": "libbpf_loader_attach_failed",
            "error_log": stderr,
        }
    if "load failed" in low or "open failed" in low:
        return {
            "phase": "load",
            "reason": "libbpf_loader_load_failed",
            "error_log": stderr,
        }
    if "no attachable program found" in low:
        return {
            "phase": "attach",
            "reason": "libbpf_loader_attach_failed",
            "error_log": stderr,
        }
    return {
        "phase": "unknown",
        "reason": "libbpf_loader_failed",
        "error_log": stderr or str(load_result.get("stdout") or ""),
    }


def attach_bpf_program(*, load_result: Dict[str, Any], attach_plan: Dict[str, Any]) -> Dict[str, Any]:
    load_cmd = (load_result or {}).get("command")
    loader_failure = _classify_libbpf_loader_failure(load_result or {})
    if loader_failure and loader_failure["phase"] == "attach":
        err_log = loader_failure.get("error_log") or ""
        return {
            "success": False,
            "stage": "attach",
            "attached": False,
            "skipped": False,
            "reason": loader_failure["reason"],
            "error_log": err_log,
            "error_message": err_log.strip() or loader_failure["reason"],
            "command": load_cmd,
            "plan": attach_plan,
            "via_libbpf_loader": load_result.get("via_libbpf_loader"),
            "loader_bin": load_result.get("loader_bin"),
        }

    if not load_result or not load_result.get("success"):
        err_log = (
            (loader_failure.get("error_log") if loader_failure else None)
            or (load_result.get("error_message") if load_result else None)
            or (load_result.get("stderr") if load_result else None)
        )
        return {
            "success": False,
            "stage": "attach",
            "attached": False,
            "skipped": True,
            "reason": loader_failure["reason"] if loader_failure else "load_failed",
            "error_log": err_log,
            "error_message": err_log,
            "command": load_cmd,
            "plan": attach_plan,
            "via_libbpf_loader": (load_result or {}).get("via_libbpf_loader"),
            "loader_bin": (load_result or {}).get("loader_bin"),
        }

    if not attach_plan.get("autoattach_requested"):
        return {
            "success": True,
            "stage": "attach",
            "attached": False,
            "skipped": True,
            "reason": "attach_not_requested",
            "error_log": None,
            "error_message": None,
            "command": load_cmd,
            "plan": attach_plan,
        }

    if (load_result or {}).get("via_libbpf_loader") is not True and bool((load_result or {}).get("autoattach")):
        return {
            "success": True,
            "stage": "attach",
            "attached": True,
            "skipped": False,
            "reason": "attached_with_bpftool_autoattach",
            "error_log": None,
            "error_message": None,
            "command": load_cmd,
            "plan": attach_plan,
            "via_bpftool": True,
        }

    attached_count = (load_result or {}).get("attached_count")
    link_pin_supported = (load_result or {}).get("link_pin_supported")
    if attached_count is not None and attached_count <= 0:
        if link_pin_supported is False:
            return {
                "success": True,
                "stage": "attach",
                "attached": False,
                "skipped": True,
                "reason": "link_pin_unsupported",
                "error_log": (load_result.get("stderr") or "").strip() or None,
                "error_message": "kernel does not support pinning bpf_link for this attach type",
                "command": load_cmd,
                "plan": attach_plan,
                "via_libbpf_loader": True,
                "loader_bin": load_result.get("loader_bin"),
            }
        return {
            "success": False,
            "stage": "attach",
            "attached": False,
            "skipped": False,
            "reason": "attach_failed",
            "error_log": (load_result.get("stderr") or "").strip() or None,
            "error_message": (load_result.get("stderr") or "").strip() or "attach_failed",
            "command": load_cmd,
            "plan": attach_plan,
            "via_libbpf_loader": True,
            "loader_bin": load_result.get("loader_bin"),
        }

    return {
        "success": True,
        "stage": "attach",
        "attached": True,
        "skipped": False,
        "reason": "attached_with_libbpf_loader",
        "error_log": None,
        "error_message": None,
        "command": load_cmd,
        "plan": attach_plan,
        "via_libbpf_loader": True,
        "loader_bin": load_result.get("loader_bin"),
    }

