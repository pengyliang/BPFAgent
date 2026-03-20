from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class ErrorSignal:
    stage: str
    error_types: List[str]
    key_lines: List[str]
    raw_log: str


def _extract_compile_log(deploy_report: Dict[str, Any]) -> str:
    compile_step = (deploy_report or {}).get("compile") or {}
    if not isinstance(compile_step, dict):
        return ""
    return (compile_step.get("stderr") or "") + "\n" + (compile_step.get("stdout") or "")


def _extract_load_log(deploy_report: Dict[str, Any]) -> str:
    load_step = (deploy_report or {}).get("load") or {}
    if not isinstance(load_step, dict):
        return ""
    verifier = load_step.get("verifier") or {}
    if isinstance(verifier, dict) and verifier.get("raw_log"):
        return str(verifier.get("raw_log") or "")
    return (load_step.get("stderr") or "") + "\n" + (load_step.get("stdout") or "")


def recognize_error(deploy_report: Dict[str, Any]) -> ErrorSignal:
    report = deploy_report or {}
    stage = str(report.get("stage") or "unknown")

    if stage == "compile_failed":
        raw = _extract_compile_log(report)
        low = raw.lower()
        key_lines = [ln.strip() for ln in raw.splitlines() if "error:" in ln.lower() or "fatal error:" in ln.lower()]
        types: List[str] = []
        if "fatal error:" in low and "file not found" in low:
            types.append("missing_header")
        if "implicit declaration of function" in low or "undeclared" in low:
            types.append("missing_declaration")
        if not types:
            types = ["compile_error"]
        return ErrorSignal(stage=stage, error_types=types, key_lines=key_lines[:30], raw_log=raw)

    if stage in {"load_failed", "attach_failed"}:
        raw = _extract_load_log(report)
        low = raw.lower()
        key_lines = [ln.strip() for ln in raw.splitlines() if any(tok in ln.lower() for tok in ["invalid", "error", "helper", "stack", "map", "insn", "loop", "type="])]
        types: List[str] = []
        if "unknown func" in low or "invalid func" in low:
            types.append("unknown_func")
        if "invalid mem access" in low or "out of bounds" in low:
            types.append("invalid_mem_access")
        if "loop" in low and ("bounded" in low or "back-edge" in low):
            types.append("unbounded_loop")
        if not types:
            types = ["verifier_reject"]
        return ErrorSignal(stage=stage, error_types=types, key_lines=key_lines[:30], raw_log=raw)

    raw = ""
    return ErrorSignal(stage=stage, error_types=["unknown"], key_lines=[], raw_log=raw)


def semantic_diff_signature(before: str, after: str) -> str:
    """A cheap signature to detect no-op / oscillation."""
    b = re.sub(r"\s+", " ", before or "").strip()
    a = re.sub(r"\s+", " ", after or "").strip()
    if b == a:
        return "no_change"
    return f"changed:{len(b)}->{len(a)}"

