from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple

VERIFIER_ERROR_PATTERNS: List[Tuple[str, List[str]]] = [
    ("invalid_mem_access", [r"invalid mem access", r"out of bounds", r"ptr_to_stack"]),
    ("unbounded_loop", [r"back-edge", r"loop is not bounded", r"infinite loop", r"unbounded loop"]),
    ("unknown_func", [r"unknown func", r"invalid func", r"helper call .* not allowed"]),
    ("reg_type_mismatch", [r"type mismatch", r"r\d+ type=", r"expected=", r"expected=.*got=.*", r"invalid bpf_context access"]),
    ("stack_depth_exceeded", [r"stack depth", r"stack limit", r"too large stack"]),
    ("invalid_map_type", [r"map type", r"unsupported map", r"invalid map"]),
    ("unreachable_insn", [r"unreachable insn", r"unreachable instruction"]),
    ("insn_limit_exceeded", [r"program too large", r"too many instructions", r"insn limit"]),
]


def parse_verifier_log(log_text: str) -> Dict[str, Any]:
    text = log_text or ""
    text_lower = text.lower()

    matched: List[str] = []
    for error_type, patterns in VERIFIER_ERROR_PATTERNS:
        for pattern in patterns:
            if re.search(pattern, text_lower):
                matched.append(error_type)
                break

    key_lines: List[str] = []
    for line in text.splitlines():
        low = line.lower()
        if any(token in low for token in ["invalid", "error", "helper", "stack", "map", "insn", "loop", "type="]):
            key_lines.append(line.strip())

    return {
        "primary_error_type": matched[0] if matched else "unknown",
        "error_types": matched,
        "key_lines": key_lines[:30],
        "raw_log": text,
    }

