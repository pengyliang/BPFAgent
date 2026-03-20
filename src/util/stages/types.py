from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Literal, Optional


StageName = Literal[
    "static_check",
    "compile",
    "load",
    "attach",
    "runtime_test",
    "detach",
    "deploy",
]


@dataclass(frozen=True)
class ToolContext:
    request_id: Optional[str] = None
    kernel_output_version: Optional[str] = None
    logs_dir: Optional[str] = None
    build_dir: Optional[str] = None
    shared_logs_dir: Optional[str] = None
    extra: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ToolResult:
    success: bool
    stage: StageName
    payload: Dict[str, Any] = field(default_factory=dict)
    error_kind: Optional[Literal["target_error", "tool_error"]] = None
    error_message: Optional[str] = None
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": bool(self.success),
            "stage": self.stage,
            "payload": self.payload,
            "error_kind": self.error_kind,
            "error_message": self.error_message,
            "warnings": list(self.warnings),
        }

