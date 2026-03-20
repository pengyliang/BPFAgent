from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional, cast

from src.util.deploy.detach import detach_bpf_program
from src.util.stages.types import ToolContext, ToolResult


@dataclass
class DetachTool:
    """Detach/unpin pinned program/link artifacts."""

    def run(
        self,
        *,
        pin_path: str,
        attach_result: Dict[str, Any],
        ctx: Optional[ToolContext] = None,
    ) -> ToolResult:
        report = detach_bpf_program(pin_path=pin_path, attach_result=attach_result)
        ok = bool(report.get("success"))
        return ToolResult(
            success=ok,
            stage="detach",
            payload=cast(Dict[str, Any], report),
            error_kind="target_error" if not ok else None,
            error_message=None if ok else "detach_failed",
        )

