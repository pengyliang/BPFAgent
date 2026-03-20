from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from src.util.static_check.static_checker import analyze_case_static_checks
from src.util.stages.types import ToolContext, ToolResult


@dataclass
class StaticCheckTool:
    """Structured wrapper around static compatibility checking."""

    def run(
        self,
        *,
        summaries: List[Dict[str, Any]],
        kernel_profile: Dict[str, Any],
        output_path: Optional[str] = None,
        ctx: Optional[ToolContext] = None,
    ) -> ToolResult:
        report = analyze_case_static_checks(
            summaries=summaries,
            kernel_profile=kernel_profile,
            output_path=output_path,
        )
        ok = bool((report or {}).get("success"))
        return ToolResult(
            success=ok,
            stage="static_check",
            payload=report or {},
            error_kind="target_error" if not ok else None,
            error_message=None if ok else "static_check_failed",
        )

