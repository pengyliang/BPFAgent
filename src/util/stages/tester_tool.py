from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional, cast

from src.util.deploy.commands import run_command
from src.util.deploy.runtime_tester import run_case_runtime_validation
from src.util.stages.types import ToolContext, ToolResult


@dataclass
class TesterTool:
    """Run runtime validation for a deployed case (workload + validator.yaml)."""

    def run(
        self,
        *,
        source_file: str,
        pin_path: str,
        runtime_timeout: int = 30,
        ctx: Optional[ToolContext] = None,
    ) -> ToolResult:
        report = run_case_runtime_validation(
            case_dir=Path(source_file).parent,
            pin_path=pin_path,
            timeout=runtime_timeout,
            run_command=run_command,
        )
        ok = bool(report.get("success"))
        return ToolResult(
            success=ok,
            stage="runtime_test",
            payload=cast(Dict[str, Any], report),
            error_kind="target_error" if not ok else None,
            error_message=None if ok else "runtime_test_failed",
        )

