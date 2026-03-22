"""Load AST summary + kernel profile JSON and run static compatibility checks."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional

from src.util.static_check.static_checker import analyze_case_static_checks


def analyze_project_static_checks(
    *,
    ast_summary_path: str,
    kernel_profile_path: str,
    output_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Read `ast_summary.json`-style payload and `kernel_profile.json`, return static check report."""
    with Path(ast_summary_path).open(encoding="utf-8") as f:
        ast_payload = json.load(f)
    with Path(kernel_profile_path).open(encoding="utf-8") as f:
        kernel_profile = json.load(f)
    summaries = ast_payload.get("summaries") or []
    if not isinstance(summaries, list):
        summaries = []
    return analyze_case_static_checks(summaries, kernel_profile, output_path=output_path)
