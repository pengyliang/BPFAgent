"""Run static compatibility checks from collected AST + kernel profile."""

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.agent.analysis.static_checker import analyze_project_static_checks


if __name__ == "__main__":
    report = analyze_project_static_checks(
        ast_summary_path="tests/logs/ast_summary.json",
        kernel_profile_path="tests/logs/kernel_profile.json",
        output_path="tests/logs/static_check_report.json",
    )
    print(
        "Static check done:",
        f"errors={report['summary']['error_count']}",
        f"warnings={report['summary']['warning_count']}",
    )
