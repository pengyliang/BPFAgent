from __future__ import annotations

import subprocess
from typing import Any, Dict, List, Optional


def run_command(cmd: List[str], *, timeout: int = 60, cwd: Optional[str] = None) -> Dict[str, Any]:
    try:
        completed = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            timeout=timeout,
            cwd=cwd,
        )
        return {
            "command": cmd,
            "returncode": completed.returncode,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
            "timed_out": False,
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "command": cmd,
            "returncode": None,
            "stdout": exc.stdout or "",
            "stderr": exc.stderr or "",
            "timed_out": True,
        }

