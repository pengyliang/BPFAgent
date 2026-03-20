from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional


def write_json(path: str | Path, payload: Any) -> str:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return str(p)


def read_json(path: str | Path) -> Optional[Dict[str, Any]]:
    p = Path(path)
    if not p.exists():
        return None
    try:
        raw = json.loads(p.read_text(encoding="utf-8", errors="ignore"))
        return raw if isinstance(raw, dict) else None
    except Exception:
        return None

