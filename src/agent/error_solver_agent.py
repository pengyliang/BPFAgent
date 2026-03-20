from __future__ import annotations

import difflib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

from prompts.error_solver import ERROR_SOLVER_PROMPT, build_error_solver_variables
from src.core.llm.openai_compat import OpenAICompatClient, extract_first_message_content
from src.agent.repair.patterns import ErrorSignal
from src.agent.repair.single_agent import RuleBasedSingleAgentRepair


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _read_text(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return ""


def _unified_diff(before: str, after: str, *, fromfile: str = "before", tofile: str = "after") -> str:
    return "".join(
        difflib.unified_diff(
            (before or "").splitlines(keepends=True),
            (after or "").splitlines(keepends=True),
            fromfile=fromfile,
            tofile=tofile,
        )
    )


def _extract_json_block(text: str) -> Optional[Dict[str, Any]]:
    if not text:
        return None
    m = re.search(r"```json\s*\n([\s\S]*?)```", text, flags=re.IGNORECASE)
    if not m:
        return None
    raw = m.group(1).strip()
    try:
        obj = json.loads(raw)
        return obj if isinstance(obj, dict) else None
    except Exception:
        return None


@dataclass(frozen=True)
class SolveResult:
    patched: bool
    patched_path: Optional[str]
    patched_code: Optional[str]
    diff: str
    llm_raw: Optional[str]
    llm_thought: Optional[str]
    llm_rationale: Optional[str]


class ErrorSolverAgent:
    """
    Error solver that writes ALL artifacts under:
      <case_log_dir>/error_solve/

    It also maintains an append-only record:
      <case_log_dir>/error_solve/error_record.json
    """

    def __init__(self, *, llm: Optional[OpenAICompatClient]):
        self.llm = llm
        self.rule_fallback = RuleBasedSingleAgentRepair()

    def _load_repair_method(self, repair_method_yaml: str) -> str:
        p = Path(repair_method_yaml)
        if not p.exists():
            return ""
        try:
            obj = yaml.safe_load(p.read_text(encoding="utf-8", errors="ignore"))
            return yaml.safe_dump(obj, sort_keys=False, allow_unicode=True).strip()
        except Exception:
            return _read_text(str(p)).strip()

    def _read_record(self, record_path: Path) -> Dict[str, Any]:
        if record_path.exists():
            try:
                obj = json.loads(record_path.read_text(encoding="utf-8", errors="ignore"))
                if isinstance(obj, dict):
                    obj.setdefault("attempts", [])
                    return obj
            except Exception:
                pass
        return {"generated_at": _utc_now(), "attempts": []}

    def _write_record(self, record_path: Path, record: Dict[str, Any]) -> None:
        record_path.parent.mkdir(parents=True, exist_ok=True)
        record["updated_at"] = _utc_now()
        record_path.write_text(json.dumps(record, indent=2, ensure_ascii=False), encoding="utf-8")

    def solve(
        self,
        *,
        error_solve_dir: str,
        retry_code_dir: str,
        error_record_path: str,
        case_display: str,
        error_state: str,
        state_result_json: str,
        error_message_json: str,
        new_code_path: str,
        current_source_file: str,
        current_code: str,
        signal: ErrorSignal,
        patch_history: List[str],
        repair_method_yaml_path: str,
        tool_info_text: str = "",
        usable_files_text: str = "",
        temperature: float = 0.2,
        verbose: bool = True,
    ) -> SolveResult:
        error_solve = Path(error_solve_dir)
        error_solve.mkdir(parents=True, exist_ok=True)
        Path(retry_code_dir).mkdir(parents=True, exist_ok=True)

        repair_method_text = self._load_repair_method(repair_method_yaml_path)

        llm_raw: Optional[str] = None
        llm_thought: Optional[str] = None
        llm_rationale: Optional[str] = None
        patched_code: Optional[str] = None

        if verbose:
            print("\n[error_solve] input")
            print(f"[error_solve] case={case_display}")
            print(f"[error_solve] error_state={error_state}")
            print(f"[error_solve] current_source_file={current_source_file}")
            print(f"[error_solve] state_result_json={state_result_json}")
            print(f"[error_solve] error_message_json={error_message_json}")
            print(f"[error_solve] error_types={signal.error_types}")
            if signal.key_lines:
                print("[error_solve] key_lines:")
                for ln in signal.key_lines[:12]:
                    print(f"  {ln}")

        if self.llm is not None:
            vars_map = build_error_solver_variables(
                error_state=error_state,
                state_result_json=state_result_json,
                error_message_json=error_message_json,
                repair_method=repair_method_text,
                usable_files=usable_files_text,
                tool_info=tool_info_text,
                new_code_path=new_code_path,
            )
            sys_prompt = ERROR_SOLVER_PROMPT.render(vars_map)
            user_prompt = (
                "当前源码路径：{path}\n"
                "错误类型：{types}\n"
                "关键报错行：\n{key}\n\n"
                "源码如下：\n```c\n{code}\n```\n"
            ).format(
                path=current_source_file,
                types=", ".join(signal.error_types),
                key="\n".join(signal.key_lines[:30]),
                code=current_code,
            )

            resp = self.llm.chat_completions(
                messages=[{"role": "system", "content": sys_prompt}, {"role": "user", "content": user_prompt}],
                temperature=temperature,
                max_tokens=1800,
            )
            llm_raw = extract_first_message_content(resp) or ""
            obj = _extract_json_block(llm_raw)
            if obj:
                llm_thought = str(obj.get("thought") or "") or None
                llm_rationale = str(obj.get("rationale") or "") or None
                patched_code = obj.get("patched_code") if isinstance(obj.get("patched_code"), str) else None
            if verbose:
                print("\n[error_solve] llm_output")
                if llm_thought:
                    print("[error_solve] thought:")
                    print(llm_thought)
                if llm_rationale:
                    print("[error_solve] rationale:")
                    print(llm_rationale)

        # fallback when LLM is disabled or not parseable
        if not patched_code:
            attempt = self.rule_fallback.repair(current_code=current_code, signal=signal, patch_history=patch_history)
            if attempt.success:
                patched_code = attempt.patched_code
                llm_rationale = llm_rationale or attempt.rationale
                if verbose:
                    print("\n[error_solve] fallback_rule_applied")
                    print(f"[error_solve] rationale={attempt.rationale}")

        diff_text = _unified_diff(current_code, patched_code or "", fromfile=current_source_file, tofile=new_code_path)
        diff_sig = "no_change" if not patched_code or (patched_code.strip() == current_code.strip()) else f"changed:{len(current_code)}->{len(patched_code)}"

        record_path = Path(error_record_path)
        record = self._read_record(record_path)
        record.setdefault("case_display", case_display)
        record.setdefault("error_solve_dir", str(error_solve))
        record.setdefault("retry_code_dir", str(Path(retry_code_dir)))
        record["last_error_state"] = error_state
        record["last_signal"] = {"stage": signal.stage, "error_types": signal.error_types, "key_lines": signal.key_lines[:30]}

        attempt_item: Dict[str, Any] = {
            "ts": _utc_now(),
            "input": {
                "error_state": error_state,
                "state_result_json": state_result_json,
                "error_message_json": error_message_json,
                "current_source_file": current_source_file,
            },
            "output": {
                "patched": bool(patched_code) and diff_sig != "no_change",
                "new_code_path": new_code_path,
                "diff_sig": diff_sig,
            },
            "llm": {
                "enabled": bool(self.llm is not None),
                "thought": llm_thought,
                "rationale": llm_rationale,
                "raw": llm_raw,
            },
            "diff": diff_text,
        }

        if patched_code and diff_sig != "no_change":
            Path(new_code_path).write_text(patched_code, encoding="utf-8")
            attempt_item["output"]["written"] = True
            if verbose:
                print("\n[error_solve] output")
                print(f"[error_solve] patched=true diff_sig={diff_sig}")
                print(f"[error_solve] wrote={new_code_path}")
        else:
            attempt_item["output"]["written"] = False
            if verbose:
                print("\n[error_solve] output")
                print("[error_solve] patched=false (no_change)")

        attempts = record.get("attempts")
        if isinstance(attempts, list):
            attempts.append(attempt_item)
        self._write_record(record_path, record)
        if verbose:
            print(f"[error_solve] error_record={record_path}")
            if diff_text.strip():
                print("[error_solve] diff(top):")
                for ln in diff_text.splitlines()[:80]:
                    print(ln)

        return SolveResult(
            patched=bool(patched_code) and diff_sig != "no_change",
            patched_path=new_code_path if (patched_code and diff_sig != "no_change") else None,
            patched_code=patched_code,
            diff=diff_text,
            llm_raw=llm_raw,
            llm_thought=llm_thought,
            llm_rationale=llm_rationale,
        )

