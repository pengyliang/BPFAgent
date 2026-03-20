from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

from prompts.reflect_agent import REFLECT_AGENT_PROMPT
from src.core.io import write_json
from src.core.llm.openai_compat import OpenAICompatClient, extract_first_message_content


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _slugify(text: str) -> str:
    s = re.sub(r"[^a-zA-Z0-9]+", "_", (text or "").strip()).strip("_").lower()
    return s or "rule"


def _extract_yaml_block(text: str) -> Optional[str]:
    if not text:
        return None
    m = re.search(r"```yaml\s*\n([\s\S]*?)```", text, flags=re.IGNORECASE)
    if not m:
        return None
    return m.group(1).strip() + "\n"


def _ensure_repair_db(path: Path) -> Dict[str, Any]:
    if path.exists():
        try:
            obj = yaml.safe_load(path.read_text(encoding="utf-8", errors="ignore"))
            return obj if isinstance(obj, dict) else {"version": 1, "updated_at": _utc_now(), "rules": []}
        except Exception:
            return {"version": 1, "updated_at": _utc_now(), "rules": []}
    return {"version": 1, "updated_at": _utc_now(), "rules": []}


def _rule_key(rule: Dict[str, Any]) -> Tuple[str, str]:
    stage = str(rule.get("stage") or "")
    sig = str(rule.get("error_signature") or "")
    return stage, sig


def merge_rule(db: Dict[str, Any], rule: Dict[str, Any]) -> Dict[str, Any]:
    rules = db.setdefault("rules", [])
    if not isinstance(rules, list):
        rules = []
        db["rules"] = rules
    key = _rule_key(rule)
    for existing in rules:
        if isinstance(existing, dict) and _rule_key(existing) == key and key != ("", ""):
            ex = existing.setdefault("examples", [])
            if isinstance(ex, list):
                for item in (rule.get("examples") or []):
                    if item not in ex:
                        ex.append(item)
            # Keep existing but allow filling missing constraints/root_cause/fix_strategy
            for k in ("root_cause", "fix_strategy", "constraints", "symptoms"):
                if not existing.get(k) and rule.get(k):
                    existing[k] = rule[k]
            db["updated_at"] = _utc_now()
            return db
    rules.append(rule)
    db["updated_at"] = _utc_now()
    return db


@dataclass(frozen=True)
class ReflectOutputs:
    reflect_record_json: str
    repair_method_yaml: str
    repair_report_json: Optional[str]


def run_reflect(
    *,
    llm: Optional[OpenAICompatClient],
    logs_dir: str,
    category: str,
    case_rel: str,
    case_display: str,
    kernel_profile: Dict[str, Any],
    deploy: Dict[str, Any],
    error_signature_counts: Dict[str, int],
    last_error_signature: Optional[str],
    key_lines: List[str],
    attempts: List[Dict[str, Any]],
    repair_method_yaml_path: str,
) -> ReflectOutputs:
    logs = Path(logs_dir)
    logs.mkdir(parents=True, exist_ok=True)

    reflect_record = logs / "reflect_record.json"

    final_stage = str(deploy.get("stage") or "unknown")
    final_success = bool(deploy.get("success"))
    kernel_ver = str(((kernel_profile.get("kernel_version") or {}).get("raw")) or "")

    print("\n[reflect] input")
    print(f"[reflect] case={case_display}")
    print(f"[reflect] kernel={kernel_ver}")
    print(f"[reflect] final_success={final_success} final_stage={final_stage}")
    if last_error_signature:
        print(f"[reflect] last_error_signature={last_error_signature}")
    if error_signature_counts:
        print(f"[reflect] error_signature_counts={error_signature_counts}")
    if key_lines:
        print("[reflect] key_lines:")
        for ln in key_lines[:12]:
            print(f"  {ln}")
    if attempts:
        print(f"[reflect] attempts_count={len(attempts)}")

    # If failed or had novel behavior, propose/update repair_method.yaml
    db_path = Path(repair_method_yaml_path)
    db = _ensure_repair_db(db_path)

    llm_thought: Optional[str] = None
    llm_rationale: Optional[str] = None
    yaml_rule_text: Optional[str] = None
    rule: Optional[Dict[str, Any]] = None
    if llm is not None:
        attempts_summary = yaml.safe_dump(attempts or [], sort_keys=False, allow_unicode=True)
        prompt_vars = {
            "case_display": case_display,
            "kernel_version": kernel_ver,
            "final_stage": final_stage,
            "final_success": str(final_success).lower(),
            "error_signature_counts": yaml.safe_dump(error_signature_counts or {}, sort_keys=True, allow_unicode=True),
            "key_lines": "\n".join((key_lines or [])[:30]),
            "attempts_summary": attempts_summary,
        }
        sys_msg = REFLECT_AGENT_PROMPT.render(prompt_vars)
        resp = llm.chat_completions(messages=[{"role": "system", "content": sys_msg}], temperature=0.1, max_tokens=900)
        content = extract_first_message_content(resp) or ""
        yml = _extract_yaml_block(content)
        if yml:
            try:
                obj = yaml.safe_load(yml)
                if isinstance(obj, dict) and obj.get("stage"):
                    rule = obj
                    yaml_rule_text = yml
                    llm_thought = str(obj.get("thought") or "") or None
                    llm_rationale = str(obj.get("rationale") or "") or None
            except Exception:
                rule = None
        print("\n[reflect] llm_output")
        if yml:
            print("[reflect] yaml_rule:")
            print(yml.strip())
        else:
            print("[reflect] yaml_rule: <missing_or_unparseable>")

    if rule is None:
        # Deterministic fallback rule
        stage = final_stage if final_stage != "success" else "unknown"
        sig = last_error_signature or ""
        rid = _slugify(f"{stage}_{sig}")[:60]
        rule = {
            "id": rid,
            "stage": stage,
            "error_signature": sig,
            "symptoms": [{"pattern": (key_lines[0] if key_lines else sig or stage)[:120]}],
            "root_cause": "需要进一步归纳（LLM 未启用或未返回可解析 YAML）。",
            "fix_strategy": ["收集更多关键报错行与 verifier 片段后再归纳修复策略。"],
            "constraints": {"kernel_min": None, "requires_btf": None},
            "examples": [{"case": f"{category}/{case_rel}", "report": None}],
            "thought": llm_thought or "",
            "rationale": llm_rationale or "",
        }
        yaml_rule_text = yaml.safe_dump(rule, sort_keys=False, allow_unicode=True)

    # Ensure required fields
    rule.setdefault("examples", [])
    if isinstance(rule["examples"], list):
        rule["examples"].append({"case": f"{category}/{case_rel}", "report": None})
    rule.setdefault("id", _slugify(f"{rule.get('stage')}_{rule.get('error_signature')}")[:60])

    db = merge_rule(db, rule)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    db_path.write_text(yaml.safe_dump(db, sort_keys=False, allow_unicode=True), encoding="utf-8")
    print(f"[reflect] updated_repair_method={db_path}")

    # 4) repair_report.json only when failed
    repair_report_path: Optional[str] = None
    if not final_success:
        repair_report = {
            "generated_at": _utc_now(),
            "case_display": case_display,
            "final_stage": final_stage,
            "same_error_threshold": 3,
            "error_signature_counts": error_signature_counts,
            "attempts": attempts,
        }
        repair_report_path = str(logs / "repair_report.json")
        write_json(repair_report_path, repair_report)
        print(f"[reflect] wrote={repair_report_path}")

    record = {
        "generated_at": _utc_now(),
        "case_display": case_display,
        "kernel": {"raw": kernel_ver},
        "final": {"success": final_success, "stage": final_stage, "last_error_signature": last_error_signature},
        "input": {
            "category": category,
            "case_rel": case_rel,
            "deploy": deploy,
            "error_signature_counts": error_signature_counts,
            "last_error_signature": last_error_signature,
            "key_lines": key_lines[:50],
            "attempts": attempts,
        },
        "llm": {
            "enabled": bool(llm is not None),
            "thought": llm_thought,
            "rationale": llm_rationale,
            "yaml_rule_text": (yaml_rule_text or "").strip() or None,
        },
        "output": {
            "final_yaml_rule": rule,
            "updated_repair_method": str(db_path),
        },
        "updated_at": _utc_now(),
    }
    write_json(reflect_record, record)
    print(f"[reflect] wrote={reflect_record}")

    return ReflectOutputs(
        reflect_record_json=str(reflect_record),
        repair_method_yaml=str(db_path),
        repair_report_json=repair_report_path,
    )

