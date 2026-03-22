from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

from prompts.refiner import REFINER_PROMPT
from src.agent.base import (
    BaseAgent,
    VALID_FAIL_STAGES,
    build_error_signal,
    canonical_pattern_id,
    knowledge_base_enabled,
    knowledge_base_path,
    normalize_repair_knowledge_obj,
    normalize_repair_method,
    normalize_string_list,
)
from src.core.state import CaseState


def _normalize_method_text(text: str, *, default_can_fix: bool) -> str:
    del default_can_fix
    return normalize_repair_method(text)


PatternEntry = Dict[str, Any]
RepairDb = Dict[str, PatternEntry]
AppendTriple = Tuple[str, PatternEntry]


def _dedupe_preserve_order(items: List[str]) -> List[str]:
    seen: set[str] = set()
    out: List[str] = []
    for x in items:
        if isinstance(x, str) and x not in seen:
            seen.add(x)
            out.append(x)
    return out


def _sanitize_pattern_entry(entry: Dict[str, Any]) -> PatternEntry:
    aliases = _dedupe_preserve_order(normalize_string_list(entry.get("aliases")))
    stage_hints = _dedupe_preserve_order(
        [stage for stage in normalize_string_list(entry.get("stage_hints")) if stage in VALID_FAIL_STAGES]
    )
    evidence_hint = _dedupe_preserve_order(normalize_string_list(entry.get("evidence_hint")))
    repair_methods = _dedupe_preserve_order([normalize_repair_method(x) for x in entry.get("repair_methods") or [] if x])
    summary = str(entry.get("summary") or "").strip()
    handoff = str(entry.get("handoff") or "").strip()
    can_fix = bool(entry.get("can_fix", True))
    cleaned: PatternEntry = {
        "summary": summary,
        "aliases": aliases,
        "stage_hints": stage_hints,
        "can_fix": can_fix,
        "evidence_hint": evidence_hint,
        "repair_methods": repair_methods,
    }
    if handoff:
        cleaned["handoff"] = normalize_repair_method(handoff)
    return cleaned


def _ensure_repair_db(path: Path) -> RepairDb:
    if path.exists():
        try:
            obj = yaml.safe_load(path.read_text(encoding="utf-8", errors="ignore"))
            normalized = normalize_repair_knowledge_obj(obj)
            patterns = normalized.get("patterns")
            if isinstance(patterns, dict):
                return {str(pattern_id): _sanitize_pattern_entry(dict(entry or {})) for pattern_id, entry in patterns.items()}
        except Exception:
            pass
    return {}


def _repair_db_to_yaml_obj(db: RepairDb) -> Dict[str, Any]:
    out: Dict[str, Any] = {"version": 2, "patterns": {}}
    for pattern_id, entry in db.items():
        cleaned = _sanitize_pattern_entry(entry)
        payload: Dict[str, Any] = {
            "aliases": list(cleaned.get("aliases") or []),
            "stage_hints": list(cleaned.get("stage_hints") or []),
            "can_fix": bool(cleaned.get("can_fix", True)),
            "repair_methods": list(cleaned.get("repair_methods") or []),
        }
        if cleaned.get("summary"):
            payload["summary"] = cleaned["summary"]
        if cleaned.get("evidence_hint"):
            payload["evidence_hint"] = list(cleaned["evidence_hint"])
        if cleaned.get("handoff"):
            payload["handoff"] = cleaned["handoff"]
        out["patterns"][pattern_id] = payload
    return out


def _normalize_repair_method_updates(obj: Any) -> List[AppendTriple]:
    if not isinstance(obj, dict):
        return []
    root = obj
    if "patterns" not in obj and obj.get("version") != 2 and not any(str(k) in VALID_FAIL_STAGES for k in obj.keys()):
        root = {"version": 2, "patterns": obj}
    normalized = normalize_repair_knowledge_obj(root)
    patterns = normalized.get("patterns") if isinstance(normalized, dict) else None
    if not isinstance(patterns, dict):
        return []
    return [(str(pattern_id), _sanitize_pattern_entry(dict(entry or {}))) for pattern_id, entry in patterns.items()]


def _merge_rule(db: RepairDb, appends: List[AppendTriple]) -> tuple[RepairDb, RepairDb]:
    """按 pattern_id 合并知识；列表字段仅做精确去重，布尔可修性采用保守合并。"""
    added: RepairDb = {}
    for pattern_id, incoming in appends:
        incoming = _sanitize_pattern_entry(incoming)
        if not any(
            [
                incoming.get("summary"),
                incoming.get("aliases"),
                incoming.get("stage_hints"),
                incoming.get("repair_methods"),
                incoming.get("handoff"),
            ]
        ):
            continue
        before = _sanitize_pattern_entry(dict(db.get(pattern_id) or {})) if pattern_id in db else None
        if before is None:
            db[pattern_id] = incoming
            added[pattern_id] = incoming
            continue

        merged = dict(before)
        if incoming.get("summary") and not merged.get("summary"):
            merged["summary"] = incoming["summary"]
        for key in ("aliases", "stage_hints", "evidence_hint", "repair_methods"):
            cur = list(merged.get(key) or [])
            for item in incoming.get(key) or []:
                if item not in cur:
                    cur.append(item)
            merged[key] = cur
        merged["can_fix"] = bool(merged.get("can_fix", True) and incoming.get("can_fix", True))
        if incoming.get("handoff") and not merged.get("handoff"):
            merged["handoff"] = incoming["handoff"]
        merged = _sanitize_pattern_entry(merged)
        if merged == before:
            continue
        db[pattern_id] = merged
        added[pattern_id] = merged
    return db, added


def _appends_jsonable(appends: List[AppendTriple]) -> List[Dict[str, Any]]:
    return [{"pattern_id": pattern_id, **entry} for pattern_id, entry in appends]


def _collect_successful_stage_advances(state: CaseState) -> List[Dict[str, Any]]:
    deploy_events: Dict[int, Dict[str, Any]] = {}
    for event in state.get("workflow_events") or []:
        if not isinstance(event, dict) or event.get("node") != "deploy_tool":
            continue
        try:
            node_index = int(event.get("node_index") or 0)
        except Exception:
            continue
        key_results = event.get("key_results") or {}
        deploy_events[node_index] = {
            "deploy_state": bool(key_results.get("deploy_state")),
            "failed_stage": str(key_results.get("failed_stage") or "").strip(),
        }

    advances: List[Dict[str, Any]] = []
    for attempt in state.get("repair_attempts") or []:
        if not isinstance(attempt, dict) or not attempt.get("patched"):
            continue
        try:
            attempt_index = int(attempt.get("attempt_index") or 0)
        except Exception:
            continue
        previous_stage = str(attempt.get("stage") or "").strip()
        next_deploy = deploy_events.get(attempt_index + 1)
        if not previous_stage or previous_stage not in VALID_FAIL_STAGES or not next_deploy:
            continue
        next_success = bool(next_deploy.get("deploy_state"))
        next_stage = str(next_deploy.get("failed_stage") or "").strip()
        if not next_success and next_stage == previous_stage:
            continue
        error_type = str(attempt.get("error_type") or "").strip()
        repair_method = str(attempt.get("repair_method") or "").strip()
        if not error_type or not repair_method:
            continue
        pattern_id = canonical_pattern_id(error_type)
        can_fix = bool(attempt.get("can_fix", True))
        normalized_method = normalize_repair_method(repair_method)
        entry: PatternEntry = {
            "aliases": [error_type] if error_type != pattern_id else [],
            "stage_hints": [previous_stage],
            "can_fix": can_fix,
            "repair_methods": [normalized_method] if can_fix else [],
            "evidence_hint": [],
        }
        if not can_fix:
            entry["handoff"] = normalized_method
        advances.append(
            {
                "stage": previous_stage,
                "observed_error_type": error_type,
                "pattern_id": pattern_id,
                "entry": _sanitize_pattern_entry(entry),
            }
        )
    return advances


class RefinerAgent(BaseAgent):
    agent_name = "Refiner"
    thought_field = "refiner_thought"

    def run(self, state: CaseState, *, enable_reflect_agent: bool) -> CaseState:
        previous_node = str(state.get("last_node") or "")
        refiner_idx = self.node_index(state, self.agent_name)
        refiner_dir = self.node_base_dir(state, self.agent_name, refiner_idx)
        state["last_node"] = self.agent_name
        if not state.get("final_decision"):
            state["final_decision"] = "success" if state.get("deploy_state") else "failed_refine"

        signal = build_error_signal(state)
        record_path = refiner_dir / f"refiner_record_{refiner_idx}.json"
        if not enable_reflect_agent:
            self.set_thought(state, "Reflect agent 未启用，Refiner 仅汇总流程信息。")
            self.write_record(
                record_path,
                {
                    "generated_at": self.now(),
                    "node": self.agent_name,
                    "node_index": refiner_idx,
                    "from_node": previous_node,
                    "inputs": {
                        "deploy_state": state.get("deploy_state"),
                        "failed_stage": state.get("failed_stage"),
                        "deploy": state.get("deploy"),
                        "repair_attempts": state.get("repair_attempts") or [],
                        "workflow_events": state.get("workflow_events") or [],
                    },
                    "thought_process": state.get(self.thought_field),
                    "outputs": {
                        "final_decision": state.get("final_decision"),
                        "reflect_record_path": None,
                        "repair_report_path": None,
                    },
                    "result_params": {
                        "has_repaired": state.get("has_repaired"),
                        "fixed_time": state.get("fixed_time"),
                        "last_error_signature": state.get("last_error_signature"),
                    },
                },
            )
            self.append_workflow_event(
                state,
                node_name=self.agent_name,
                node_index=refiner_idx,
                from_node=previous_node,
                key_results={
                    "final_decision": state.get("final_decision"),
                    "deploy_state": bool(state.get("deploy_state")),
                    "failed_stage": state.get("failed_stage") or "",
                    "has_repaired": state.get("has_repaired"),
                },
            )
            return state

        deploy_payload = state.get("deploy") or {
            "success": bool(state.get("deploy_state")),
            "stage": state.get("failed_stage") or ("success" if state.get("deploy_state") else "unknown"),
            "compile": state.get("compile") or {},
            "load": state.get("load") or {},
            "attach": state.get("attach") or {},
            "runtime": state.get("runtime") or {},
            "detach": state.get("detach") or {},
        }
        kernel_ver = str(((state.get("kernel_profile") or {}).get("kernel_version") or {}).get("raw") or "")
        attempts_yaml = yaml.safe_dump(state.get("repair_attempts") or [], sort_keys=False, allow_unicode=True)
        shared_history_yaml = yaml.safe_dump(state.get("shared_history") or [], sort_keys=False, allow_unicode=True)
        now = self.now()
        kb_enabled = knowledge_base_enabled()
        db_path = knowledge_base_path() if kb_enabled else None
        raw_output = ""
        updates: List[AppendTriple] = []
        added_updates: RepairDb = {}
        if kb_enabled and db_path is not None:
            db = _ensure_repair_db(db_path)
            existing_yaml = yaml.safe_dump(_repair_db_to_yaml_obj(db), sort_keys=False, allow_unicode=True).strip() or "{}"
            system_prompt = REFINER_PROMPT.render(
                {
                    "case_display": state.get("case_display") or "",
                    "kernel_version": kernel_ver,
                    "final_stage": str(deploy_payload.get("stage") or "unknown"),
                    "final_success": str(bool(deploy_payload.get("success"))).lower(),
                    "error_signature_counts": yaml.safe_dump(
                        state.get("error_signature_counts") or {}, sort_keys=True, allow_unicode=True
                    ),
                    "key_lines": "\n".join(signal.key_lines[:30]),
                    "attempts_summary": attempts_yaml,
                    "shared_history": shared_history_yaml,
                    "existing_repair_method": existing_yaml,
                }
            )
            raw_output = self.call_llm(
                system_prompt=system_prompt,
                user_prompt="请输出需要新增到 repair_method.yaml 的 YAML 映射。",
                temperature=0.1,
                max_tokens=900,
            )
            self.set_thought(state, raw_output or "基于 repair_attempts 与 deploy 结果生成知识库总结。")
            updates = self._build_rule_updates(state, raw_output, signal)
            db, added_updates = _merge_rule(db, updates)
            db_path.parent.mkdir(parents=True, exist_ok=True)
            db_path.write_text(
                yaml.safe_dump(_repair_db_to_yaml_obj(db), sort_keys=False, allow_unicode=True),
                encoding="utf-8",
            )
        else:
            self.set_thought(state, "知识库已禁用，Refiner 仅汇总流程信息，不读取或写入 repair_method.yaml。")

        reflect_record_path = Path(state["logs_dir"]) / "reflect_record.json"
        if state.get("write_reflect_record_artifacts", True):
            reflect_record = {
                "generated_at": now,
                "case_display": state.get("case_display"),
                "final": {
                    "success": bool(deploy_payload.get("success")),
                    "stage": deploy_payload.get("stage"),
                    "last_error_signature": state.get("last_error_signature"),
                },
                "input": {
                    "deploy": deploy_payload,
                    "error_signature_counts": state.get("error_signature_counts") or {},
                    "last_error_signature": state.get("last_error_signature"),
                    "key_lines": signal.key_lines[:50],
                    "attempts": state.get("repair_attempts") or [],
                },
                "llm": {
                    "enabled": bool(self.llm is not None),
                    "thought": state.get(self.thought_field),
                },
                "output": {
                    "proposed_updates": _appends_jsonable(updates),
                    "applied_updates": added_updates,
                    "updated_repair_method": str(db_path) if db_path is not None else None,
                },
                "updated_at": now,
            }
            self.write_record(reflect_record_path, reflect_record)
            state["reflect_record_path"] = str(reflect_record_path)
        else:
            state["reflect_record_path"] = None

        repair_report_path: Optional[str] = None
        if not bool(deploy_payload.get("success")):
            repair_report_path = str(Path(state["logs_dir"]) / "repair_report.json")
            self.write_record(
                Path(repair_report_path),
                {
                    "generated_at": now,
                    "case_display": state.get("case_display"),
                    "final_stage": deploy_payload.get("stage"),
                    "same_error_threshold": 3,
                    "error_signature_counts": state.get("error_signature_counts") or {},
                    "attempts": state.get("repair_attempts") or [],
                },
            )
        state["repair_report_path"] = repair_report_path

        self.write_record(
            record_path,
            {
                "generated_at": now,
                "node": self.agent_name,
                "node_index": refiner_idx,
                "from_node": previous_node,
                "inputs": {
                    "deploy_state": state.get("deploy_state"),
                    "failed_stage": state.get("failed_stage"),
                    "deploy": deploy_payload,
                    "repair_attempts": state.get("repair_attempts") or [],
                    "workflow_events": state.get("workflow_events") or [],
                },
                "thought_process": state.get(self.thought_field),
                "outputs": {
                    "final_decision": state.get("final_decision"),
                    "reflect_record_path": state.get("reflect_record_path"),
                    "repair_report_path": state.get("repair_report_path"),
                    "knowledge_base_path": str(db_path) if db_path is not None else None,
                    "applied_updates": added_updates,
                },
                "result_params": {
                    "has_repaired": state.get("has_repaired"),
                    "fixed_time": state.get("fixed_time"),
                    "last_error_signature": state.get("last_error_signature"),
                },
            },
        )
        self.append_workflow_event(
            state,
            node_name=self.agent_name,
            node_index=refiner_idx,
            from_node=previous_node,
            key_results={
                "final_decision": state.get("final_decision"),
                "deploy_state": bool(state.get("deploy_state")),
                "failed_stage": state.get("failed_stage") or "",
                "has_repaired": state.get("has_repaired"),
                "applied_updates_patterns": len(added_updates or {}),
                "applied_updates_total_methods": sum(
                    len((entry or {}).get("repair_methods") or []) for entry in (added_updates or {}).values()
                ),
            },
        )
        return state

    def _build_rule_updates(self, state: CaseState, raw_output: str, signal) -> List[AppendTriple]:
        successful_advances = _collect_successful_stage_advances(state)
        allowed_pattern_ids = {str(item.get("pattern_id") or "").strip() for item in successful_advances}
        allowed_aliases = {str(item.get("observed_error_type") or "").strip() for item in successful_advances}
        yaml_block = self.extract_yaml(raw_output or "")
        if yaml_block:
            try:
                obj = yaml.safe_load(yaml_block)
                normalized = _normalize_repair_method_updates(obj)
                filtered = []
                for pattern_id, entry in normalized:
                    aliases = {str(x).strip() for x in entry.get("aliases") or [] if str(x).strip()}
                    if pattern_id in allowed_pattern_ids or bool(aliases & allowed_aliases):
                        filtered.append((pattern_id, entry))
                if filtered:
                    return filtered
            except Exception:
                pass

        out: List[AppendTriple] = []
        seen: set[str] = set()
        for item in successful_advances:
            pattern_id = str(item.get("pattern_id") or "").strip()
            if not pattern_id or pattern_id in seen:
                continue
            seen.add(pattern_id)
            out.append((pattern_id, dict(item.get("entry") or {})))
        return out
