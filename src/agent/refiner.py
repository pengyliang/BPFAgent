from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

from prompts.refiner import REFINER_PROMPT
from src.agent.base import BaseAgent, build_error_signal, knowledge_base_path
from src.core.state import CaseState


def _slugify(text: str) -> str:
    s = re.sub(r"[^a-zA-Z0-9]+", "_", (text or "").strip()).strip("_").lower()
    return s or "rule"


VALID_FAIL_STAGES = {
    "static_check_failed",
    "compile_failed",
    "load_failed",
    "attach_failed",
    "runtime_test_failed",
}


def _parse_can_fix_prefix(text: str) -> tuple[Optional[bool], str]:
    raw = str(text or "").strip()
    m = re.match(r"^can_fix\s*=\s*(true|false)\s*\+\s*(.*)$", raw, flags=re.IGNORECASE)
    if not m:
        return None, raw
    return m.group(1).lower() == "true", m.group(2).strip()


def _normalize_method_text(text: str, *, default_can_fix: bool) -> str:
    _, body = _parse_can_fix_prefix(text)
    body = re.sub(r"\s+", " ", body).strip()
    if "具体步骤" in body:
        body = body.split("具体步骤", 1)[0].rstrip(" ：:，,；;。")
    body = re.sub(r"^[0-9]+[.)、]\s*", "", body)
    parts = [p.strip(" ，,；;。") for p in re.split(r"[。；;!?！？]", body) if p.strip(" ，,；;。")]
    body = "。".join(parts[:2]).strip()
    if not body:
        body = "按当前失败阶段采取最小必要修复。"
    elif not body.endswith("。"):
        body = body + "。"
    return f"can_fix={'true' if default_can_fix else 'false'}+{body}"


RepairDb = Dict[str, Dict[str, List[str]]]
AppendTriple = Tuple[str, str, str]


def _dedupe_preserve_order(items: List[str]) -> List[str]:
    seen: set[str] = set()
    out: List[str] = []
    for x in items:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def _ingest_raw_methods(raw: Any) -> List[str]:
    if isinstance(raw, str):
        t = raw.strip()
        if not t:
            return []
        return [_normalize_method_text(t, default_can_fix=True)]
    if isinstance(raw, list):
        out: List[str] = []
        for x in raw:
            if isinstance(x, str) and x.strip():
                out.append(_normalize_method_text(x.strip(), default_can_fix=True))
        return _dedupe_preserve_order(out)
    return []


def _mapping_value_to_appends(stage: str, et: str, val: Any) -> List[AppendTriple]:
    """仅支持标量字符串或字符串列表；合并侧一律做「在 error_type 下增量追加（规范化后精确去重）」。"""
    out: List[AppendTriple] = []
    if isinstance(val, str):
        m = _normalize_method_text(val.strip(), default_can_fix=True)
        if m:
            out.append((stage, et, m))
        return out
    if isinstance(val, list):
        for item in val:
            if isinstance(item, str):
                m = _normalize_method_text(item.strip(), default_can_fix=True)
                if m:
                    out.append((stage, et, m))
        return out
    return out


def _ensure_repair_db(path: Path) -> RepairDb:
    if path.exists():
        try:
            obj = yaml.safe_load(path.read_text(encoding="utf-8", errors="ignore"))
            if isinstance(obj, dict):
                cleaned: RepairDb = {}
                for stage, mapping in obj.items():
                    if stage not in VALID_FAIL_STAGES or not isinstance(mapping, dict):
                        continue
                    entries: Dict[str, List[str]] = {}
                    for error_type, raw in mapping.items():
                        key = str(error_type or "").strip()
                        if not key:
                            continue
                        methods = _ingest_raw_methods(raw)
                        if methods:
                            entries[key] = methods
                    if entries:
                        cleaned[str(stage)] = entries
                return cleaned
        except Exception:
            pass
    return {}


def _repair_db_to_yaml_obj(db: RepairDb) -> Dict[str, Any]:
    """写出时保持层级：fail_stage → error_type → methods（YAML 列表）。"""
    out: Dict[str, Any] = {}
    for stage, smap in db.items():
        stage_out: Dict[str, Any] = {}
        for et, methods in smap.items():
            if methods:
                stage_out[et] = list(methods)
        if stage_out:
            out[stage] = stage_out
    return out


def _normalize_repair_method_updates(obj: Any) -> List[AppendTriple]:
    result: List[AppendTriple] = []
    if not isinstance(obj, dict):
        return result
    for stage, mapping in obj.items():
        stage_name = str(stage or "").strip()
        if stage_name not in VALID_FAIL_STAGES or not isinstance(mapping, dict):
            continue
        for error_type, val in mapping.items():
            et = str(error_type or "").strip()
            if not et:
                continue
            result.extend(_mapping_value_to_appends(stage_name, et, val))
    return result


def _merge_rule(db: RepairDb, appends: List[AppendTriple]) -> tuple[RepairDb, RepairDb]:
    """在各自 error_type 下追加 method；是否与已有条目语义重复由 Refiner 提示词约束，此处只做规范化后的精确去重。"""
    added: RepairDb = {}
    for stage, et, method in appends:
        if not method.strip():
            continue
        stage_bucket = db.setdefault(stage, {})
        before = list(stage_bucket.get(et, []))
        cur = list(before)
        if method not in cur:
            cur.append(method)
        if cur == before:
            continue
        stage_bucket[et] = cur
        added.setdefault(stage, {})[et] = list(cur)
    return db, added


def _appends_jsonable(appends: List[AppendTriple]) -> List[Dict[str, str]]:
    return [{"stage": s, "error_type": e, "repair_method": m} for s, e, m in appends]


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
        advances.append(
            {
                "stage": previous_stage,
                "error_type": error_type,
                "repair_method": _normalize_method_text(
                    repair_method,
                    default_can_fix=bool(attempt.get("can_fix", True)),
                ),
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
        db_path = knowledge_base_path()
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

        now = self.now()
        updates = self._build_rule_updates(state, raw_output, signal)
        db, added_updates = _merge_rule(db, updates)
        db_path.parent.mkdir(parents=True, exist_ok=True)
        db_path.write_text(
            yaml.safe_dump(_repair_db_to_yaml_obj(db), sort_keys=False, allow_unicode=True),
            encoding="utf-8",
        )

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
                    "updated_repair_method": str(db_path),
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
                    "knowledge_base_path": str(db_path),
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
                "applied_updates_stages": len(added_updates or {}),
                "applied_updates_total_mappings": sum(len(v or {}) for v in (added_updates or {}).values()),
            },
        )
        return state

    def _build_rule_updates(self, state: CaseState, raw_output: str, signal) -> List[AppendTriple]:
        successful_advances = _collect_successful_stage_advances(state)
        allowed_pairs = {(item["stage"], item["error_type"]) for item in successful_advances}
        yaml_block = self.extract_yaml(raw_output or "")
        if yaml_block:
            try:
                obj = yaml.safe_load(yaml_block)
                normalized = _normalize_repair_method_updates(obj)
                filtered = [(s, e, m) for s, e, m in normalized if (s, e) in allowed_pairs]
                if filtered:
                    return filtered
            except Exception:
                pass

        out: List[AppendTriple] = []
        seen: set[tuple[str, str]] = set()
        for item in successful_advances:
            st, et = item["stage"], item["error_type"]
            if (st, et) in seen:
                continue
            seen.add((st, et))
            out.append((st, et, item["repair_method"]))
        return out
