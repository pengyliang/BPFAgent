from __future__ import annotations

import difflib
import json
import re
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from src.core.config_loader import load_app_config
from src.agent.repair.patterns import ErrorSignal, recognize_error
from src.core.io import write_json
from src.core.llm.openai_compat import OpenAICompatClient, extract_first_message_content
from src.core.state import CaseState
from src.util.deploy.executor import make_deploy_result_summary


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def stage_success(payload: Optional[Dict[str, Any]]) -> bool:
    return bool(isinstance(payload, dict) and payload.get("success"))


def read_text(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return ""


def extract_json_block(text: str) -> Optional[Dict[str, Any]]:
    if not text:
        return None
    fenced = re.search(r"```json\s*\n([\s\S]*?)```", text, flags=re.IGNORECASE)
    if fenced:
        raw = fenced.group(1).strip()
    else:
        open_fence = re.search(r"```json\s*\n([\s\S]*)$", text, flags=re.IGNORECASE)
        raw = open_fence.group(1).strip() if open_fence else text.strip()
    try:
        obj = json.loads(raw)
        return obj if isinstance(obj, dict) else None
    except Exception:
        return None


def extract_code_block(text: str) -> Optional[str]:
    if not text:
        return None
    match = re.search(r"```(?:c)?\s*\n([\s\S]*?)```", text, flags=re.IGNORECASE)
    if match:
        code = match.group(1).strip("\n")
        return code + "\n"
    open_fence = re.search(r"```(?:c)?\s*\n([\s\S]*)$", text, flags=re.IGNORECASE)
    if not open_fence:
        return None
    code = open_fence.group(1).strip("\n")
    return code + "\n"


def extract_yaml_block(text: str) -> Optional[str]:
    if not text:
        return None
    match = re.search(r"```yaml\s*\n([\s\S]*?)```", text, flags=re.IGNORECASE)
    if match:
        return match.group(1).strip() + "\n"
    open_fence = re.search(r"```yaml\s*\n([\s\S]*)$", text, flags=re.IGNORECASE)
    if not open_fence:
        return None
    return open_fence.group(1).strip() + "\n"


def knowledge_base_path() -> Path:
    return Path(__file__).resolve().parents[2] / "knowledge_base" / "repair" / "repair_method.yaml"


def knowledge_base_enabled() -> bool:
    try:
        return bool(load_app_config().agent.knowledge_base_enabled)
    except Exception:
        return True


VALID_FAIL_STAGES = {
    "static_check_failed",
    "compile_failed",
    "load_failed",
    "attach_failed",
    "runtime_test_failed",
}

LEGACY_ERROR_TYPE_TO_PATTERN_ID = {
    "attach_target_not_found": "attach_target_missing",
    "missing_attach_target": "attach_target_missing",
    "program_type_min_kernel": "attach_type_unsupported",
    "program_type_not_supported": "attach_type_unsupported",
    "fentry_fexit_require_btf": "attach_type_unsupported",
    "core_requires_btf": "core_requires_btf",
    "map_feature_incompatible": "map_type_unsupported",
    "map_type_not_in_probe": "map_type_unsupported",
    "missing_header_dependency": "header_dependency_missing",
    "missing_header_include": "header_dependency_missing",
    "missing_linux_types_header": "linux_types_definition_missing",
    "missing_bpf_map_type_definition": "bpf_map_constant_missing",
    "load_verifier_rejection": "verifier_rejection_generic",
    "verifier_reject": "verifier_rejection_generic",
    "invalid_mem_access": "verifier_memory_bounds",
    "reg_type_mismatch": "verifier_reg_type_mismatch",
    "unknown_func": "helper_unsupported",
    "invalid_map_type": "map_type_unsupported",
    "runtime_validation_failed": "runtime_semantic_mismatch",
    "runtime_validation_mismatch": "runtime_semantic_mismatch",
    "workload_not_found": "external_runtime_dependency_missing",
    "validator_not_found": "external_runtime_dependency_missing",
}


def _slugify_pattern_id(text: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9]+", "_", str(text or "").strip()).strip("_").lower()
    return slug or "unknown_pattern"


def canonical_pattern_id(error_type: str) -> str:
    raw = str(error_type or "").strip()
    if not raw:
        return "unknown_pattern"
    return LEGACY_ERROR_TYPE_TO_PATTERN_ID.get(raw, _slugify_pattern_id(raw))


def error_type_from_signature(error_signature: Optional[str]) -> str:
    raw = str(error_signature or "").strip()
    if not raw:
        return ""
    if ":" not in raw:
        return raw
    return raw.split(":", 1)[-1].strip()


def normalize_string_list(raw: Any) -> List[str]:
    values = raw if isinstance(raw, list) else [raw]
    out: List[str] = []
    seen: set[str] = set()
    for item in values:
        if not isinstance(item, str):
            continue
        text = re.sub(r"\s+", " ", item).strip()
        if not text or text in seen:
            continue
        seen.add(text)
        out.append(text)
    return out


def parse_can_fix_method(text: str) -> tuple[Optional[bool], str]:
    raw = str(text or "").strip()
    m = re.match(r"^can_fix\s*=\s*(true|false)\s*\+\s*(.*)$", raw, flags=re.IGNORECASE)
    if not m:
        return None, raw
    return m.group(1).lower() == "true", m.group(2).strip()


def normalize_repair_method(text: str) -> str:
    _, body = parse_can_fix_method(text)
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
    return body


def _default_rule_can_fix(stage: str, error_type: str, methods: List[str]) -> bool:
    parsed = [flag for flag, _ in (parse_can_fix_method(x) for x in methods) if flag is not None]
    if parsed:
        return parsed[0]
    if stage == "static_check_failed" and error_type in {
        "attach_target_not_found",
        "missing_attach_target",
        "program_type_min_kernel",
        "program_type_not_supported",
        "fentry_fexit_require_btf",
    }:
        return False
    if stage == "runtime_test_failed" and error_type in {"workload_not_found", "validator_not_found"}:
        return False
    return True


def _normalize_pattern_entry(
    pattern_id: str,
    raw: Dict[str, Any],
    *,
    fallback_stage: Optional[str] = None,
    fallback_aliases: Optional[List[str]] = None,
    fallback_methods: Optional[List[str]] = None,
) -> Optional[tuple[str, Dict[str, Any]]]:
    pid = canonical_pattern_id(pattern_id)
    aliases = normalize_string_list(raw.get("aliases"))
    for alias in fallback_aliases or []:
        if alias and alias != pid and alias not in aliases:
            aliases.append(alias)

    stage_hints = [s for s in normalize_string_list(raw.get("stage_hints")) if s in VALID_FAIL_STAGES]
    if fallback_stage and fallback_stage in VALID_FAIL_STAGES and fallback_stage not in stage_hints:
        stage_hints.append(fallback_stage)

    summary = str(raw.get("summary") or "").strip()
    evidence_hint = normalize_string_list(raw.get("evidence_hint"))
    handoff = str(raw.get("handoff") or "").strip()

    method_sources: List[str] = []
    method_sources.extend(normalize_string_list(raw.get("repair_methods")))
    method_sources.extend(normalize_string_list(raw.get("repair_method")))
    method_sources.extend(normalize_string_list(fallback_methods or []))

    parsed_flags: List[bool] = []
    methods: List[str] = []
    for item in method_sources:
        can_fix_flag, _ = parse_can_fix_method(item)
        if can_fix_flag is not None:
            parsed_flags.append(can_fix_flag)
        normalized = normalize_repair_method(item)
        if normalized and normalized not in methods:
            methods.append(normalized)

    can_fix_raw = raw.get("can_fix")
    if isinstance(can_fix_raw, bool):
        can_fix = can_fix_raw
    elif parsed_flags:
        can_fix = parsed_flags[0]
    elif fallback_stage:
        can_fix = _default_rule_can_fix(fallback_stage, str((fallback_aliases or [pid])[0]), method_sources)
    else:
        can_fix = True

    if not summary and not aliases and not stage_hints and not methods and not handoff:
        return None

    entry: Dict[str, Any] = {
        "summary": summary,
        "aliases": aliases,
        "stage_hints": stage_hints,
        "can_fix": bool(can_fix),
        "evidence_hint": evidence_hint,
        "repair_methods": methods,
    }
    if handoff:
        entry["handoff"] = handoff
    return pid, entry


def normalize_repair_knowledge_obj(obj: Any) -> Dict[str, Any]:
    if not isinstance(obj, dict):
        return {"version": 2, "patterns": {}}

    patterns_raw = obj.get("patterns")
    if isinstance(patterns_raw, dict):
        normalized_patterns: Dict[str, Any] = {}
        for pattern_id, raw in patterns_raw.items():
            if not isinstance(raw, dict):
                continue
            normalized = _normalize_pattern_entry(str(pattern_id or ""), raw)
            if normalized is None:
                continue
            pid, entry = normalized
            normalized_patterns[pid] = entry
        return {"version": 2, "patterns": normalized_patterns}

    normalized_patterns = {}
    for stage, mapping in obj.items():
        if stage not in VALID_FAIL_STAGES or not isinstance(mapping, dict):
            continue
        for error_type, raw_methods in mapping.items():
            alias = str(error_type or "").strip()
            if not alias:
                continue
            methods = normalize_string_list(raw_methods)
            normalized = _normalize_pattern_entry(
                alias,
                {},
                fallback_stage=str(stage),
                fallback_aliases=[alias],
                fallback_methods=methods,
            )
            if normalized is None:
                continue
            pid, entry = normalized
            existing = normalized_patterns.get(pid)
            if not existing:
                normalized_patterns[pid] = entry
                continue
            for alias_item in entry.get("aliases", []):
                if alias_item not in existing["aliases"]:
                    existing["aliases"].append(alias_item)
            for stage_item in entry.get("stage_hints", []):
                if stage_item not in existing["stage_hints"]:
                    existing["stage_hints"].append(stage_item)
            for method_item in entry.get("repair_methods", []):
                if method_item not in existing["repair_methods"]:
                    existing["repair_methods"].append(method_item)
            if not existing.get("handoff") and entry.get("handoff"):
                existing["handoff"] = entry["handoff"]
            existing["can_fix"] = bool(existing.get("can_fix", True) and entry.get("can_fix", True))
    return {"version": 2, "patterns": normalized_patterns}


def _select_pattern_subset(knowledge_obj: Dict[str, Any], stage: str, error_signature: Optional[str], key_lines: Optional[List[str]]) -> Dict[str, Any]:
    patterns = knowledge_obj.get("patterns") if isinstance(knowledge_obj, dict) else None
    if not isinstance(patterns, dict):
        return {"version": 2, "patterns": {}}

    query_error_type = error_type_from_signature(error_signature)
    canonical_query = canonical_pattern_id(query_error_type) if query_error_type else ""
    query_lines = "\n".join(key_lines or []).lower()

    scored: List[tuple[int, str, Dict[str, Any]]] = []
    for pattern_id, entry in patterns.items():
        if not isinstance(entry, dict):
            continue
        aliases = {str(x).strip() for x in entry.get("aliases") or [] if str(x).strip()}
        stage_hints = {str(x).strip() for x in entry.get("stage_hints") or [] if str(x).strip()}
        evidence_hint = [str(x).strip().lower() for x in entry.get("evidence_hint") or [] if str(x).strip()]

        score = 0
        if query_error_type:
            if pattern_id == query_error_type:
                score += 100
            if canonical_query and pattern_id == canonical_query:
                score += 90
            if query_error_type in aliases:
                score += 80
            if canonical_query and canonical_query in aliases:
                score += 70
        if stage and stage in stage_hints:
            score += 20
        if query_lines:
            score += sum(8 for token in evidence_hint if token and token in query_lines)
        if score > 0:
            scored.append((score, str(pattern_id), entry))

    if not scored:
        fallback = []
        for pattern_id, entry in patterns.items():
            if not isinstance(entry, dict):
                continue
            if stage and stage in set(entry.get("stage_hints") or []):
                fallback.append((10, str(pattern_id), entry))
        scored = fallback or [(0, str(pattern_id), entry) for pattern_id, entry in patterns.items() if isinstance(entry, dict)]

    selected: Dict[str, Any] = {}
    for _, pattern_id, entry in sorted(scored, key=lambda item: (-item[0], item[1]))[:5]:
        selected[pattern_id] = entry
    return {"version": 2, "patterns": selected}


def load_knowledge_rules(stage: str, error_signature: Optional[str], key_lines: Optional[List[str]] = None) -> str:
    if not knowledge_base_enabled():
        return ""
    kb_path = knowledge_base_path()
    if not kb_path.exists():
        return ""
    try:
        obj = yaml.safe_load(kb_path.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return kb_path.read_text(encoding="utf-8", errors="ignore")
    normalized = normalize_repair_knowledge_obj(obj)
    selected = _select_pattern_subset(normalized, stage, error_signature, key_lines)
    return yaml.safe_dump(selected, sort_keys=False, allow_unicode=True).strip()


def static_issue_codes(payload: Dict[str, Any]) -> List[str]:
    issues = payload.get("issues") if isinstance(payload, dict) else []
    codes: list[str] = []
    if not isinstance(issues, list):
        return codes
    for item in issues:
        if not isinstance(item, dict):
            continue
        code = str(item.get("code") or "").strip()
        if code:
            codes.append(code)
    return codes


def static_check_requires_environment_change(payload: Dict[str, Any]) -> bool:
    issue_codes = set(static_issue_codes(payload))
    unfixable_codes = {
        "attach_target_not_found",
        "missing_attach_target",
        "program_type_min_kernel",
        "program_type_not_supported",
        "fentry_fexit_require_btf",
    }
    return bool(issue_codes & unfixable_codes)


def default_can_fix(stage: str, failed_payload: Dict[str, Any]) -> bool:
    if not stage:
        return False
    if stage == "detach_failed":
        return False
    if stage == "static_check_failed" and static_check_requires_environment_change(failed_payload):
        return False
    if stage == "runtime_test_failed":
        reason = str((failed_payload or {}).get("reason") or "")
        if reason in {"workload_not_found", "validator_not_found"}:
            return False
    return stage in {
        "static_check_failed",
        "compile_failed",
        "load_failed",
        "attach_failed",
        "runtime_test_failed",
    }


def summarize_static_failure(payload: Dict[str, Any]) -> ErrorSignal:
    issues = payload.get("issues") if isinstance(payload, dict) else []
    key_lines: list[str] = []
    error_types: list[str] = []
    if isinstance(issues, list):
        for item in issues[:10]:
            if not isinstance(item, dict):
                continue
            issue_type = str(item.get("code") or item.get("type") or item.get("kind") or "static_issue")
            message = str(item.get("message") or item.get("reason") or issue_type)
            error_types.append(issue_type)
            key_lines.append(message)
    if not error_types:
        error_types = ["static_check_error"]
    return ErrorSignal(
        stage="static_check_failed",
        error_types=error_types[:5],
        key_lines=key_lines[:20],
        raw_log=json.dumps(payload or {}, ensure_ascii=False, indent=2),
    )


def summarize_generic_failure(stage: str, payload: Dict[str, Any]) -> ErrorSignal:
    parts = []
    for key in ("error_message", "error_log", "stderr", "stdout", "reason"):
        value = payload.get(key) if isinstance(payload, dict) else None
        if value:
            parts.append(str(value))
    raw = "\n".join(parts)
    key_lines = [ln.strip() for ln in raw.splitlines() if ln.strip()][:20]
    return ErrorSignal(
        stage=stage or "unknown",
        error_types=[stage or "unknown"],
        key_lines=key_lines,
        raw_log=raw,
    )


def build_error_signal(state: CaseState) -> ErrorSignal:
    deploy = state.get("deploy") or {}
    stage = str(state.get("failed_stage") or deploy.get("stage") or "")
    if stage in {"compile_failed", "load_failed", "attach_failed"}:
        return recognize_error(deploy)
    failed_payload = state.get("failed_stage_result") or {}
    if stage == "static_check_failed":
        return summarize_static_failure(failed_payload)
    return summarize_generic_failure(stage, failed_payload)


def stage_result_path(state: CaseState, stage: str) -> Optional[str]:
    mapping = {
        "static_check_failed": state.get("static_check_path"),
        "compile_failed": state.get("compile_result_path"),
        "load_failed": state.get("load_result_path"),
        "attach_failed": state.get("attach_result_path"),
        "runtime_test_failed": state.get("runtime_result_path"),
        "detach_failed": state.get("detach_result_path"),
    }
    value = mapping.get(stage)
    return str(value) if value else None


def set_failed_payload(state: CaseState, stage: str) -> None:
    payload_map = {
        "static_check_failed": state.get("static_check") or {},
        "compile_failed": state.get("compile") or {},
        "load_failed": state.get("load") or {},
        "attach_failed": state.get("attach") or {},
        "runtime_test_failed": state.get("runtime") or {},
        "detach_failed": state.get("detach") or {},
    }
    state["failed_stage_result"] = payload_map.get(stage, {}) or {}
    state["failed_stage_result_path"] = stage_result_path(state, stage)


def rough_semantic_equivalent(before: str, after: str) -> bool:
    if not before.strip() or not after.strip():
        return False
    before_sections = re.findall(r'SEC\("([^"]+)"\)', before)
    after_sections = re.findall(r'SEC\("([^"]+)"\)', after)
    if before_sections != after_sections:
        return False
    before_lines = max(1, len(before.splitlines()))
    after_lines = max(1, len(after.splitlines()))
    ratio = after_lines / before_lines
    return 0.5 <= ratio <= 1.8


def program_name(state: CaseState) -> str:
    return Path(state["original_source_file"]).name.replace(".bpf.c", "")


def code_change_summary(before: str, after: str) -> str:
    diff_lines = list(
        difflib.unified_diff(
            (before or "").splitlines(),
            (after or "").splitlines(),
            fromfile="before",
            tofile="after",
            lineterm="",
        )
    )
    body = [line for line in diff_lines if line and not line.startswith(("---", "+++", "@@"))]
    if not body:
        return "未检测到有效代码改动。"
    added = sum(1 for line in body if line.startswith("+"))
    removed = sum(1 for line in body if line.startswith("-"))
    preview = "\n".join(body[:12])
    return f"新增 {added} 行，删除 {removed} 行。\n{preview}"


def deploy_summary_payload(state: CaseState) -> Dict[str, Any]:
    deploy = state.get("deploy") or {}
    return make_deploy_result_summary(deploy)


def advance_pipeline_paths(state: CaseState, *, next_pipeline: int) -> None:
    if next_pipeline < 1:
        next_pipeline = 1
    logs_dir = Path(state["logs_dir"])
    error_solve_dir = Path(state["error_solve_dir"])
    artifact_stem = str(state.get("artifact_stem") or "")
    stage_dir = logs_dir / "deploy" / f"deploy_{next_pipeline}"
    retry_code_dir = error_solve_dir / f"repair_{next_pipeline}"

    def p(name: str) -> str:
        suffix = f"_{artifact_stem}" if artifact_stem else ""
        return str(stage_dir / f"{name}{suffix}.json")

    state["pipeline_index"] = next_pipeline
    state["attempt_index"] = next_pipeline
    state["retry_code_dir"] = str(retry_code_dir)
    state["static_check_path"] = p("static_check")
    state["compile_result_path"] = p("compile_result")
    state["load_result_path"] = p("load_result")
    state["attach_result_path"] = p("attach_result")
    state["runtime_result_path"] = p("runtime_result")
    state["detach_result_path"] = p("detach_result")
    state["deploy_result_path"] = p("deploy_summary")


@dataclass(frozen=True)
class WorkflowArtifacts:
    compile_path: Path
    load_path: Path
    attach_path: Path
    runtime_path: Path
    detach_path: Path


def artifact_paths(state: CaseState) -> WorkflowArtifacts:
    return WorkflowArtifacts(
        compile_path=Path(state["compile_result_path"]),
        load_path=Path(state["load_result_path"]),
        attach_path=Path(state["attach_result_path"]),
        runtime_path=Path(state["runtime_result_path"]),
        detach_path=Path(state["detach_result_path"]),
    )


class BaseAgent:
    agent_name = "BaseAgent"
    thought_field = ""

    _WORKFLOW_REPAIRER_KEYS = frozenset(
        {
            "outcome",
            "reason",
            "note",
            "llm_enabled",
            "patched",
            "final_decision",
            "next_deploy_index",
        }
    )

    def __init__(self, *, llm: Optional[OpenAICompatClient]):
        self.llm = llm
        self._last_llm_response_meta: Dict[str, Any] = {}

    def call_llm(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        temperature: float,
        max_tokens: int,
    ) -> str:
        if self.llm is None:
            return ""
        if not getattr(self.llm, "show_terminal_output", True):
            resp = self.llm.chat_completions(
                messages=[{"role": "system", "content": system_prompt}, {"role": "user", "content": user_prompt}],
                temperature=temperature,
                max_tokens=max_tokens,
                stream=True,
            )
            self._last_llm_response_meta = dict((resp or {}).get("stream_meta") or {})
            return extract_first_message_content(resp) or ""
        printed = False
        reasoning_printed = False
        first_chunk_event = threading.Event()
        finished_event = threading.Event()

        def _warn_if_silent() -> None:
            if not first_chunk_event.wait(timeout=10.0) and not finished_event.is_set():
                print(f"\n[{self.agent_name}] 模型 10s 内没有任何输出，可能已超时或首包较慢。", flush=True)

        def _on_delta(chunk: str) -> None:
            nonlocal printed
            first_chunk_event.set()
            if not printed:
                print(f"\n[{self.agent_name}] 模型实时输出:")
                printed = True
            print(chunk, end="", flush=True)

        def _on_reasoning_delta(chunk: str) -> None:
            nonlocal reasoning_printed
            first_chunk_event.set()
            if not reasoning_printed:
                print(f"\n[{self.agent_name}] 模型思考过程:", flush=True)
                reasoning_printed = True
            print(chunk, end="", flush=True)

        watcher = threading.Thread(target=_warn_if_silent, daemon=True)
        watcher.start()
        resp = self.llm.chat_completions(
            messages=[{"role": "system", "content": system_prompt}, {"role": "user", "content": user_prompt}],
            temperature=temperature,
            max_tokens=max_tokens,
            stream=True,
            on_delta=_on_delta,
            on_reasoning_delta=_on_reasoning_delta,
        )
        self._last_llm_response_meta = dict((resp or {}).get("stream_meta") or {})
        finished_event.set()
        if reasoning_printed:
            print("")
        if printed:
            print("")
        return extract_first_message_content(resp) or ""

    def last_llm_response_meta(self) -> Dict[str, Any]:
        return dict(self._last_llm_response_meta or {})

    def now(self) -> str:
        return utc_now()

    def extract_json(self, text: str) -> Optional[Dict[str, Any]]:
        return extract_json_block(text)

    def extract_code(self, text: str) -> Optional[str]:
        return extract_code_block(text)

    def extract_yaml(self, text: str) -> Optional[str]:
        return extract_yaml_block(text)

    def set_thought(self, state: CaseState, text: str) -> None:
        if self.thought_field:
            state[self.thought_field] = text

    def node_index(self, state: CaseState, node_name: str) -> int:
        counts = state.setdefault("node_run_counts", {})
        current = int(counts.get(node_name) or 0) + 1
        counts[node_name] = current
        return current

    def node_base_dir(self, state: CaseState, node_name: str, idx: int) -> Path:
        if node_name == "deploy_tool":
            root = Path(state["logs_dir"]) / "deploy" / f"deploy_{idx}"
            root.mkdir(parents=True, exist_ok=True)
            return root
        folder_map = {
            "Analyzer": "analyzer",
            "Repairer": "repair",
            "Inspector": "inspector",
            "Refiner": "refiner",
        }
        dir_map = {
            "Analyzer": f"analyzer_{idx}",
            "Repairer": f"repair_{idx}",
            "Inspector": f"inspector_{idx}",
            "Refiner": f"refiner_{idx}",
        }
        root = Path(state["logs_dir"]) / folder_map[node_name] / dir_map[node_name]
        root.mkdir(parents=True, exist_ok=True)
        return root

    def append_workflow_event(
        self,
        state: CaseState,
        *,
        node_name: str,
        node_index: int,
        from_node: str,
        key_results: Dict[str, Any],
    ) -> None:
        events = state.setdefault("workflow_events", [])
        # 去掉 workflow_summary 里的所有文件路径信息，只保留 agent 输出本身。
        sanitized_key_results: Dict[str, Any] = {}
        if node_name == "Repairer":
            for k, v in (key_results or {}).items():
                if isinstance(k, str) and k in self._WORKFLOW_REPAIRER_KEYS:
                    if isinstance(v, str):
                        sanitized_key_results[k] = self._clip_text(v, limit=200)
                    else:
                        sanitized_key_results[k] = v
        else:
            for k, v in (key_results or {}).items():
                if not isinstance(k, str):
                    continue
                lk = k.lower()
                if "path" in lk or "file" in lk or lk.endswith("_file"):
                    continue
                sanitized_key_results[k] = v

        event = {
            "seq": len(events) + 1,
            "ts": utc_now(),
            "node": node_name,
            "node_index": node_index,
            "key_results": sanitized_key_results,
        }
        events.append(event)
        summary = {
            "generated_at": events[0]["ts"] if events else utc_now(),
            "updated_at": utc_now(),
            "final_decision": state.get("final_decision"),
            "deploy_state": state.get("deploy_state"),
            "failed_stage": state.get("failed_stage"),
            "events": events,
        }
        write_json(Path(state["logs_dir"]) / "workflow_summary.json", summary)

    def append_error_record(self, state: CaseState, item: Dict[str, Any]) -> None:
        if not state.get("write_repair_error_record", True):
            return
        record_path = Path(state["error_record_path"])
        if record_path.exists():
            try:
                record = json.loads(record_path.read_text(encoding="utf-8", errors="ignore"))
                if not isinstance(record, dict):
                    record = {}
            except Exception:
                record = {}
        else:
            record = {}
        attempts = record.setdefault("attempts", [])
        if isinstance(attempts, list):
            attempts.append(item)
        record.setdefault("case_display", state.get("case_display") or "")
        record["last_error_signature"] = state.get("last_error_signature")
        record_path.parent.mkdir(parents=True, exist_ok=True)
        record_path.write_text(json.dumps(record, indent=2, ensure_ascii=False), encoding="utf-8")

    def write_record(self, path: Path, payload: Dict[str, Any]) -> str:
        return write_json(path, payload)

    def _clip_text(self, value: Any, *, limit: int = 400) -> str:
        text = str(value or "").strip()
        if len(text) <= limit:
            return text
        return text[:limit] + "...(truncated)"

    def _compact_value(self, value: Any, *, depth: int = 0) -> Any:
        if depth >= 3:
            if isinstance(value, (dict, list)):
                return self._clip_text(json.dumps(value, ensure_ascii=False), limit=240)
            return self._clip_text(value, limit=240)
        if isinstance(value, dict):
            compact: Dict[str, Any] = {}
            for idx, (key, item) in enumerate(value.items()):
                if idx >= 12:
                    compact["..."] = f"trimmed {len(value) - 12} fields"
                    break
                compact[str(key)] = self._compact_value(item, depth=depth + 1)
            return compact
        if isinstance(value, list):
            compact_list = [self._compact_value(item, depth=depth + 1) for item in value[:8]]
            if len(value) > 8:
                compact_list.append(f"... trimmed {len(value) - 8} items")
            return compact_list
        if isinstance(value, str):
            return self._clip_text(value, limit=240)
        return value

    def _history_line(self, entry: Dict[str, Any]) -> str:
        node = str(entry.get("node") or "unknown")
        node_index = entry.get("node_index")
        summary = self._clip_text(entry.get("summary") or "", limit=200)
        if node == "HistoryDigest":
            return f"{node}: {summary}"
        return f"{node}#{node_index}: {summary}" if node_index is not None else f"{node}: {summary}"

    def _compress_history(self, history: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        max_entries = 8
        keep_recent = 6
        if len(history) <= max_entries:
            return history
        older = history[:-keep_recent]
        recent = history[-keep_recent:]
        lines = [self._history_line(entry) for entry in older]
        digest = {
            "ts": utc_now(),
            "node": "HistoryDigest",
            "summary": self._clip_text("\n".join(lines), limit=1200),
        }
        return [digest, *recent]

    def render_shared_history(self, state: CaseState) -> str:
        history = state.get("shared_history") or []
        if not history:
            return "[]"
        return json.dumps(history, ensure_ascii=False, indent=2)

    def append_shared_history(
        self,
        state: CaseState,
        *,
        node_name: str,
        node_index: int,
        from_node: str,
        inputs: Dict[str, Any],
        outputs: Dict[str, Any],
        thought_process: Any,
        summary: str,
    ) -> None:
        history = list(state.get("shared_history") or [])
        history.append(
            {
                "ts": utc_now(),
                "node": node_name,
                "node_index": node_index,
                "from_node": from_node,
                "summary": self._clip_text(summary, limit=320),
                "inputs": self._compact_value(inputs),
                "outputs": self._compact_value(outputs),
                "thought_process": self._clip_text(thought_process, limit=320),
            }
        )
        compressed = self._compress_history(history)
        state["shared_history"] = compressed
        history_path = Path(state["shared_history_path"])
        payload = {
            "case_display": state.get("case_display"),
            "updated_at": utc_now(),
            "history": compressed,
        }
        history_path.parent.mkdir(parents=True, exist_ok=True)
        history_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
