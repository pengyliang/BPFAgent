from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, TypedDict


class CaseState(TypedDict, total=False):
    # identity & paths
    category: str
    case_rel: str
    case_display: str
    logs_dir: str
    build_dir: str
    shared_logs_dir: str
    kernel_profile: Dict[str, Any]
    artifact_stem: str

    # files (mutable during repair)
    original_source_file: str
    current_source_file: str
    candidate_source_file: Optional[str]
    object_file: str
    pin_path: str
    program_type: Optional[str]
    vmlinux_header_dir: Optional[str]

    # artifact paths
    static_check_path: str
    compile_result_path: str
    load_result_path: str
    attach_result_path: str
    runtime_result_path: str
    detach_result_path: str
    deploy_result_path: str
    retry_code_dir: str
    error_solve_dir: str
    error_record_path: str
    shared_history_path: str

    # in-memory stage payloads
    static_check: Dict[str, Any]
    compile: Dict[str, Any]
    load: Dict[str, Any]
    attach: Dict[str, Any]
    runtime: Dict[str, Any]
    detach: Dict[str, Any]
    deploy: Dict[str, Any]
    failed_stage_result: Dict[str, Any]
    failed_stage_result_path: Optional[str]

    # workflow control
    pipeline_index: int
    attempt_index: int
    load_backend_attempt: int
    patch_history: List[str]
    repair_attempts: List[Dict[str, Any]]
    retry_code_paths: List[str]
    error_signature_counts: Dict[str, int]
    last_error_signature: Optional[str]
    failed_stage: str
    deploy_state: bool
    has_repaired: bool
    fixed_time: int
    max_fix_time: int
    last_node: str
    can_fix: bool
    semantic_equivalent: Optional[bool]
    final_decision: str  # success|failed_refine|failed_no_patch

    # agent outputs
    analysis_report: str
    repair_action: Dict[str, Any]
    inspector_report: str
    last_code_change_summary: str
    analyzer_thought: str
    repairer_thought: str
    inspector_thought: str
    refiner_thought: str
    last_inspector_context: Dict[str, Any]
    shared_history: List[Dict[str, Any]]

    # persisted workflow traces
    node_run_counts: Dict[str, int]
    workflow_events: List[Dict[str, Any]]

    # reports
    repair_report_path: Optional[str]
    reflect_record_path: Optional[str]

    # internal runtime context
    _load_backend: Optional[str]
    _load_process: Any

    # output control flags
    write_repair_error_record: bool
    write_reflect_record_artifacts: bool


@dataclass(frozen=True)
class CasePaths:
    logs_dir: Path
    build_dir: Path
    shared_logs_dir: Path

    def ensure_dirs(self) -> None:
        self.logs_dir.mkdir(parents=True, exist_ok=True)
        self.build_dir.mkdir(parents=True, exist_ok=True)

