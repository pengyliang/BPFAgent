from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional

from langgraph.graph import END, StateGraph

from src.agent.analyzer import AnalyzerAgent
from src.agent.base import (
    BaseAgent,
    artifact_paths,
    deploy_summary_payload,
    set_failed_payload,
    stage_success,
)
from src.agent.inspector import InspectorAgent
from src.agent.refiner import RefinerAgent
from src.agent.repairer import RepairerAgent
from src.core.coordinator import Coordinator, stable_error_signature
from src.core.io import write_json
from src.core.state import CasePaths, CaseState
from src.util.static_check.ast_summary import build_static_check_summaries


SAME_ERROR_THRESHOLD = 4
MAX_REPAIR_ATTEMPTS = 3


def _inc_signature(state: CaseState, sig: str) -> int:
    counts = state.setdefault("error_signature_counts", {})
    cur = int(counts.get(sig) or 0) + 1
    counts[sig] = cur
    state["last_error_signature"] = sig
    return cur


def _attempt_progress(state: CaseState) -> str:
    current = int(state.get("fixed_time") or 0)
    maximum = int(state.get("max_fix_time") or MAX_REPAIR_ATTEMPTS)
    return f"[{current}/{maximum}]"


def _final_result_text(state: CaseState) -> str:
    if state.get("final_decision") == "success":
        return "success"
    failed_stage = str(state.get("failed_stage") or "")
    if failed_stage:
        return failed_stage
    return str(state.get("final_decision") or "failed")


def _print_limit_redirect(message: str) -> None:
    print(f"达到上限，转入 Refiner: {message}")


def build_case_graph(
    *,
    coordinator: Coordinator,
    enable_resolve_agent: bool = True,
    enable_inspector_agent: bool = True,
    enable_reflect_agent: bool = False,
    use_pipeline_dirs: bool = False,
):
    g: StateGraph = StateGraph(CaseState)
    llm = getattr(coordinator, "llm", None)
    helper = BaseAgent(llm=None)
    analyzer = AnalyzerAgent(llm=llm)
    repairer = RepairerAgent(llm=llm)
    inspector = InspectorAgent(llm=llm)
    refiner = RefinerAgent(llm=llm)

    def node_end(state: CaseState) -> CaseState:
        previous_node = str(state.get("last_node") or "")
        state["last_node"] = "End"
        if not state.get("final_decision"):
            state["final_decision"] = "success" if state.get("deploy_state") else "failed_refine"
        print(f"结果: {_final_result_text(state)}")
        helper.append_workflow_event(
            state,
            node_name="End",
            node_index=len(state.get("workflow_events") or []) + 1,
            from_node=previous_node,
            key_results={
                "final_decision": state.get("final_decision"),
                "deploy_state": state.get("deploy_state"),
                "failed_stage": state.get("failed_stage"),
            },
        )
        return state

    def node_deploy_tool(state: CaseState) -> CaseState:
        previous_node = str(state.get("last_node") or "")
        deploy_idx = helper.node_index(state, "deploy_tool")
        deploy_dir = helper.node_base_dir(state, "deploy_tool", deploy_idx)
        artifacts = artifact_paths(state)
        print("deploy")
        state["last_node"] = "deploy_tool"
        state["candidate_source_file"] = None
        state["semantic_equivalent"] = None
        state["static_check"] = {}
        state["compile"] = {}
        state["load"] = {}
        state["attach"] = {}
        state["runtime"] = {}
        state["detach"] = {}
        state["last_inspector_context"] = {}

        backend = coordinator.choose_loader_backend(
            attempt=int(state.get("load_backend_attempt") or 0),
            last_error_sig=state.get("last_error_signature"),
        )
        proc = None
        state["_load_backend"] = backend
        state["_load_process"] = None

        # 每个 deploy_n 目录固定落盘 static_check.json（与 compile/load 等一致），供回放与 main 汇总读取。
        # 先 clang AST；失败则 ast_fallback，static_checker 退回源码分析。
        static_artifact_dir = Path(state["static_check_path"]).parent
        static_artifact_dir.mkdir(parents=True, exist_ok=True)
        summaries = build_static_check_summaries(
            [state["current_source_file"]],
            artifact_dir=static_artifact_dir,
            vmlinux_header_dir=state.get("vmlinux_header_dir"),
        )
        static_report = coordinator.run_static_check(
            summaries=summaries,
            kernel_profile=state.get("kernel_profile") or {},
            output_path=state["static_check_path"],
        )
        state["static_check"] = static_report or {}

        if stage_success(static_report):
            compile_report = coordinator.run_compile(
                source_file=state["current_source_file"],
                object_file=state["object_file"],
                vmlinux_header_dir=state.get("vmlinux_header_dir"),
            )
            state["compile"] = compile_report or {}
            write_json(artifacts.compile_path, state["compile"])

            if stage_success(compile_report):
                payload = coordinator.run_load_attach(
                    source_file=state["current_source_file"],
                    object_file=str((state.get("compile") or {}).get("object_file") or state["object_file"]),
                    pin_path=state["pin_path"],
                    program_type=state.get("program_type"),
                    backend=backend,
                )
                state["load"] = (payload.get("load") if isinstance(payload, dict) else None) or {}
                state["attach"] = (payload.get("attach") if isinstance(payload, dict) else None) or {}
                proc = payload.get("_process") if isinstance(payload, dict) else None
                state["_load_process"] = proc
                write_json(artifacts.load_path, state["load"])
                write_json(artifacts.attach_path, state["attach"])

                if stage_success(state["load"]) and stage_success(state["attach"]):
                    state["runtime"] = coordinator.run_runtime_test(
                        source_file=state["original_source_file"],
                        pin_path=state["pin_path"],
                        attach_report=state.get("attach"),
                    ) or {}
                else:
                    state["runtime"] = {
                        "success": True,
                        "stage": "runtime_test",
                        "skipped": True,
                        "reason": "load_or_attach_failed",
                    }
                write_json(artifacts.runtime_path, state["runtime"])
            else:
                state["load"] = {"success": True, "stage": "load", "skipped": True, "reason": "compile_failed"}
                state["attach"] = {"success": True, "stage": "attach", "skipped": True, "reason": "compile_failed"}
                state["runtime"] = {
                    "success": True,
                    "stage": "runtime_test",
                    "skipped": True,
                    "reason": "compile_failed",
                }
                write_json(artifacts.load_path, state["load"])
                write_json(artifacts.attach_path, state["attach"])
                write_json(artifacts.runtime_path, state["runtime"])
        else:
            state["compile"] = {"success": True, "stage": "compile", "skipped": True, "reason": "static_check_failed"}
            state["load"] = {"success": True, "stage": "load", "skipped": True, "reason": "static_check_failed"}
            state["attach"] = {"success": True, "stage": "attach", "skipped": True, "reason": "static_check_failed"}
            state["runtime"] = {
                "success": True,
                "stage": "runtime_test",
                "skipped": True,
                "reason": "static_check_failed",
            }
            write_json(artifacts.compile_path, state["compile"])
            write_json(artifacts.load_path, state["load"])
            write_json(artifacts.attach_path, state["attach"])
            write_json(artifacts.runtime_path, state["runtime"])

        state["detach"] = coordinator.run_detach(
            backend=backend,
            pin_path=state["pin_path"],
            load_report=state.get("load"),
            attach_report=state.get("attach"),
            proc=proc,
        ) or {}
        write_json(artifacts.detach_path, state["detach"])

        success, stage = coordinator.classify_deploy_stage(
            static_report=static_report,
            compile_report=state.get("compile"),
            load_report=state.get("load"),
            attach_report=state.get("attach"),
            runtime_report=state.get("runtime"),
            detach_report=state.get("detach"),
        )

        state["deploy"] = {
            "success": bool(success),
            "stage": stage,
            "compile": state.get("compile") or {},
            "load": state.get("load") or {},
            "attach": state.get("attach") or {},
            "runtime": state.get("runtime") or {},
            "detach": state.get("detach") or {},
        }
        state["deploy_state"] = bool(success)
        state["failed_stage"] = "" if success else stage
        if success:
            state["failed_stage_result"] = {}
            state["failed_stage_result_path"] = None
            state["final_decision"] = "success"
        else:
            set_failed_payload(state, stage)
            state["final_decision"] = ""
            _inc_signature(state, stable_error_signature(state["deploy"]))

        write_json(state["deploy_result_path"], deploy_summary_payload(state))
        print(f"deploy结果 {_attempt_progress(state)}: {stage}")
        helper.append_workflow_event(
            state,
            node_name="deploy_tool",
            node_index=deploy_idx,
            from_node=previous_node,
            key_results={
                "deploy_state": state.get("deploy_state"),
                "failed_stage": state.get("failed_stage"),
                "source_file": state.get("current_source_file"),
                "summary_path": state.get("deploy_result_path"),
            },
        )
        return state

    def node_analyzer(state: CaseState) -> CaseState:
        print("Analyzing")
        return analyzer.run(state)

    def node_repairer(state: CaseState) -> CaseState:
        print("Repairing")
        return repairer.run(state, use_pipeline_dirs=use_pipeline_dirs)

    def node_inspector(state: CaseState) -> CaseState:
        print("Inspecting")
        return inspector.run(state)

    def node_refiner(state: CaseState) -> CaseState:
        print("Refining")
        return refiner.run(state, enable_reflect_agent=enable_reflect_agent)

    def route_after_deploy_tool(state: CaseState) -> str:
        if state.get("deploy_state"):
            if state.get("has_repaired"):
                return "refiner"
            state["final_decision"] = "success"
            return "end"
        if not enable_resolve_agent:
            return "refiner" if enable_reflect_agent else "end"
        sig = state.get("last_error_signature") or ""
        counts = state.get("error_signature_counts") or {}
        if sig and int(counts.get(sig) or 0) >= SAME_ERROR_THRESHOLD:
            _print_limit_redirect(f"相同错误签名重复 {int(counts.get(sig) or 0)} 次: {sig}")
            return "refiner"
        if int(state.get("fixed_time") or 0) >= int(state.get("max_fix_time") or MAX_REPAIR_ATTEMPTS):
            _print_limit_redirect(
                f"修复次数达到上限 {int(state.get('fixed_time') or 0)}/{int(state.get('max_fix_time') or MAX_REPAIR_ATTEMPTS)}"
            )
            return "refiner"
        return "analyzer"

    def route_after_analyzer(state: CaseState) -> str:
        if state.get("can_fix") and len(state.get("repair_attempts") or []) < MAX_REPAIR_ATTEMPTS:
            return "repairer"
        return "refiner" if enable_reflect_agent else "end"

    def route_after_repairer(state: CaseState) -> str:
        if state.get("candidate_source_file") and state.get("final_decision") != "failed_no_patch":
            return "inspector" if enable_inspector_agent else "deploy_tool"
        return "refiner" if enable_reflect_agent else "end"

    def route_after_inspector(state: CaseState) -> str:
        if state.get("semantic_equivalent"):
            return "deploy_tool"
        max_attempts = min(MAX_REPAIR_ATTEMPTS, int(state.get("max_fix_time") or MAX_REPAIR_ATTEMPTS))
        if len(state.get("repair_attempts") or []) >= max_attempts:
            _print_limit_redirect(f"Inspector 后可继续修复次数耗尽 {len(state.get('repair_attempts') or [])}/{max_attempts}")
            return "refiner"
        return "repairer"

    g.add_node("deploy_tool", node_deploy_tool)
    g.add_node("analyzer", node_analyzer)
    g.add_node("repairer", node_repairer)
    g.add_node("inspector", node_inspector)
    g.add_node("refiner", node_refiner)
    g.add_node("end", node_end)

    g.set_entry_point("deploy_tool")
    g.add_conditional_edges("deploy_tool", route_after_deploy_tool, {"analyzer": "analyzer", "refiner": "refiner", "end": "end"})
    g.add_conditional_edges("analyzer", route_after_analyzer, {"repairer": "repairer", "refiner": "refiner", "end": "end"})
    g.add_conditional_edges(
        "repairer",
        route_after_repairer,
        {"deploy_tool": "deploy_tool", "inspector": "inspector", "refiner": "refiner", "end": "end"},
    )
    g.add_conditional_edges("inspector", route_after_inspector, {"deploy_tool": "deploy_tool", "repairer": "repairer", "refiner": "refiner"})
    g.add_edge("refiner", END)
    g.add_edge("end", END)
    return g.compile()


def init_case_state(
    *,
    paths: CasePaths,
    category: str,
    case_rel: str,
    kernel_profile: Dict[str, Any],
    source_file: str,
    object_file: str,
    pin_path: str,
    program_type: Optional[str],
    vmlinux_header_dir: Optional[str],
    artifact_stem: str,
    use_pipeline_dirs: bool = False,
    write_repair_error_record: bool = True,
    write_reflect_record_artifacts: bool = True,
) -> CaseState:
    logs_dir = paths.logs_dir
    pipeline_index = 1
    pipeline_dir = logs_dir / "deploy" / f"deploy_{pipeline_index}" if use_pipeline_dirs else logs_dir
    error_solve_dir = logs_dir / "repair"
    retry_code_dir = error_solve_dir / (f"repair_{pipeline_index}" if use_pipeline_dirs else "")
    error_record_path = error_solve_dir / "error_record.json"
    shared_history_path = logs_dir / "history.json"

    def p(name: str) -> str:
        if artifact_stem:
            return str(pipeline_dir / f"{name}_{artifact_stem}.json")
        return str(pipeline_dir / f"{name}.json")

    return {
        "category": category,
        "case_rel": case_rel,
        "case_display": f"{category}/{case_rel}/{Path(source_file).name}",
        "logs_dir": str(logs_dir),
        "build_dir": str(paths.build_dir),
        "shared_logs_dir": str(paths.shared_logs_dir),
        "kernel_profile": dict(kernel_profile or {}),
        "artifact_stem": artifact_stem,
        "original_source_file": source_file,
        "current_source_file": source_file,
        "candidate_source_file": None,
        "object_file": object_file,
        "pin_path": pin_path,
        "program_type": program_type,
        "vmlinux_header_dir": vmlinux_header_dir,
        "static_check_path": p("static_check"),
        "compile_result_path": p("compile_result"),
        "load_result_path": p("load_result"),
        "attach_result_path": p("attach_result"),
        "runtime_result_path": p("runtime_result"),
        "detach_result_path": p("detach_result"),
        "deploy_result_path": p("deploy_summary"),
        "retry_code_dir": str(retry_code_dir),
        "error_solve_dir": str(error_solve_dir),
        "error_record_path": str(error_record_path),
        "shared_history_path": str(shared_history_path),
        "write_repair_error_record": write_repair_error_record,
        "write_reflect_record_artifacts": write_reflect_record_artifacts,
        "static_check": {},
        "compile": {},
        "load": {},
        "attach": {},
        "runtime": {},
        "detach": {},
        "deploy": {},
        "failed_stage_result": {},
        "failed_stage_result_path": None,
        "pipeline_index": pipeline_index,
        "attempt_index": pipeline_index,
        "load_backend_attempt": 0,
        "patch_history": [],
        "repair_attempts": [],
        "retry_code_paths": [],
        "error_signature_counts": {},
        "last_error_signature": None,
        "failed_stage": "",
        "deploy_state": False,
        "has_repaired": False,
        "fixed_time": 0,
        "max_fix_time": MAX_REPAIR_ATTEMPTS,
        "last_node": "",
        "can_fix": False,
        "semantic_equivalent": None,
        "final_decision": "",
        "analysis_report": "",
        "repair_action": {},
        "inspector_report": "",
        "last_code_change_summary": "",
        "analyzer_thought": "",
        "repairer_thought": "",
        "inspector_thought": "",
        "refiner_thought": "",
        "last_inspector_context": {},
        "shared_history": [],
        "node_run_counts": {},
        "workflow_events": [],
        "repair_report_path": None,
        "reflect_record_path": None,
        "_load_backend": None,
        "_load_process": None,
    }

