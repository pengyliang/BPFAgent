"""Project entrypoint to run AST analysis, kernel profiling, static checks and deployment.

Input:
- all .bpf.c files under ./data/<category>/<case>

Outputs:
- intermediate artifacts under ./output/<kernel_version>/log/<category>/<case>
- build artifacts (.o) under ./output/<kernel_version>/build/<category>/<case>

Usage:
- python main.py                        # run for all cases under data/
- python main.py verifier               # run all cases under data/verifier
- python main.py verifier/loop_support  # run only data/verifier/loop_support
"""

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
from collections import Counter, defaultdict, OrderedDict
import shutil
import platform
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.setup.kernel_info_collector import collect_kernel_info
from src.util.static_check.ast_summary import build_static_check_summaries
from src.core.coordinator import Coordinator, CoordinatorConfig
from src.core.config_loader import DEFAULT_CONFIG_PATH, get_api_key, load_app_config
from src.core.llm.openai_compat import OpenAICompatClient, OpenAICompatConfig
from src.core.io import read_json
from src.util.deploy.executor import make_deploy_result_summary, save_deploy_report
from src.core.state import CasePaths
from src.core.workflow import build_case_graph, init_case_state


def _normalize_program_type(sec_value):
    prefix = sec_value.split("/", 1)[0]
    if prefix in {"kprobe", "kretprobe", "tracepoint", "xdp", "lsm", "iter", "fentry", "fexit"}:
        return prefix
    if prefix.startswith("raw_tp"):
        return "raw_tracepoint"
    if prefix.startswith("cgroup"):
        return "cgroup_skb"
    return None


def _guess_program_type(source_text):
    sections = re.findall(r'SEC\("([^"]+)"\)', source_text)
    for sec in sections:
        if sec in {".maps", "license"}:
            continue
        ptype = _normalize_program_type(sec)
        if ptype:
            return ptype
    return None


def _parse_version_tuple(version_text):
    if not version_text:
        return None
    m = re.match(r"^\s*(\d+)\.(\d+)(?:\.(\d+))?\s*$", str(version_text))
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3) or 0))


def _current_kernel_output_version():
    release = platform.release()
    m = re.match(r"^(\d+)\.(\d+)", release or "")
    if m:
        return f"{m.group(1)}.{m.group(2)}"
    return "unknown"


def _version_at_least(current_version, minimum_version):
    if not current_version or not minimum_version:
        return None
    return current_version >= minimum_version


def _extract_min_kernel(meta_path):
    path = Path(meta_path)
    if not path.exists():
        return None
    text = path.read_text(encoding="utf-8", errors="ignore")
    m = re.search(r"^\s*min_kernel\s*:\s*['\"]?([0-9]+(?:\.[0-9]+){1,2})", text, flags=re.MULTILINE)
    if not m:
        return None
    return m.group(1)


def _expected_deploy_for_source(source_path, current_kernel_tuple):
    meta_path = Path(source_path).parent / "meta.yaml"
    min_kernel_text = _extract_min_kernel(meta_path)
    min_kernel_tuple = _parse_version_tuple(min_kernel_text)
    expected_success = _version_at_least(current_kernel_tuple, min_kernel_tuple)
    return {
        "meta_path": str(meta_path),
        "min_kernel": min_kernel_text,
        "expected_success": expected_success,
    }


def _resolve_agent_final_status(final_state, *, fallback_stage):
    deploy_state = final_state.get("deploy_state")
    if deploy_state is None:
        return None
    if bool(deploy_state):
        return True, "success"
    failed_stage = str(final_state.get("failed_stage") or "").strip()
    if failed_stage:
        return False, failed_stage
    final_decision = str(final_state.get("final_decision") or "").strip()
    if final_decision and final_decision != "success":
        return False, final_decision
    return False, fallback_stage


def _compute_agent_metrics_1_40(prepared_cases: list[dict]) -> list[dict]:
    """
    Compute the 1-40 agent metrics for agent_mode_report.json.

    Notes:
    - This implementation is based on per-case logs under output/<kernel>/log/agent_mode/<category>/<case>.
    - Token usage is not available in current logs, so related metrics are None.
    """

    # Stage / counts among "initial failed" cases (deploy_tool@node_index==1)
    initial_failed_stage_counts: Counter[str] = Counter()
    stage_to_cases: defaultdict[str, list[str]] = defaultdict(list)
    initial_failed_cases: list[str] = []

    # Per-case aggregates
    per_case: dict[str, dict] = {}

    # Total repair metrics
    total_repair_attempts = 0
    total_agent_calls = 0
    total_fixed_time_sum = 0
    initial_failure_count = 0
    repair_success_case_count = 0

    # Category aggregates
    cats: dict[str, dict] = defaultdict(
        lambda: {
            "has_repair_needed": False,
            "repair_needed_case_count": 0,
            "repair_success_case_count": 0,
            "total_fixed_time": 0,
        }
    )

    # Analyzer can_fix consistency
    can_fix_true_final_success = 0
    can_fix_true_final_failed = 0
    can_fix_false_final_success = 0
    can_fix_false_final_failed = 0
    can_fix_mismatch = 0

    # Error signature aggregation
    error_sig_agg: Counter[str] = Counter()
    same_error_threshold_hit_cases: list[dict] = []

    # Iterate all prepared cases and parse per-case logs.
    for item in prepared_cases:
        case = item["case"]
        category = case["category"]
        case_rel = case["case_rel"]
        case_id = f"{category}/{case_rel.as_posix()}"
        case_root: Path = item["logs_dir"]

        wf_path = case_root / "workflow_summary.json"
        if not wf_path.exists():
            continue

        wf = json.loads(wf_path.read_text(encoding="utf-8"))
        events = wf.get("events") or []

        deploy_events = [e for e in events if e.get("node") == "deploy_tool"]
        deploy1_status = "unknown"
        if deploy_events:
            deploy1 = next((e for e in deploy_events if e.get("node_index") == 1), None)
            if deploy1 is None:
                deploy1 = sorted(deploy_events, key=lambda x: x.get("seq", 0))[0]
            key_results = deploy1.get("key_results") or {}
            if key_results.get("deploy_state") is True:
                deploy1_status = "success"
            else:
                deploy1_status = str(key_results.get("failed_stage") or wf.get("failed_stage") or "unknown")

        final_success = bool(wf.get("deploy_state"))
        final_status = "success" if final_success else str(wf.get("failed_stage") or "unknown")

        initial_failed = deploy1_status != "success"

        # Count agent node calls: every node except deploy_tool (an approximation of "agent calls").
        agent_calls = sum(1 for e in events if e.get("node") != "deploy_tool")

        repair_round = 0
        error_signature_counts: dict[str, int] = {}
        same_error_threshold = None
        repair_report_path = case_root / "repair_report.json"
        if repair_report_path.exists():
            rr = json.loads(repair_report_path.read_text(encoding="utf-8"))
            attempts = rr.get("attempts") or []
            repair_round = len(attempts)
            error_signature_counts = rr.get("error_signature_counts") or {}
            same_error_threshold = rr.get("same_error_threshold")

            for sig, cnt in error_signature_counts.items():
                try:
                    error_sig_agg[sig] += int(cnt)
                except Exception:
                    pass

            # "same_error_threshold" hit: stuck / repeated signature.
            if same_error_threshold is not None:
                try:
                    thr = int(same_error_threshold)
                except Exception:
                    thr = None
                if thr is not None:
                    max_sig = None
                    max_cnt = 0
                    for sig, cnt in error_signature_counts.items():
                        try:
                            cnt_i = int(cnt)
                        except Exception:
                            continue
                        if cnt_i > max_cnt:
                            max_cnt = cnt_i
                            max_sig = sig
                    if max_cnt >= thr:
                        same_error_threshold_hit_cases.append(
                            {
                                "case": case_id,
                                "hit": True,
                                "same_error_threshold": thr,
                                "max_signature": max_sig,
                                "max_count": max_cnt,
                            }
                        )

        # fixed_time: sum of refiner_record_*.json result_params.fixed_time
        fixed_time_sum = 0
        for rf in case_root.rglob("refiner_record*.json"):
            try:
                rj = json.loads(rf.read_text(encoding="utf-8"))
            except Exception:
                continue
            t = (rj.get("result_params") or {}).get("fixed_time")
            if isinstance(t, (int, float)):
                fixed_time_sum += int(t)

        # last Analyzer can_fix
        last_analyzer = None
        for e in sorted(events, key=lambda x: x.get("seq", 0)):
            if e.get("node") == "Analyzer":
                last_analyzer = e
        can_fix_last = None
        if last_analyzer:
            can_fix_last = (last_analyzer.get("key_results") or {}).get("can_fix")

        per_case[case_id] = {
            "case_id": case_id,
            "category": category,
            "deploy_1_status": deploy1_status,
            "initial_failed": initial_failed,
            "final_success": final_success,
            "final_status": final_status,
            "agent_calls": agent_calls,
            "repair_round": repair_round,
            "fixed_time_sum": fixed_time_sum,
            "last_analyzer_can_fix": can_fix_last,
            "error_signature_counts": error_signature_counts,
            "same_error_threshold": same_error_threshold,
        }

        # Only aggregate metrics from initial_failed cases.
        if not initial_failed:
            continue

        initial_failed_stage_counts[deploy1_status] += 1
        stage_to_cases[deploy1_status].append(case_id)
        initial_failed_cases.append(case_id)
        initial_failure_count += 1

        if final_success:
            repair_success_case_count += 1

        total_repair_attempts += repair_round
        total_agent_calls += agent_calls
        total_fixed_time_sum += fixed_time_sum

        c = cats[category]
        c["has_repair_needed"] = True
        c["repair_needed_case_count"] += 1
        c["total_fixed_time"] += fixed_time_sum
        if final_success:
            c["repair_success_case_count"] += 1

        if can_fix_last is True:
            if final_success:
                can_fix_true_final_success += 1
            else:
                can_fix_true_final_failed += 1
                can_fix_mismatch += 1
        elif can_fix_last is False:
            if final_success:
                can_fix_false_final_success += 1
                can_fix_mismatch += 1
            else:
                can_fix_false_final_failed += 1

    # Derived metrics
    repair_success_rate = (repair_success_case_count / initial_failure_count) if initial_failure_count else None
    can_fix_mismatch_rate = (can_fix_mismatch / initial_failure_count) if initial_failure_count else None

    per_stage_total = {s: len(stage_to_cases.get(s, [])) for s in stage_to_cases}
    per_stage_success = {}
    per_stage_rates = {}
    for s, case_ids in stage_to_cases.items():
        succ = sum(1 for cid in case_ids if per_case.get(cid, {}).get("final_success"))
        per_stage_success[s] = succ
        per_stage_rates[s] = (succ / len(case_ids)) if case_ids else None

    failed_cases_need_repair = [cid for cid in initial_failed_cases if not per_case[cid]["final_success"]]
    final_failed_stage_counts = Counter(per_case[cid]["final_status"] for cid in failed_cases_need_repair)
    failed_need_repair_count = len(failed_cases_need_repair)
    initial_stage_ratio = {
        s: (cnt / initial_failure_count) if initial_failure_count else None for s, cnt in initial_failed_stage_counts.items()
    }
    final_failed_stage_ratio = {
        s: (cnt / failed_need_repair_count) if failed_need_repair_count else None for s, cnt in final_failed_stage_counts.items()
    }

    final_success_count_all = sum(1 for meta in per_case.values() if meta["final_success"])
    final_failure_count_all = len(per_case) - final_success_count_all
    final_stage_counts_all = Counter(
        meta["final_status"] for meta in per_case.values() if not meta["final_success"]
    )
    final_failure_stage_distribution_all = dict(final_stage_counts_all)
    final_failure_stage_distribution_all_ratio = {
        s: (cnt / final_failure_count_all) if final_failure_count_all else None
        for s, cnt in final_stage_counts_all.items()
    }

    # Repair rounds distribution among initial_failed cases.
    repair_rounds_per_case = {cid: per_case[cid]["repair_round"] for cid in initial_failed_cases}
    hist = Counter(repair_rounds_per_case.values())
    repair_round_histogram = dict(sorted(hist.items(), key=lambda x: x[0]))
    repair_round_avg = (sum(repair_rounds_per_case.values()) / len(repair_rounds_per_case)) if repair_rounds_per_case else None
    repair_round_max = max(repair_rounds_per_case.values()) if repair_rounds_per_case else None

    # Error signature top 10
    error_sig_top = [[sig, cnt] for sig, cnt in error_sig_agg.most_common(10)]

    # Per-case helper dicts for metrics
    per_case_last_can_fix = {cid: per_case[cid]["last_analyzer_can_fix"] for cid in per_case}
    per_case_final_status = {cid: per_case[cid]["final_status"] for cid in per_case}

    # 1-40 metrics list
    metrics: list[dict] = []

    def add_metric(i: int, name: str, value):
        metrics.append({"id": i, "name": name, "value": value})

    # 1-8 total repair metrics
    add_metric(1, "per_case_agent_calls_during_repair", {cid: per_case[cid]["agent_calls"] for cid in initial_failed_cases})
    add_metric(2, "total_agent_calls_during_repair", total_agent_calls)
    add_metric(3, "initial_failure_count", int(initial_failure_count))
    add_metric(4, "total_repair_attempt_count", int(total_repair_attempts))
    add_metric(5, "total_repair_success_case_count", int(repair_success_case_count))
    add_metric(6, "total_repair_success_rate", repair_success_rate)
    add_metric(7, "total_fixed_time_sum", int(total_fixed_time_sum))
    add_metric(8, "total_token_consumption_sum", None)  # token not recorded in current logs

    # 9-14 category metrics
    cats_ordered = sorted(cats.keys())
    add_metric(9, "category_has_repair_needed", {c: bool(cats[c]["has_repair_needed"]) for c in cats_ordered})
    add_metric(10, "category_repair_needed_case_count", {c: cats[c]["repair_needed_case_count"] for c in cats_ordered})
    add_metric(11, "category_repair_success_case_count", {c: cats[c]["repair_success_case_count"] for c in cats_ordered})
    add_metric(
        12,
        "category_repair_success_rate",
        {c: (cats[c]["repair_success_case_count"] / cats[c]["repair_needed_case_count"]) if cats[c]["repair_needed_case_count"] else None for c in cats_ordered},
    )
    add_metric(13, "category_total_fixed_time_sum", {c: cats[c]["total_fixed_time"] for c in cats_ordered})
    add_metric(14, "category_total_token_consumption_sum", {c: None for c in cats_ordered})

    # 15-24 stage metrics
    add_metric(15, "initial_failed_stage_distribution_count", dict(initial_failed_stage_counts))
    add_metric(16, "initial_failed_stage_distribution_ratio", initial_stage_ratio)
    add_metric(
        17,
        "final_repair_result_counts",
        {"success_count": int(final_success_count_all), "failure_count": int(final_failure_count_all)},
    )
    add_metric(18, "final_failed_stage_distribution_count_need_repair_initially", dict(final_failed_stage_counts))
    add_metric(19, "final_failed_stage_distribution_ratio_need_repair_initially", final_failed_stage_ratio)
    add_metric(20, "per_stage_repair_success_rate", per_stage_rates)
    add_metric(21, "per_stage_repair_success_cases_count", per_stage_success)
    add_metric(22, "per_stage_repair_total_cases_count", per_stage_total)
    add_metric(23, "final_failure_stage_distribution_all", final_failure_stage_distribution_all)
    add_metric(24, "final_failure_stage_distribution_all_ratio", final_failure_stage_distribution_all_ratio)

    # 25-32 agent metrics
    add_metric(25, "repair_round_histogram", repair_round_histogram)
    add_metric(26, "repair_round_average", repair_round_avg)
    add_metric(27, "repair_round_max", repair_round_max)
    add_metric(28, "repair_rounds_per_case", repair_rounds_per_case)
    add_metric(
        29,
        "analyzer_last_can_fix_distribution",
        {
            "can_fix_true": sum(1 for v in per_case_last_can_fix.values() if v is True),
            "can_fix_false": sum(1 for v in per_case_last_can_fix.values() if v is False),
            "can_fix_none": sum(1 for v in per_case_last_can_fix.values() if v is None),
        },
    )
    add_metric(30, "can_fix_true_final_success_case_count", int(can_fix_true_final_success))
    add_metric(31, "can_fix_true_final_failed_case_count", int(can_fix_true_final_failed))
    add_metric(32, "can_fix_false_final_success_case_count", int(can_fix_false_final_success))

    # 33-40 remaining
    add_metric(33, "can_fix_false_final_failed_case_count", int(can_fix_false_final_failed))
    add_metric(34, "analyze_can_fix_mismatch_rate", can_fix_mismatch_rate)
    add_metric(35, "error_signature_counts_top10", error_sig_top)
    add_metric(36, "cases_hit_same_error_threshold_count", len(same_error_threshold_hit_cases))
    add_metric(37, "cases_hit_same_error_threshold_details", same_error_threshold_hit_cases)
    add_metric(38, "error_signature_counts_aggregate_total_unique_signatures", len(error_sig_agg))
    add_metric(39, "per_case_last_analyzer_can_fix", per_case_last_can_fix)
    add_metric(40, "per_case_final_status", per_case_final_status)

    if len(metrics) != 40:
        raise RuntimeError(f"Expected 40 metrics, got {len(metrics)}")

    return metrics


def run_pipeline(
    data_dir,
    logs_dir,
    build_dir,
    kernel_profile_path,
    kernel_profile,
    bpftool_output_path=None,
    shared_logs_dir=None,
    coordinator=None,
    enable_resolve_agent=True,
    enable_reflect_agent=True,
    app_config=None,
):
    data_path = Path(data_dir)
    logs_path = Path(logs_dir)
    build_path = Path(build_dir)
    shared_logs_path = Path(shared_logs_dir) if shared_logs_dir else logs_path

    logs_path.mkdir(parents=True, exist_ok=True)
    build_path.mkdir(parents=True, exist_ok=True)

    # Remove legacy static report naming from previous runs.
    legacy_static_report = logs_path / "static_check_report.json"
    if legacy_static_report.exists():
        legacy_static_report.unlink()

    bpf_sources = sorted(data_path.glob("*.bpf.c"))
    if not bpf_sources:
        raise RuntimeError(f"No .bpf.c files found under {data_path}")

    # 先对每份源码跑 clang AST；若 clang 失败或无法解析 JSON，parse_ebpf_source 会标记
    # ast_fallback 并返回空 bpf_helper_calls，static_checker 再退回源码正则分析。
    summaries = build_static_check_summaries(
        bpf_sources,
        artifact_dir=logs_path,
        vmlinux_header_dir=str(shared_logs_path),
    )

    kernel_profile_path = Path(kernel_profile_path)
    kernel_version = kernel_profile.get("kernel_version", {})
    current_kernel_raw = kernel_version.get("raw")
    current_kernel_tuple = (
        kernel_version.get("major"),
        kernel_version.get("minor"),
        kernel_version.get("patch") or 0,
    )

    if app_config is None:
        app_config = load_app_config(str(DEFAULT_CONFIG_PATH))

    effective_resolve_agent = bool(enable_resolve_agent and app_config.agent.agent_mode and app_config.agent.analyzer_enabled)
    effective_inspector_agent = bool(effective_resolve_agent and app_config.agent.inspector_enabled)
    effective_reflect_agent = bool(enable_reflect_agent and app_config.agent.agent_mode and app_config.agent.refiner_enabled)
    agent_mode = bool(effective_resolve_agent or effective_reflect_agent)

    # Build OpenAI-compatible client if enabled and key exists.
    llm_client = None
    if app_config.llm.enabled:
        if app_config.llm.show_terminal_output:
            print(f"当前使用的模型: {app_config.llm.model}")
        key = get_api_key(app_config.llm)
        if key:
            llm_client = OpenAICompatClient(
                OpenAICompatConfig(
                    base_url=app_config.llm.base_url,
                    model=app_config.llm.model,
                    api_key=key,
                    timeout_s=app_config.llm.timeout_s,
                    extra_body=app_config.llm.extra_body,
                    show_terminal_output=app_config.llm.show_terminal_output,
                )
            )
        else:
            if app_config.llm.show_terminal_output:
                print("LLM 已启用，但未获取到 API Key，当前不会创建模型客户端。")
    else:
        if app_config.llm.show_terminal_output:
            print("LLM 已禁用，当前不会使用模型。")

    coordinator = coordinator or Coordinator(
        config=CoordinatorConfig(
            max_retries=int(app_config.max_retry or 1),
            enable_agent=bool(effective_resolve_agent),
            agent_max_patches=int(app_config.agent.agent_max_patches or 2),
            enable_static_check=bool(app_config.static_check.enabled),
        )
    )
    # Coordinator is deterministic; LLM is consumed by agent modules.
    coordinator.llm = llm_client  # type: ignore[attr-defined]
    case_graph = build_case_graph(
        coordinator=coordinator,
        enable_resolve_agent=bool(effective_resolve_agent),
        enable_inspector_agent=bool(effective_inspector_agent),
        # Reflect depends on the same agent enable flag as resolve.
        enable_reflect_agent=bool(effective_reflect_agent),
        use_pipeline_dirs=bool(effective_resolve_agent),
    )

    static_report_path = logs_path / "static_check.json"
    static_report = coordinator.run_static_check(
        summaries=summaries,
        kernel_profile=kernel_profile,
        output_path=None if agent_mode else str(static_report_path),
    )

    deploy_results = []
    success_count = 0
    core_compile_count = 0
    non_core_compile_count = 0
    single_source_case = len(bpf_sources) == 1
    rel_case = data_path.relative_to(REPO_ROOT / "data")
    category_name = rel_case.parts[0] if rel_case.parts else "root"
    case_rel_path = Path(*rel_case.parts[1:]) if len(rel_case.parts) > 1 else Path("_default")
    for src in bpf_sources:
        stem = src.name.replace(".bpf.c", "")
        object_path = build_path / f"{stem}.bpf.o"
        source_text = src.read_text(encoding="utf-8", errors="ignore")
        program_type = _guess_program_type(source_text)
        pin_path = f"/sys/fs/bpf/ebpf_agent_{stem}"
        expectation = _expected_deploy_for_source(src, current_kernel_tuple)

        retry_dir = logs_path / "retry_code"
        paths = CasePaths(logs_dir=logs_path, build_dir=build_path, shared_logs_dir=shared_logs_path)
        paths.ensure_dirs()
        state = init_case_state(
            paths=paths,
            category=category_name,
            case_rel=case_rel_path.as_posix(),
            kernel_profile=kernel_profile,
            source_file=str(src),
            object_file=str(object_path),
            pin_path=pin_path,
            program_type=program_type,
            vmlinux_header_dir=str(shared_logs_path),
            artifact_stem=("" if single_source_case else stem),
            use_pipeline_dirs=bool(effective_resolve_agent),
            write_repair_error_record=not agent_mode,
            write_reflect_record_artifacts=not agent_mode,
        )
        final_state = case_graph.invoke(state)

        # Summarize deploy stage from per-stage *_result.json files (no deploy_summary node).
        stage_root = logs_path
        if effective_resolve_agent:
            # Prefer the latest deploy/deploy_* dir; fall back to legacy pipeline_* dirs.
            max_n = 0
            best_stage_root = None
            for child in logs_path.iterdir():
                if child.is_dir() and child.name == "deploy":
                    for deploy_child in child.iterdir():
                        if deploy_child.is_dir() and deploy_child.name.startswith("deploy_"):
                            try:
                                n = int(deploy_child.name.split("_", 1)[1])
                                compile_name = f"compile_result_{stem}.json" if not single_source_case else "compile_result.json"
                                runtime_name = f"runtime_result_{stem}.json" if not single_source_case else "runtime_result.json"
                                has_stage_outputs = (
                                    (deploy_child / compile_name).exists()
                                    or (deploy_child / runtime_name).exists()
                                    or (deploy_child / "deploy_summary.json").exists()
                                )
                                if has_stage_outputs and n >= max_n:
                                    max_n = n
                                    best_stage_root = deploy_child
                            except Exception:
                                pass
                    continue
                if not child.is_dir():
                    continue
                for prefix in ("pipeline_",):
                    if child.name.startswith(prefix):
                        try:
                            n = int(child.name.split("_", 1)[1])
                            compile_name = f"compile_result_{stem}.json" if not single_source_case else "compile_result.json"
                            runtime_name = f"runtime_result_{stem}.json" if not single_source_case else "runtime_result.json"
                            has_stage_outputs = (child / compile_name).exists() or (child / runtime_name).exists()
                            if has_stage_outputs and n >= max_n:
                                max_n = n
                                best_stage_root = child
                        except Exception:
                            pass
                        break
            if best_stage_root is not None:
                stage_root = best_stage_root

        if single_source_case:
            per_file_report_path = stage_root / "deploy_summary.json"
            compile_report_path = stage_root / "compile_result.json"
            load_report_path = stage_root / "load_result.json"
            attach_report_path = stage_root / "attach_result.json"
            runtime_report_path = stage_root / "runtime_result.json"
            detach_report_path = stage_root / "detach_result.json"
        else:
            per_file_report_path = stage_root / f"deploy_summary_{stem}.json"
            compile_report_path = stage_root / f"compile_result_{stem}.json"
            load_report_path = stage_root / f"load_result_{stem}.json"
            attach_report_path = stage_root / f"attach_result_{stem}.json"
            runtime_report_path = stage_root / f"runtime_result_{stem}.json"
            detach_report_path = stage_root / f"detach_result_{stem}.json"

        compile_report = read_json(compile_report_path) or {}
        load_report = read_json(load_report_path) or {}
        attach_report = read_json(attach_report_path) or {}
        runtime_report = read_json(runtime_report_path) or {}
        detach_report = read_json(detach_report_path) or {}
        static_check_report = read_json(stage_root / "static_check.json") or {}

        success, stage = coordinator.classify_deploy_stage(
            static_report=static_check_report,
            compile_report=compile_report,
            load_report=load_report,
            attach_report=attach_report,
            runtime_report=runtime_report,
            detach_report=detach_report,
        )
        if effective_resolve_agent:
            agent_final_status = _resolve_agent_final_status(final_state, fallback_stage=stage)
            if agent_final_status is not None:
                success, stage = agent_final_status
        deploy_report = {
            "success": bool(success),
            "stage": stage,
            "static_check": static_check_report,
            "compile": compile_report,
            "load": load_report,
            "attach": attach_report,
            "runtime": runtime_report,
            "detach": detach_report,
        }

        save_deploy_report(make_deploy_result_summary(deploy_report), str(per_file_report_path))

        compile_info = deploy_report.get("compile") or {}
        compile_mode = compile_info.get("compile_mode")
        vmlinux_header = compile_info.get("vmlinux_header")
        if compile_mode == "core":
            core_compile_count += 1
        elif compile_mode == "non-core":
            non_core_compile_count += 1

        deploy_results.append(
            {
                "source": str(src),
                "object_file": str(object_path),
                "program_type": program_type,
                "compile_mode": compile_mode,
                "vmlinux_header": vmlinux_header,
                "pin_path": pin_path,
                "meta_path": expectation["meta_path"],
                "min_kernel": expectation["min_kernel"],
                "expected_deploy_success": expectation["expected_success"],
                "success": deploy_report["success"],
                "stage": deploy_report["stage"],
                "report": str(per_file_report_path),
                "compile_report": str(compile_report_path),
                "load_report": str(load_report_path),
                "attach_report": str(attach_report_path),
                "runtime_report": str(runtime_report_path),
                "detach_report": str(detach_report_path),
                "attach_target": ((deploy_report.get("attach") or {}).get("plan") or {}).get("attach_target"),
            }
        )
        if deploy_report["success"]:
            success_count += 1

    failed_items = [item for item in deploy_results if not item["success"]]
    expected_success_items = [item for item in deploy_results if item["expected_deploy_success"] is True]
    expected_failure_items = [item for item in deploy_results if item["expected_deploy_success"] is False]
    expected_unknown_items = [item for item in deploy_results if item["expected_deploy_success"] is None]
    mismatch_items = [
        item
        for item in deploy_results
        if item["expected_deploy_success"] is not None and item["expected_deploy_success"] != item["success"]
    ]
    unexpected_failure_items = [
        item for item in deploy_results if item["expected_deploy_success"] is True and not item["success"]
    ]
    unexpected_success_items = [
        item for item in deploy_results if item["expected_deploy_success"] is False and item["success"]
    ]

    total_files = len(deploy_results)
    failed_count = len(failed_items)
    success_rate = (success_count / total_files * 100.0) if total_files else 0.0

    pipeline_report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "inputs": {
            "data_dir": str(data_path),
            "bpf_sources": [str(x) for x in bpf_sources],
        },
        "outputs": {
            "logs_dir": str(logs_path),
            "build_dir": str(build_path),
            "kernel_profile": str(kernel_profile_path),
            "static_check": str(static_report_path),
            "bpftool_feature_probe": bpftool_output_path,
        },
        "summary": {
            "total_files": total_files,
            "deploy_success_count": success_count,
            "deploy_failure_count": failed_count,
            "deploy_success_rate": round(success_rate, 2),
            "expected_success_count": len(expected_success_items),
            "expected_failure_count": len(expected_failure_items),
            "expected_unknown_count": len(expected_unknown_items),
            "deploy_failed_files": [item["source"] for item in failed_items],
            "deploy_failed_stages": [item["stage"] for item in failed_items],
            # Static report schema v2:
            #   {"success": bool, "error_warning_count": {"error": int, "warning": int}, "issues": [...]}
            # Backward compatible with legacy schema v1 that had {"summary": {"error_count", "warning_count"}, ...}
            "static_errors": int(
                ((static_report.get("error_warning_count") or {}).get("error"))
                if isinstance(static_report, dict)
                else 0
            )
            if isinstance(static_report, dict) and "error_warning_count" in static_report
            else int(((static_report.get("summary") or {}).get("error_count")) if isinstance(static_report, dict) else 0),
            "static_warnings": int(
                ((static_report.get("error_warning_count") or {}).get("warning"))
                if isinstance(static_report, dict)
                else 0
            )
            if isinstance(static_report, dict) and "error_warning_count" in static_report
            else int(((static_report.get("summary") or {}).get("warning_count")) if isinstance(static_report, dict) else 0),
            "core_compile_count": core_compile_count,
            "non_core_compile_count": non_core_compile_count,
            "current_kernel": current_kernel_raw,
            "expected_success_files": [item["source"] for item in expected_success_items],
            "expected_failure_files": [item["source"] for item in expected_failure_items],
            "expected_unknown_files": [item["source"] for item in expected_unknown_items],
            "expectation_mismatch_count": len(mismatch_items),
            "expectation_mismatch_files": [item["source"] for item in mismatch_items],
            "unexpected_failure_count": len(unexpected_failure_items),
            "unexpected_failure_files": [item["source"] for item in unexpected_failure_items],
            "unexpected_success_count": len(unexpected_success_items),
            "unexpected_success_files": [item["source"] for item in unexpected_success_items],
        },
        "expectation_mismatches": [
            {
                "source": item["source"],
                "min_kernel": item["min_kernel"],
                "expected_success": item["expected_deploy_success"],
                "actual_success": item["success"],
                "actual_stage": item["stage"],
            }
            for item in mismatch_items
        ],
        "deploy_results": deploy_results,
    }

    return pipeline_report


def _discover_data_cases(data_root):
    case_dirs = set()
    for src in data_root.rglob("*.bpf.c"):
        rel_parent = src.parent.relative_to(data_root)
        if rel_parent.parts and rel_parent.parts[0] == "build":
            continue
        case_dirs.add(src.parent)

    cases = []
    for case_dir in sorted(case_dirs):
        rel = case_dir.relative_to(data_root)
        category = rel.parts[0] if rel.parts else "root"
        case_rel = Path(*rel.parts[1:]) if len(rel.parts) > 1 else Path("_default")
        cases.append(
            {
                "dir": case_dir,
                "category": category,
                "case_rel": case_rel,
                "display": f"{category}/{case_rel.as_posix()}",
            }
        )
    return cases


def _select_cases(data_root, selector, all_cases):
    if not selector:
        return all_cases

    target = (data_root / selector).resolve()
    data_root_resolved = data_root.resolve()
    if not target.exists() or not target.is_dir():
        raise RuntimeError(f"Data path not found: {target}")

    if data_root_resolved not in target.parents and target != data_root_resolved:
        raise RuntimeError(f"Selected path must be under {data_root}")

    selected = [
        case
        for case in all_cases
        if case["dir"].resolve() == target or target in case["dir"].resolve().parents
    ]
    if not selected:
        raise RuntimeError(f"No .bpf.c test cases found under {target}")
    return selected


def run_for_groups(
    group_name=None,
    *,
    enable_resolve_agent=True,
    enable_reflect_agent=True,
    config_path=None,
):
    data_root = REPO_ROOT / "data"
    kernel_output_version = _current_kernel_output_version()
    output_root = REPO_ROOT / "output" / kernel_output_version
    logs_base = output_root / "log"
    build_root = output_root / "build"
    app_config = load_app_config(config_path or str(DEFAULT_CONFIG_PATH))
    effective_resolve_agent = bool(enable_resolve_agent and app_config.agent.agent_mode and app_config.agent.analyzer_enabled)
    effective_reflect_agent = bool(enable_reflect_agent and app_config.agent.agent_mode and app_config.agent.refiner_enabled)

    mode_name = "agent_mode" if (effective_resolve_agent or effective_reflect_agent) else "no_agent_mode"
    mode_logs_root = logs_base / mode_name

    all_cases = _discover_data_cases(data_root)
    if not all_cases:
        raise RuntimeError(f"No data test cases with .bpf.c files found under {data_root}")

    cases = _select_cases(data_root, group_name, all_cases)
    mode_logs_root.mkdir(parents=True, exist_ok=True)

    global_bpftool_probe = logs_base / "bpftool_feature_probe.json"
    kernel_profile_path = logs_base / "kernel_profile.json"
    kernel_profile = collect_kernel_info(
        output_path=str(kernel_profile_path),
        bpftool_output_path=str(global_bpftool_probe),
    )
    print(f"Kernel profile loaded: {kernel_profile_path}")

    prepared_cases = []
    for case in cases:
        case_logs_dir_base = mode_logs_root / case["category"] / case["case_rel"]
        # If the user restarts with agent_mode and previous pipeline results exist,
        # clear them and rerun from scratch (pipeline_1).
        if mode_name == "agent_mode" and case_logs_dir_base.exists():
            shutil.rmtree(case_logs_dir_base)
        prepared_cases.append(
            {
                "case": case,
                "logs_dir": case_logs_dir_base,
                "build_dir": build_root / case["category"] / case["case_rel"],
            }
        )

    def run_single_case(prepared_case):
        case = prepared_case["case"]
        print(f"\n=== Running pipeline for case: {case['display']} ===")
        report = run_pipeline(
            data_dir=case["dir"],
            logs_dir=prepared_case["logs_dir"],
            build_dir=prepared_case["build_dir"],
            kernel_profile_path=str(kernel_profile_path),
            kernel_profile=kernel_profile,
            bpftool_output_path=str(global_bpftool_probe),
            shared_logs_dir=str(logs_base),
            coordinator=None,
            enable_resolve_agent=effective_resolve_agent,
            enable_reflect_agent=effective_reflect_agent,
            app_config=app_config,
        )
        return {
            "category": case["category"],
            "case": case["case_rel"].as_posix(),
            "data_dir": str(case["dir"]),
            "report": report,
        }

    all_reports = [None] * len(prepared_cases)
    with ThreadPoolExecutor(max_workers=max(1, len(prepared_cases))) as executor:
        future_to_index = {
            executor.submit(run_single_case, prepared_case): idx for idx, prepared_case in enumerate(prepared_cases)
        }
        for future in as_completed(future_to_index):
            idx = future_to_index[future]
            all_reports[idx] = future.result()

    flattened = []
    for item in all_reports:
        category = item["category"]
        case_name = item["case"]
        deploy_results = item["report"].get("deploy_results", [])
        for deploy_item in deploy_results:
            flattened.append(
                {
                    "category": category,
                    "case": case_name,
                    "source": deploy_item.get("source"),
                    "stage": deploy_item.get("stage"),
                    "success": bool(deploy_item.get("success")),
                    "min_kernel": deploy_item.get("min_kernel"),
                    "expected_deploy_success": deploy_item.get("expected_deploy_success"),
                }
            )

    total_files = len(flattened)
    success_count = sum(1 for x in flattened if x["success"])
    failure_count = total_files - success_count
    success_rate = (success_count / total_files * 100.0) if total_files else 0.0
    failed_files = [x["source"] for x in flattened if not x["success"]]
    failed_stages = [x["stage"] for x in flattened if not x["success"]]
    expected_success_items = [x for x in flattened if x["expected_deploy_success"] is True]
    expected_failure_items = [x for x in flattened if x["expected_deploy_success"] is False]
    expected_unknown_items = [x for x in flattened if x["expected_deploy_success"] is None]
    mismatch_items = [
        x for x in flattened if x["expected_deploy_success"] is not None and x["expected_deploy_success"] != x["success"]
    ]
    unexpected_failure_items = [x for x in flattened if x["expected_deploy_success"] is True and not x["success"]]
    unexpected_success_items = [x for x in flattened if x["expected_deploy_success"] is False and x["success"]]

    aggregate = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "cases": [f"{x['category']}/{x['case']}" for x in all_reports],
        "total_files": total_files,
        "deploy_success_count": success_count,
        "deploy_failure_count": failure_count,
        "deploy_success_rate": round(success_rate, 2),
        "deploy_failed_files": failed_files,
        "deploy_failed_stages": failed_stages,
        "expected_success_count": len(expected_success_items),
        "expected_failure_count": len(expected_failure_items),
        "expected_unknown_count": len(expected_unknown_items),
        "expected_success_files": [x["source"] for x in expected_success_items],
        "expected_failure_files": [x["source"] for x in expected_failure_items],
        "expected_unknown_files": [x["source"] for x in expected_unknown_items],
        "expectation_mismatch_count": len(mismatch_items),
        "expectation_mismatch_files": [x["source"] for x in mismatch_items],
        "unexpected_failure_count": len(unexpected_failure_items),
        "unexpected_failure_files": [x["source"] for x in unexpected_failure_items],
        "unexpected_success_count": len(unexpected_success_items),
        "unexpected_success_files": [x["source"] for x in unexpected_success_items],
        "expectation_mismatches": [
            {
                "category": x["category"],
                "case": x["case"],
                "source": x["source"],
                "min_kernel": x["min_kernel"],
                "expected_success": x["expected_deploy_success"],
                "actual_success": x["success"],
                "actual_stage": x["stage"],
            }
            for x in mismatch_items
        ],
        "reports": all_reports,
    }
    # Mode-specific aggregate report content.
    if mode_name == "agent_mode":
        aggregate = {
            "generated_at": aggregate["generated_at"],
            "cases": aggregate["cases"],
            "total_files": total_files,
            "deploy_success_count": success_count,
            "deploy_failure_count": failure_count,
            "deploy_success_rate": round(success_rate, 2),
            "deploy_failed_files": failed_files,
            "deploy_failed_stages": failed_stages,
        }
        # Always compute agent metrics so every run has consistent reporting.
        metrics_1_40 = _compute_agent_metrics_1_40(prepared_cases)
        ordered = OrderedDict()
        ordered["metrics_1_40"] = metrics_1_40
        for k, v in aggregate.items():
            ordered[k] = v
        aggregate = ordered
    report_name = "pipeline_report.json"
    if mode_name == "agent_mode":
        report_name = "agent_mode_pipeline_report.json"
    aggregate_path = mode_logs_root / report_name
    with open(aggregate_path, "w", encoding="utf-8") as f:
        json.dump(aggregate, f, indent=2, ensure_ascii=True)

    # 同步关键汇总报告到更上层目录，便于外部检索/对比。
    try:
        if mode_name == "agent_mode":
            dest_path = logs_base / "agent_mode_report.json"
            # Always copy the freshly generated report (don't prefer a possibly stale exams cache).
            shutil.copyfile(str(aggregate_path), str(dest_path))
        else:
            dest_path = logs_base / "no_agent_mode_report.json"
            shutil.copyfile(str(aggregate_path), str(dest_path))
    except Exception:
        pass

    print(f"\nAll pipelines finished. Aggregate report: {aggregate_path}")

    # bpftool_feature_probe.json is a cache; delete it after successful run.
    try:
        if global_bpftool_probe.exists():
            global_bpftool_probe.unlink()
    except Exception:
        pass
    return aggregate


if __name__ == "__main__":
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument(
        "selector",
        nargs="?",
        default=None,
        help="可选：data/ 下的子路径选择器，如 verifier 或 verifier/bpf_to_bpf_fault",
    )
    parser.add_argument(
        "--no-agent",
        action="store_true",
        help="禁用单 Agent 修复（默认启用）",
    )
    parser.add_argument(
        "--no-resolve-agent",
        action="store_true",
        help="仅禁用 Error_solver（resolve agent），仍可启用 reflect agent（如你显式开启）。",
    )
    parser.add_argument(
        "--enable-reflect-agent",
        action="store_true",
        help="显式启用 reflect agent（现已默认开启，保留该参数兼容旧调用）。",
    )
    parser.add_argument(
        "--no-reflect-agent",
        action="store_true",
        help="禁用 reflect/refiner 知识沉淀流程。",
    )
    parser.add_argument(
        "--config",
        default=str(DEFAULT_CONFIG_PATH),
        help="配置文件路径（Python），默认使用仓库根目录的 app_config.py。",
    )
    args = parser.parse_args()
    if args.no_agent:
        enable_resolve_agent = False
        enable_reflect_agent = False
    else:
        enable_resolve_agent = not args.no_resolve_agent
        enable_reflect_agent = not args.no_reflect_agent
    run_for_groups(
        args.selector,
        enable_resolve_agent=enable_resolve_agent,
        enable_reflect_agent=enable_reflect_agent,
        config_path=args.config,
    )
