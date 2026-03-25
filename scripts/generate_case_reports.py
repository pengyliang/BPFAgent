#!/usr/bin/env python3
"""
Generate CSV reports from workflow_summary.json.

Reads:
  output/<version>/log/<mode_name>/**/workflow_summary.json

Writes:
  output/<version>/log/reports/case_summary.csv
  output/<version>/log/reports/case_stage_record.csv

The output schema matches the "数据设计" in this repo.
"""

from __future__ import annotations

import argparse
import csv
import json
import time
import os
from datetime import datetime
from pathlib import Path


def parse_iso(ts: str) -> datetime:
    return datetime.fromisoformat(ts)


def fmt_bool(v: object) -> str:
    if v is True:
        return "true"
    if v is False:
        return "false"
    return ""


def fmt_opt2(v: object) -> str:
    if v is None:
        return ""
    try:
        return f"{float(v):.2f}"
    except Exception:
        return ""


def last_analyzer_error_for_node_index(events_sorted: list[dict], node_index: object) -> str:
    if node_index is None:
        return ""
    last = None
    for e in reversed(events_sorted):
        if e.get("node") == "Analyzer" and e.get("node_index") == node_index:
            last = e
            break
    if not last:
        return ""
    return (last.get("key_results") or {}).get("error_type") or ""


def compute_durations_seconds(events_sorted: list[dict]) -> list[float | None]:
    # duration[i] = ts[i] - ts[i-1], aligned to event i (current event)
    durations: list[float | None] = [None] * len(events_sorted)
    for i in range(1, len(events_sorted)):
        ts_prev = events_sorted[i - 1].get("ts")
        ts_cur = events_sorted[i].get("ts")
        if not ts_prev or not ts_cur:
            continue
        try:
            dt = parse_iso(ts_cur) - parse_iso(ts_prev)
            durations[i] = round(max(0.0, dt.total_seconds()), 2)
        except Exception:
            continue
    return durations


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True, help="如 5.4 / 5.15 / 6.6")
    parser.add_argument("--mode", default="agent_mode", help="agent_mode 或 no_agent_mode")
    parser.add_argument(
        "--out-dir",
        default="",
        help="可选：报告输出目录（默认 output/<version>/log/reports）。写权限不足时会自动 fallback 到临时目录。",
    )
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parents[1]
    output_root = repo_root / "output" / args.version / "log"
    mode_root = output_root / args.mode

    default_reports_dir = output_root / "reports"
    if args.out_dir:
        reports_dir = Path(args.out_dir).expanduser().resolve()
    else:
        reports_dir = default_reports_dir

    def _ensure_dir(p: Path) -> None:
        p.mkdir(parents=True, exist_ok=True)

    fallback_dir = repo_root / "_case_reports_tmp" / args.version / args.mode
    reports_dir_writable = False
    try:
        _ensure_dir(reports_dir)
        reports_dir_writable = os.access(str(reports_dir), os.W_OK)
    except Exception:
        reports_dir_writable = False

    if not reports_dir_writable:
        _ensure_dir(fallback_dir)
        print(f"[WARN] 目标目录不可写: {reports_dir}. 将改写到: {fallback_dir}")
        reports_dir = fallback_dir

    if not mode_root.exists():
        raise FileNotFoundError(f"mode_root 不存在: {mode_root}")

    workflow_paths = sorted(mode_root.rglob("workflow_summary.json"))
    if not workflow_paths:
        raise RuntimeError(f"未找到 workflow_summary.json: {mode_root}")

    # case_summary.csv
    headers_case = [
        "case_id",
        "initial_deploy_state",
        "final_deploy_state",
        "total_time",
        "final_failed_stage",
        "final_error_type",
        "total_repair_round",
        "analyzer_round",
        "repairer_round",
        "inspector_round",
        "refiner_round",
        "analyzer_time_consumption",
        "repairer_time_consumption",
        "inspector_time_consumption",
        "refiner_time_consumption",
        "total_agent_calls",
        "deploy_tool_round",
        "first_analyzer_can_fix",
        "last_analyzer_can_fix",
    ]

    # case_stage_record.csv
    headers_stage = ["case_id", "attempt_no", "deploy_success", "failed_stage", "error_type"]

    case_rows: list[list[str]] = []
    stage_rows: list[list[str]] = []

    for wf_path in workflow_paths:
        rel = wf_path.relative_to(mode_root)
        case_id = "/".join(rel.parts[:-1])  # drop workflow_summary.json

        wf = json.loads(wf_path.read_text(encoding="utf-8"))
        events = wf.get("events") or []
        if not events:
            continue

        events_sorted = sorted(events, key=lambda x: x.get("seq", 0))
        durations = compute_durations_seconds(events_sorted)

        ts0 = events_sorted[0].get("ts")
        tsN = events_sorted[-1].get("ts")
        total_time_s = None
        if ts0 and tsN:
            try:
                total_time_s = round(max(0.0, (parse_iso(tsN) - parse_iso(ts0)).total_seconds()), 2)
            except Exception:
                total_time_s = None

        deploy_events = [e for e in events_sorted if e.get("node") == "deploy_tool"]

        # initial deploy state from the first deploy_tool attempt
        initial_deploy_state = None
        if deploy_events:
            kr0 = deploy_events[0].get("key_results") or {}
            if "deploy_state" in kr0:
                initial_deploy_state = kr0.get("deploy_state")

        final_deploy_state = bool(wf.get("deploy_state"))
        final_failed_stage = "" if final_deploy_state else (wf.get("failed_stage") or "")

        def sum_time(node_name: str) -> float:
            s = 0.0
            for e, d in zip(events_sorted, durations):
                if e.get("node") == node_name and isinstance(d, (int, float)):
                    s += float(d)
            return round(s, 2)

        analyzer_time = sum_time("Analyzer")
        repairer_time = sum_time("Repairer")
        inspector_time = sum_time("Inspector")
        refiner_time = sum_time("Refiner")

        analyzer_round = sum(1 for e in events_sorted if e.get("node") == "Analyzer")
        repairer_round = sum(1 for e in events_sorted if e.get("node") == "Repairer")
        inspector_round = sum(1 for e in events_sorted if e.get("node") == "Inspector")
        refiner_round = sum(1 for e in events_sorted if e.get("node") == "Refiner")

        total_agent_calls = sum(1 for e in events_sorted if e.get("node") in {"Analyzer", "Repairer", "Inspector", "Refiner"})
        deploy_tool_round = len(deploy_events)

        analyzers = [e for e in events_sorted if e.get("node") == "Analyzer"]
        first_analyzer_can_fix = (analyzers[0].get("key_results") or {}).get("can_fix") if analyzers else None
        last_analyzer_can_fix = (analyzers[-1].get("key_results") or {}).get("can_fix") if analyzers else None

        final_error_type = ""
        if not final_deploy_state:
            # last failed deploy_tool attempt
            last_failed_dep = None
            for dep in deploy_events:
                dep_kr = dep.get("key_results") or {}
                dep_success = bool(dep_kr.get("deploy_state")) if "deploy_state" in dep_kr else False
                if not dep_success:
                    last_failed_dep = dep
            if last_failed_dep:
                final_error_type = last_analyzer_error_for_node_index(events_sorted, last_failed_dep.get("node_index"))

        total_repair_round = repairer_round

        case_rows.append(
            [
                case_id,
                fmt_bool(initial_deploy_state),
                fmt_bool(final_deploy_state),
                fmt_opt2(total_time_s),
                final_failed_stage,
                final_error_type,
                str(total_repair_round),
                str(analyzer_round),
                str(repairer_round),
                str(inspector_round),
                str(refiner_round),
                fmt_opt2(analyzer_time),
                fmt_opt2(repairer_time),
                fmt_opt2(inspector_time),
                fmt_opt2(refiner_time),
                str(total_agent_calls),
                str(deploy_tool_round),
                fmt_bool(first_analyzer_can_fix),
                fmt_bool(last_analyzer_can_fix),
            ]
        )

        # stage record: one row per deploy_tool attempt
        analyzer_by_idx: dict[object, dict] = {}
        for e in events_sorted:
            if e.get("node") == "Analyzer" and e.get("node_index") is not None:
                analyzer_by_idx[e.get("node_index")] = e

        for attempt_no, dep in enumerate(deploy_events, start=1):
            dep_kr = dep.get("key_results") or {}
            dep_success = bool(dep_kr.get("deploy_state")) if "deploy_state" in dep_kr else False
            failed_stage = "" if dep_success else (dep_kr.get("failed_stage") or "")
            error_type = ""
            if not dep_success:
                error_type = (analyzer_by_idx.get(dep.get("node_index")) or {}).get("key_results", {}).get("error_type") or ""

            stage_rows.append([case_id, str(attempt_no), fmt_bool(dep_success), failed_stage, error_type])

    case_summary_path = reports_dir / "case_summary.csv"
    stage_record_path = reports_dir / "case_stage_record.csv"

    def _write_csv(path: Path, headers: list[str], rows: list[list[str]]) -> Path:
        try:
            with path.open("w", encoding="utf-8", newline="") as f:
                w = csv.writer(f)
                w.writerow(headers)
                w.writerows(rows)
            return path
        except PermissionError:
            ts = int(time.time())
            alt = fallback_dir / f"{path.name}.permdenied_{ts}"
            with alt.open("w", encoding="utf-8", newline="") as f:
                w = csv.writer(f)
                w.writerow(headers)
                w.writerows(rows)
            print(f"[WARN] Permission denied when writing {path.name}. Wrote instead: {alt}")
            return alt

    written_case = _write_csv(case_summary_path, headers_case, case_rows)
    written_stage = _write_csv(stage_record_path, headers_stage, stage_rows)

    print(f"[OK] case_summary.csv: {written_case} (rows={len(case_rows)})")
    print(f"[OK] case_stage_record.csv: {written_stage} (rows={len(stage_rows)})")


if __name__ == "__main__":
    main()

