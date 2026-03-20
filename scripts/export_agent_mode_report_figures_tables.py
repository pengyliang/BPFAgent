#!/usr/bin/env python3
"""
Export academic figures/tables from output/*/log/agent_mode_report.json

Outputs (in --out dir):
  - fig_initial_failed_stage_distribution.svg
  - fig_repair_round_histogram.svg
  - fig_final_failure_stage_distribution.svg
  - fig_error_signature_topN.svg
  - table_metrics_overview.csv
  - table_error_signature_topN.csv

No HTML is generated.

Usage:
  python3 scripts/export_agent_mode_report_figures_tables.py \
    --input output/5.4/log/agent_mode_report.json \
    --out /tmp/agent_mode_vis_5_4
"""

from __future__ import annotations

import argparse
import csv
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class Metric:
    id: int
    name: str
    value: Any


def _svg_escape(s: str) -> str:
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _index_metrics(report: dict[str, Any]) -> dict[int, Metric]:
    raw = report.get("metrics_1_40") or []
    out: dict[int, Metric] = {}
    for item in raw:
        try:
            mid = int(item["id"])
            name = str(item["name"])
            value = item.get("value")
        except Exception:
            continue
        out[mid] = Metric(id=mid, name=name, value=value)
    return out


def _to_float_or_none(x: Any) -> float | None:
    try:
        return float(x)
    except Exception:
        return None


def _bar_chart_horizontal_svg(
    title: str,
    data: dict[str, Any],
    *,
    filename_hint: str,
    width: int = 980,
    left: int = 250,
    right: int = 40,
    top: int = 48,
    bar_h: int = 34,
    row_gap: int = 10,
    font_title: int = 18,
    font_axis: int = 12,
    font_label: int = 12,
) -> str:
    """
    Academic-ish horizontal bar chart (SVG, no dependencies).
    data: category -> numeric value
    """
    items: list[tuple[str, float]] = []
    for k, v in (data or {}).items():
        fv = _to_float_or_none(v)
        if fv is None:
            continue
        items.append((str(k), fv))
    # sort: desc by value, then label
    items.sort(key=lambda x: (-x[1], x[0]))

    max_v = max((v for _, v in items), default=0.0)
    if max_v <= 0:
        max_v = 1.0

    chart_w = width - left - right
    height = top + 28 + len(items) * (bar_h + row_gap) + 20

    # Determine x ticks
    ticks = [0.0, 0.25 * max_v, 0.5 * max_v, 0.75 * max_v, max_v]

    parts: list[str] = []
    parts.append(f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}">')
    parts.append(
        """
  <defs>
    <style>
      .title { font: 700 %dpx/1.2 sans-serif; fill:#111; }
      .label { font: %dpx/1.2 sans-serif; fill:#222; }
      .tick  { font: %dpx/1.2 sans-serif; fill:#333; }
      .grid { stroke:#e6e6e6; stroke-width:1; vector-effect: non-scaling-stroke; }
      .axis { stroke:#111; stroke-width:1.5; vector-effect: non-scaling-stroke; }
      .bar  { fill:#1f77b4; }
      .value{ font: %dpx/1.2 sans-serif; fill:#111; }
    </style>
  </defs>
        """
        % (font_title, font_label, font_axis, font_axis)
    )

    # Title
    parts.append(f'<text x="{left}" y="28" class="title">{_svg_escape(title)}</text>')

    chart_top = top + 10
    chart_bottom = height - 20

    # Draw grid & ticks
    for tv in ticks:
        x = left + int(chart_w * (tv / max_v))
        parts.append(f'<line x1="{x}" y1="{chart_top}" x2="{x}" y2="{chart_bottom}" class="grid" />')
        # tick label under axis
        parts.append(f'<text x="{x}" y="{height - 6}" class="tick" text-anchor="middle">{tv:g}</text>')

    # Axis line
    parts.append(f'<line x1="{left}" y1="{chart_bottom}" x2="{width-right}" y2="{chart_bottom}" class="axis" />')

    # Bars
    y = chart_top
    for cat, v in items:
        bar_w = int(chart_w * (v / max_v))
        # label
        parts.append(
            f'<text x="10" y="{y + bar_h * 0.7}" class="label">{_svg_escape(cat)}</text>'
        )
        # bar
        parts.append(
            f'<rect x="{left}" y="{y}" width="{bar_w}" height="{bar_h}" rx="6" class="bar" />'
        )
        # value at end
        text_x = left + bar_w + 8
        if bar_w < 12:
            text_x = left + 8
        parts.append(
            f'<text x="{text_x}" y="{y + bar_h * 0.7}" class="value">{v:g}</text>'
        )
        y += bar_h + row_gap

    if not items:
        parts.append(f'<text x="{left}" y="{height/2}" class="label">No data</text>')

    parts.append("</svg>")
    return "\n".join(parts)


def _error_signature_table_svg(rows: list[list[str]], *, width: int = 980) -> str:
    """
    Simple SVG table for top error signatures.
    rows: [[signature, count], ...]
    """
    n = len(rows)
    row_h = 28
    header_h = 38
    height = header_h + n * row_h + 20

    col1_left = 24
    col2_left = 820

    parts: list[str] = []
    parts.append(f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}">')
    parts.append(
        """
  <defs>
    <style>
      .title { font: 700 18px/1.2 sans-serif; fill:#111; }
      .th    { font: 700 12px/1.2 sans-serif; fill:#111; }
      .td    { font: 12px/1.2 sans-serif; fill:#222; }
      .grid  { stroke:#e6e6e6; stroke-width:1; vector-effect: non-scaling-stroke; }
    </style>
  </defs>
        """
    )

    parts.append('<text x="24" y="26" class="title">Top error signatures</text>')

    # Header
    parts.append(f'<text x="{col1_left}" y="58" class="th">signature</text>')
    parts.append(f'<text x="{col2_left}" y="58" class="th">count</text>')
    parts.append(f'<line x1="20" y1="66" x2="{width-20}" y2="66" class="grid" />')

    for i, (sig, cnt) in enumerate(rows):
        y = 86 + i * row_h
        # truncate signature for visual
        sig_s = sig
        if len(sig_s) > 120:
            sig_s = sig_s[:117] + "..."
        parts.append(f'<text x="{col1_left}" y="{y}" class="td">{_svg_escape(sig_s)}</text>')
        parts.append(f'<text x="{col2_left}" y="{y}" class="td">{_svg_escape(str(cnt))}</text>')
        parts.append(f'<line x1="20" y1="{y+12}" x2="{width-20}" y2="{y+12}" class="grid" />')

    if not rows:
        parts.append(f'<text x="24" y="{height/2}" class="td">No data</text>')

    parts.append("</svg>")
    return "\n".join(parts)


def export(report_path: Path, out_dir: Path, *, top_n_errors: int = 10) -> None:
    report = _load_json(report_path)
    metrics = _index_metrics(report)

    out_dir.mkdir(parents=True, exist_ok=True)

    # IDs according to our metrics contract
    # id=15 initial_failed_stage_distribution_count
    # id=25 repair_round_histogram
    # id=23 final_failure_stage_distribution_all
    # id=35 error_signature_counts_top10
    # also export overview table for everything

    initial_failed = metrics.get(15).value if 15 in metrics else {}
    repair_round_hist = metrics.get(25).value if 25 in metrics else {}
    final_failed = metrics.get(23).value if 23 in metrics else {}
    error_top = metrics.get(35).value if 35 in metrics else []

    # Figures
    fig1 = _bar_chart_horizontal_svg(
        "Initial failed stage distribution (count)",
        initial_failed if isinstance(initial_failed, dict) else {},
        filename_hint="initial_failed",
    )
    (out_dir / "fig_initial_failed_stage_distribution.svg").write_text(fig1, encoding="utf-8")

    hist_data: dict[str, Any] = {}
    if isinstance(repair_round_hist, dict):
        for k, v in repair_round_hist.items():
            hist_data[str(k)] = v
    fig2 = _bar_chart_horizontal_svg(
        "Repair rounds histogram (count)",
        hist_data,
        filename_hint="repair_rounds",
    )
    (out_dir / "fig_repair_round_histogram.svg").write_text(fig2, encoding="utf-8")

    fig3 = _bar_chart_horizontal_svg(
        "Final failure stage distribution (count)",
        final_failed if isinstance(final_failed, dict) else {},
        filename_hint="final_failed",
    )
    (out_dir / "fig_final_failure_stage_distribution.svg").write_text(fig3, encoding="utf-8")

    # Error table
    rows: list[list[str]] = []
    if isinstance(error_top, list):
        for item in error_top[:top_n_errors]:
            if isinstance(item, list) and len(item) >= 2:
                rows.append([str(item[0]), str(item[1])])
    fig4 = _error_signature_table_svg(rows)
    (out_dir / f"fig_error_signature_top{top_n_errors}.svg").write_text(fig4, encoding="utf-8")

    # Tables (CSV)
    # Metrics overview: id,name,value_json
    metrics_overview_path = out_dir / "table_metrics_overview.csv"
    with metrics_overview_path.open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["id", "name", "value_json"])
        # keep id order
        for mid in sorted(metrics.keys()):
            m = metrics[mid]
            w.writerow([m.id, m.name, json.dumps(m.value, ensure_ascii=False)])

    # Error signature CSV
    err_csv_path = out_dir / f"table_error_signature_top{top_n_errors}.csv"
    with err_csv_path.open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["signature", "count"])
        for sig, cnt in rows:
            w.writerow([sig, cnt])

    print("[OK] Exported figures/tables to:", out_dir)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, help="Path to agent_mode_report.json")
    parser.add_argument("--out", required=False, default=None, help="Output directory")
    parser.add_argument("--top-errors", type=int, default=10, help="Top-N error signatures")
    args = parser.parse_args()

    input_path = Path(args.input).expanduser().resolve()
    if not input_path.exists():
        raise FileNotFoundError(str(input_path))

    out_dir = (
        Path(args.out).expanduser().resolve()
        if args.out
        else (input_path.parent / "viz_agent_mode_export")
    )
    export(input_path, out_dir, top_n_errors=args.top_errors)


if __name__ == "__main__":
    main()

