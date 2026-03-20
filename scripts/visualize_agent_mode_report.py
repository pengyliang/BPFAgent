#!/usr/bin/env python3
"""
Visualize output/*/log/agent_mode_report.json (agent metrics).

No third-party plotting dependency: we render simple SVG charts and a single HTML page.

Usage examples:
  python3 scripts/visualize_agent_mode_report.py \
    --input output/5.4/log/agent_mode_report.json \
    --out /tmp/agent_mode_vis_5_4
"""

from __future__ import annotations

import argparse
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


@dataclass(frozen=True)
class Metric:
    id: int
    name: str
    value: Any


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _index_metrics(report: dict[str, Any]) -> tuple[dict[int, Metric], dict[str, Metric]]:
    raw = report.get("metrics_1_40") or []
    by_id: dict[int, Metric] = {}
    by_name: dict[str, Metric] = {}
    for item in raw:
        try:
            m_id = int(item["id"])
            m_name = str(item["name"])
            m_value = item.get("value")
        except Exception:
            continue
        m = Metric(id=m_id, name=m_name, value=m_value)
        by_id[m_id] = m
        by_name[m_name] = m
    return by_id, by_name


def _fmt_rate(x: Any) -> str:
    if x is None:
        return "N/A"
    try:
        f = float(x)
    except Exception:
        return str(x)
    # stored as [0,1] for most rates; also tolerate values already in [0,100]
    if f <= 1.0:
        return f"{f * 100:.2f}%"
    return f"{f:.2f}%"


def _svg_escape(s: str) -> str:
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


def _bar_chart_svg(
    title: str,
    data: dict[str, Any],
    *,
    width: int = 980,
    bar_height: int = 34,
    row_gap: int = 10,
    left_margin: int = 220,
    right_margin: int = 30,
) -> str:
    """
    Render a horizontal-bar list (SVG).
    data: label -> numeric value
    """
    # Normalize
    items: list[tuple[str, float]] = []
    for k, v in data.items():
        try:
            items.append((str(k), float(v)))
        except Exception:
            continue

    # Sort by value descending, then label
    items.sort(key=lambda x: (-x[1], x[0]))

    max_v = max((v for _, v in items), default=0.0)
    if max_v <= 0:
        max_v = 1.0

    chart_width = width - left_margin - right_margin
    height = 60 + len(items) * (bar_height + row_gap)

    parts: list[str] = []
    parts.append(f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}">')
    parts.append('<style>')
    parts.append("""
      .title { font: 700 18px/1.2 sans-serif; fill: #111; }
      .rowLabel { font: 12px/1.2 sans-serif; fill: #222; }
      .bar { fill: #2f6fed; }
      .value { font: 12px/1.2 sans-serif; fill: #111; }
      .grid { stroke: #e6e6e6; stroke-width: 1; }
    """)
    parts.append("</style>")

    parts.append(f'<text x="{left_margin}" y="28" class="title">{_svg_escape(title)}</text>')

    # Grid lines
    for i, frac in enumerate([0.25, 0.5, 0.75, 1.0]):
        x = left_margin + int(chart_width * frac)
        parts.append(f'<line x1="{x}" y1="50" x2="{x}" y2="{height-20}" class="grid" />')

    y = 55
    for label, v in items:
        bar_w = int(chart_width * (v / max_v))
        parts.append(
            f'<text x="10" y="{y + 22}" class="rowLabel">{_svg_escape(label)}</text>'
        )
        parts.append(
            f'<rect x="{left_margin}" y="{y}" width="{bar_w}" height="{bar_height}" class="bar" rx="6" />'
        )
        parts.append(
            f'<text x="{left_margin + bar_w + 8}" y="{y + 22}" class="value">{_svg_escape(str(v))}</text>'
        )
        y += bar_height + row_gap

    if not items:
        parts.append(f'<text x="{left_margin}" y="90" class="rowLabel">No data</text>')

    parts.append("</svg>")
    return "\n".join(parts)


def _table_svg_rows(rows: list[list[str]], *, max_rows: int = 12) -> str:
    # Very small table rendered in SVG; caller wraps.
    trimmed = rows[:max_rows]
    # columns: 0 title, 1 count
    col1_w = 650
    col2_w = 160
    header_h = 34
    row_h = 28
    height = 70 + len(trimmed) * row_h
    width = 980
    parts: list[str] = []
    parts.append(f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}">')
    parts.append('<style>')
    parts.append(
        """
      .h { font: 700 14px/1.2 sans-serif; fill: #111; }
      .c { font: 12px/1.2 sans-serif; fill: #222; }
      .grid { stroke: #e6e6e6; stroke-width: 1; }
      .cell { dominant-baseline: middle; }
    """
    )
    parts.append("</style>")
    parts.append(f'<text x="24" y="26" class="h">Top errors (signature -> count)</text>')
    parts.append(f'<line x1="20" y1="42" x2="{width-20}" y2="42" class="grid" />')

    # Header
    parts.append(f'<text x="24" y="68" class="c">signature</text>')
    parts.append(f'<text x="{20+col1_w+12}" y="68" class="c">count</text>')
    parts.append(f'<line x1="20" y1="75" x2="{width-20}" y2="75" class="grid" />')

    y = 93
    for sig, cnt in trimmed:
        sig_s = sig
        if len(sig_s) > 80:
            sig_s = sig_s[:77] + "..."
        parts.append(f'<text x="24" y="{y}" class="c cell">{_svg_escape(sig_s)}</text>')
        parts.append(f'<text x="{20+col1_w+12}" y="{y}" class="c cell">{_svg_escape(cnt)}</text>')
        parts.append(f'<line x1="20" y1="{y+row_h/2}" x2="{width-20}" y2="{y+row_h/2}" class="grid" />')
        y += row_h

    if not trimmed:
        parts.append(f'<text x="24" y="110" class="c">No data</text>')

    parts.append("</svg>")
    return "\n".join(parts)


def render_dashboard(input_path: Path, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)

    report = _load_json(input_path)
    metrics_by_id, metrics_by_name = _index_metrics(report)

    def metric_value(name: str | None = None, mid: int | None = None) -> Any:
        if mid is not None:
            m = metrics_by_id.get(mid)
            return None if m is None else m.value
        if name is not None:
            m = metrics_by_name.get(name)
            return None if m is None else m.value
        return None

    # Extract common metrics by ids based on our contract
    success_rate = metric_value(mid=6)  # total_repair_success_rate
    initial_failed_stage_counts = metric_value(mid=15) or {}
    repair_round_histogram = metric_value(mid=25) or {}
    final_failed_stage_distribution_all = metric_value(mid=23) or {}
    error_sig_top = metric_value(mid=35) or []  # list of [sig, cnt]

    # Prepare figures
    initial_failed_svg = _bar_chart_svg("Initial failed stage distribution (count)", initial_failed_stage_counts)

    # For histogram, convert to label->value
    hist_data: dict[str, Any] = {}
    if isinstance(repair_round_histogram, dict):
        for k, v in repair_round_histogram.items():
            hist_data[str(k)] = v
    repair_hist_svg = _bar_chart_svg("Repair rounds histogram (count)", hist_data)

    final_failed_svg = _bar_chart_svg(
        "Final failure stage distribution (count, among initially failed cases)",
        final_failed_stage_distribution_all,
    )

    top_errors_rows: list[list[str]] = []
    if isinstance(error_sig_top, list):
        for item in error_sig_top[:10]:
            if isinstance(item, list) and len(item) >= 2:
                top_errors_rows.append([str(item[0]), str(item[1])])
    top_errors_svg = _table_svg_rows(top_errors_rows)

    total_files = report.get("total_files")
    deploy_success_rate = report.get("deploy_success_rate")
    cases = report.get("cases") or []

    # Top summary
    success_rate_str = _fmt_rate(success_rate)
    deploy_success_rate_str = _fmt_rate(deploy_success_rate) if isinstance(deploy_success_rate, (int, float)) else (
        str(deploy_success_rate) if deploy_success_rate is not None else "N/A"
    )

    # Generate HTML
    html_parts: list[str] = []
    html_parts.append("<!doctype html>")
    html_parts.append('<html lang="zh-CN">')
    html_parts.append("<head>")
    html_parts.append('  <meta charset="utf-8" />')
    html_parts.append("  <title>agent_mode_report 覆盖指标可视化</title>")
    html_parts.append(
        "  <style>body{font-family:Arial, sans-serif; margin:24px; color:#111;} "
        ".grid{display:flex; flex-wrap:wrap; gap:24px;} "
        ".card{border:1px solid #eee; border-radius:12px; padding:16px 18px; min-width:320px; background:#fafafa;} "
        "h1{font-size:22px; margin:0 0 12px;} .k{color:#444;} .v{font-weight:700;} "
        ".section{margin-top:18px;} </style>"
    )
    html_parts.append("</head>")
    html_parts.append("<body>")
    html_parts.append("<h1>agent_mode_report.json 指标可视化</h1>")

    html_parts.append('<div class="grid">')
    html_parts.append(
        f'<div class="card"><div class="k">Total files</div><div class="v">{_svg_escape(str(total_files))}</div></div>'
    )
    html_parts.append(
        f'<div class="card"><div class="k">Deploy success rate</div><div class="v">{_svg_escape(deploy_success_rate_str)}</div></div>'
    )
    html_parts.append(
        f'<div class="card"><div class="k">Repair success rate</div><div class="v">{_svg_escape(success_rate_str)}</div></div>'
    )
    html_parts.append(
        f'<div class="card"><div class="k">Cases</div><div class="v">{_svg_escape(str(len(cases)))}</div></div>'
    )
    html_parts.append("</div>")

    html_parts.append('<div class="section">')
    html_parts.append(initial_failed_svg)
    html_parts.append("</div>")

    html_parts.append('<div class="section">')
    html_parts.append(repair_hist_svg)
    html_parts.append("</div>")

    html_parts.append('<div class="section">')
    html_parts.append(final_failed_svg)
    html_parts.append("</div>")

    html_parts.append('<div class="section">')
    html_parts.append(top_errors_svg)
    html_parts.append("</div>")

    html_parts.append("</body></html>")

    out_html = out_dir / "agent_mode_report_dashboard.html"
    out_html.write_text("\n".join(html_parts), encoding="utf-8")
    print(f"[OK] Wrote: {out_html}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--input",
        required=True,
        help="Path to agent_mode_report.json",
    )
    parser.add_argument(
        "--out",
        required=False,
        default=None,
        help="Output directory (default: <input-dir>/viz_agent_mode)",
    )
    args = parser.parse_args()

    input_path = Path(args.input).expanduser().resolve()
    if not input_path.exists():
        raise FileNotFoundError(str(input_path))

    out_dir = Path(args.out).expanduser().resolve() if args.out else (input_path.parent / "viz_agent_mode")
    render_dashboard(input_path, out_dir)


if __name__ == "__main__":
    main()

