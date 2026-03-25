#!/usr/bin/env python3
"""
Grouped bar chart: per-kernel-version deploy success rate for each LLM.

Reads experiments/processed_data/llm_case_summary.csv
and aggregates by (llm_name, kernel_version).

Required fields:
  - llm_name
  - kernel_version
  - initial_deploy_state
  - final_deploy_state

Design (图表设计 §1):
  - X: kernel version
  - Grouped bars: one per LLM (final success rate)
  - Gray dashed segment per bar: initial success rate at that LLM/version
  - Value labels on top of final bars

Dependencies: matplotlib, numpy
  pip install matplotlib numpy
"""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

try:
    import matplotlib.pyplot as plt  # pyright: ignore[reportMissingImports]
except ImportError:
    print("Please install matplotlib: pip install matplotlib", file=sys.stderr)
    raise


# =========================
# 可编辑绘图参数（集中配置）
# =========================
# 画布与导出
DEFAULT_FIG_WIDTH = 6.0
DEFAULT_FIG_HEIGHT = 5.5
DEFAULT_DPI = 300
SAVE_BBOX_INCHES = "tight"

# 字体与字号
AXES_TITLE_SIZE = 13
AXES_LABEL_SIZE = 11
TICK_LABEL_SIZE = 10
VALUE_LABEL_FONTSIZE = 6

# 柱状图布局
GROUP_STEP = 0.8          # 组中心间距（<1 更紧凑，>1 更松）
GROUP_SPAN = 0.70         # 每个组横向占用（越大组间空隙越小）
BAR_WIDTH_RATIO = 0.95    # 柱宽占 bar slot 的比例
VALUE_LABEL_DY = 1.2      # 柱顶数值标签上移量

# 标题/图例/留白（位置调参最常用）
SUPTITLE_Y = 0.650         # suptitle 的 y（越大越靠上）
LEGEND_Y = 1.30           # 图例 bbox_to_anchor 的 y（越大越靠上）
LEGEND_MAX_COLS = 3       # 图例最多列数；超出会自动换行（例如 5 项 -> 3+2）
TIGHT_TOP = 0.80          # tight_layout rect top（越小顶部留白越大）

# Baseline 虚线
BASELINE_COLOR = "#111111"
BASELINE_LINEWIDTH = 1.2
BASELINE_DASH = (0, (3, 3))

# 配色（更柔和的论文风格）
LLM_COLORS = {
    "DeepSeek": "#4e79a7",      # soft blue
    "GLM": "#59a14f",           # soft green
    "Doubao": "#f28e2b",        # soft orange
    "MiniMax": "#af7aa1",       # soft purple
    "Manual Repair": "#e15759", # soft red
}


def _repo_root_from_script() -> Path:
    return Path(__file__).resolve().parents[3]


def _version_sort_key(v: str) -> Tuple:
    parts = []
    for p in v.replace("_", ".").split("."):
        if p.isdigit():
            parts.append(int(p))
        else:
            parts.append(p)
    return tuple(parts)


def _parse_bool_cell(raw: str) -> bool:
    s = str(raw).strip().lower()
    return s in ("true", "1", "yes", "t")


def load_rates_from_csv(path: Path) -> Optional[Tuple[float, float, int]]:
    """Return (initial_rate_pct, final_rate_pct, n_rows) or None if unreadable."""
    if not path.is_file():
        return None
    try:
        with path.open(encoding="utf-8", errors="replace", newline="") as f:
            reader = csv.DictReader(f)
            if not reader.fieldnames:
                return None
            rows = list(reader)
    except OSError:
        return None
    if not rows:
        return None
    ini = fin = 0
    for row in rows:
        ini += 1 if _parse_bool_cell(row.get("initial_deploy_state", "")) else 0
        fin += 1 if _parse_bool_cell(row.get("final_deploy_state", "")) else 0
    n = len(rows)
    return (100.0 * ini / n, 100.0 * fin / n, n)


def discover_llm_version_grid(llm_root: Path) -> Tuple[List[str], List[str], Dict[Tuple[str, str], Path]]:
    """Return sorted llm_names, sorted versions, and map (llm, version) -> csv path."""
    if not llm_root.is_dir():
        return [], [], {}

    llm_names = sorted(p.name for p in llm_root.iterdir() if p.is_dir() and not p.name.startswith("."))
    version_set: set = set()
    paths: Dict[Tuple[str, str], Path] = {}

    for llm in llm_names:
        llm_dir = llm_root / llm
        for sub in llm_dir.iterdir():
            if not sub.is_dir():
                continue
            v = sub.name
            if v in {"original_logs", "__pycache__"}:
                continue
            rel = sub / "reports" / "case_summary.csv"
            if rel.is_file():
                version_set.add(v)
                paths[(llm, v)] = rel

    versions = sorted(version_set, key=_version_sort_key)
    # Only LLMs that have at least one case_summary (avoid empty columns in the chart).
    llm_with_data = sorted({llm for (llm, _) in paths.keys()})
    return llm_with_data, versions, paths


def _configure_style(*, use_zh: bool, font_family: Optional[str]) -> None:
    # Prefer a clean academic style (white background, minimal grid).
    for style in ("seaborn-v0_8-white", "seaborn-white", "default"):
        try:
            plt.style.use(style)
            break
        except OSError:
            continue

    plt.rcParams.update(
        {
            "figure.facecolor": "#ffffff",
            "axes.facecolor": "#ffffff",
            "savefig.facecolor": "#ffffff",
            "axes.edgecolor": "#333333",
            "axes.labelcolor": "#111111",
            "axes.titleweight": "normal",
            "axes.titlesize": AXES_TITLE_SIZE,
            "axes.labelsize": AXES_LABEL_SIZE,
            "xtick.labelsize": TICK_LABEL_SIZE,
            "ytick.labelsize": TICK_LABEL_SIZE,
            "grid.color": "#e6e6e6",
            "grid.linestyle": "-",
            "grid.linewidth": 0.8,
            "grid.alpha": 1.0,
            "legend.frameon": False,
        }
    )
    # Academic sans-serif preference (fallback to DejaVu Sans).
    plt.rcParams["font.family"] = "sans-serif"
    plt.rcParams["font.sans-serif"] = [
        *( [font_family] if font_family else [] ),
        "Helvetica",
        "Arial",
        "DejaVu Sans",
    ]
    if use_zh:
        plt.rcParams["font.sans-serif"] = [
            *( [font_family] if font_family else [] ),
            "Noto Sans CJK SC",
            "WenQuanYi Zen Hei",
            "Source Han Sans SC",
            "SimHei",
            "Microsoft YaHei",
            "PingFang SC",
            "DejaVu Sans",
        ]
        plt.rcParams["axes.unicode_minus"] = False


def plot_deploy_success_rate(
    *,
    case_summary_csv: Path,
    output: Path,
    title: Optional[str],
    use_zh: bool,
    font_family: Optional[str],
    fig_width: float,
    fig_height: float,
    dpi: int,
) -> None:
    if not case_summary_csv.is_file():
        print(f"No llm_case_summary.csv found: {case_summary_csv}", file=sys.stderr)
        sys.exit(1)

    # Aggregate (llm_name, kernel_version) group rates.
    llms_set: set[str] = set()
    versions_set: set[str] = set()
    ini_counts: Dict[Tuple[str, str], int] = {}
    fin_counts: Dict[Tuple[str, str], int] = {}
    group_counts: Dict[Tuple[str, str], int] = {}
    # Baseline: initial deploy success aggregated by kernel_version.
    ini_by_ver: Dict[str, int] = {}
    total_by_ver: Dict[str, int] = {}

    try:
        with case_summary_csv.open("r", encoding="utf-8", errors="replace", newline="") as f:
            reader = csv.DictReader(f)
            if not reader.fieldnames:
                raise ValueError("missing header")
            rows = list(reader)
    except OSError as e:
        print(f"Failed reading: {case_summary_csv}: {e}", file=sys.stderr)
        sys.exit(1)

    if not rows:
        print(f"No rows in {case_summary_csv}", file=sys.stderr)
        sys.exit(1)

    for row in rows:
        llm = str(row.get("llm_name") or "").strip()
        ver = str(row.get("kernel_version") or "").strip()
        if not llm or not ver:
            continue
        key = (llm, ver)
        llms_set.add(llm)
        versions_set.add(ver)
        group_counts[key] = int(group_counts.get(key) or 0) + 1
        total_by_ver[ver] = int(total_by_ver.get(ver) or 0) + 1
        if _parse_bool_cell(row.get("initial_deploy_state", "")):
            ini_counts[key] = int(ini_counts.get(key) or 0) + 1
            ini_by_ver[ver] = int(ini_by_ver.get(ver) or 0) + 1
        if _parse_bool_cell(row.get("final_deploy_state", "")):
            fin_counts[key] = int(fin_counts.get(key) or 0) + 1

    def _llm_display_name(raw: str) -> str:
        low = str(raw or "").strip().lower()
        if "deepseek" in low:
            return "DeepSeek"
        if low.startswith("glm") or "chatglm" in low:
            return "GLM"
        if "doubao" in low:
            return "Doubao"
        if "minimax" in low:
            return "MiniMax"
        return str(raw or "").strip() or "Unknown"

    # Map raw llm_name -> display name (may collapse variants).
    # If multiple raw names collapse to one display name, we keep them separate in aggregation by raw key,
    # but for plotting we want stable legend names; therefore we aggregate again by display name.
    disp_llms_set: set[str] = set()
    disp_ini: Dict[Tuple[str, str], int] = {}
    disp_fin: Dict[Tuple[str, str], int] = {}
    disp_total: Dict[Tuple[str, str], int] = {}
    for (raw_llm, ver), n in group_counts.items():
        d = _llm_display_name(raw_llm)
        disp_llms_set.add(d)
        k = (d, ver)
        disp_total[k] = int(disp_total.get(k) or 0) + int(n or 0)
        disp_ini[k] = int(disp_ini.get(k) or 0) + int(ini_counts.get((raw_llm, ver)) or 0)
        disp_fin[k] = int(disp_fin.get(k) or 0) + int(fin_counts.get((raw_llm, ver)) or 0)

    # Optional: add a "Manual Repair" series from experiments/manual_repair/expected_repaired_cases.csv
    manual_csv = _repo_root_from_script() / "experiments" / "manual_repair" / "expected_repaired_cases.csv"
    manual_rates: Dict[str, float] = {}
    if manual_csv.is_file():
        try:
            with manual_csv.open("r", encoding="utf-8", errors="replace", newline="") as f:
                reader = csv.DictReader(f)
                manual_rows = list(reader)
            if manual_rows:
                ver_keys = [v for v in (versions_set or set())]
                # Use the same versions discovered from llm_case_summary, and treat empty cells as 0.
                total_cases = len(manual_rows)
                for ver in ver_keys:
                    ok = 0
                    for r in manual_rows:
                        cell = str(r.get(ver) or "").strip()
                        ok += 1 if cell in {"1", "true", "True", "yes", "YES"} else 0
                    manual_rates[ver] = (100.0 * ok / total_cases) if total_cases > 0 else 0.0
                disp_llms_set.add("Manual Repair")
        except Exception:
            manual_rates = {}

    # Stable plotting order and colorblind-friendly palette (Tableau-like).
    plot_order = ["DeepSeek", "GLM", "Doubao", "MiniMax", "Manual Repair"]
    llms = [name for name in plot_order if name in disp_llms_set] + sorted([x for x in disp_llms_set if x not in set(plot_order)])
    versions = sorted(versions_set, key=_version_sort_key)
    if not versions or not llms:
        print(f"No valid (llm_name, kernel_version) groups in {case_summary_csv}", file=sys.stderr)
        sys.exit(1)

    _configure_style(use_zh=use_zh, font_family=font_family)

    n_v, n_l = len(versions), len(llms)
    # final[i][j] = final rate for version i, llm j
    final: List[List[Optional[float]]] = [[None for _ in range(n_l)] for _ in range(n_v)]
    counts: List[List[int]] = [[0 for _ in range(n_l)] for _ in range(n_v)]

    for j, llm in enumerate(llms):
        for i, ver in enumerate(versions):
            if llm == "Manual Repair" and manual_rates:
                final[i][j] = float(manual_rates.get(ver) or 0.0)
                counts[i][j] = 0
                continue
            key = (llm, ver)
            n = int(disp_total.get(key) or 0)
            if n <= 0:
                continue
            fin_pct = 100.0 * float(disp_fin.get(key) or 0) / float(n)
            final[i][j] = fin_pct
            counts[i][j] = n

    group_step = GROUP_STEP
    x = [float(i) * group_step for i in range(n_v)]
    # Compact grouped bars: larger span => smaller inter-group gaps.
    group_span = GROUP_SPAN
    bar_w = group_span / max(n_l, 1)
    offsets = [(float(j) - (n_l - 1) / 2.0) * bar_w for j in range(n_l)]

    # Colorblind-friendly, moderate saturation palette (Tableau-like).
    # Softer (lighter) tones for publication figures (Tableau-like).
    llm_colors = dict(LLM_COLORS)

    fig, ax = plt.subplots(figsize=(fig_width, fig_height), dpi=dpi)
    # Despine (remove top/right), keep clean white background.
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)

    legend_handles = []
    legend_labels = []
    for j, llm in enumerate(llms):
        c = llm_colors.get(llm, "#4c4c4c")
        xs = [xi + offsets[j] for xi in x]
        vals = [final[i][j] for i in range(n_v)]
        bar_vals = [float(v) if isinstance(v, (int, float)) else 0.0 for v in vals]
        bars = ax.bar(
            xs,
            bar_vals,
            width=bar_w * BAR_WIDTH_RATIO,
            color=c,
            edgecolor="none",
            zorder=3,
        )
        legend_handles.append(bars[0])
        legend_labels.append(llm)

        # Value label on top of final bar
        for i in range(n_v):
            if not isinstance(vals[i], (int, float)):
                continue
            xc = float(xs[i])
            fin_v = float(vals[i])
            ax.text(
                xc,
                fin_v + VALUE_LABEL_DY,
                f"{fin_v:.1f}%",
                ha="center",
                va="bottom",
                fontsize=VALUE_LABEL_FONTSIZE,
                color="#111111",
                zorder=5,
                clip_on=False,
            )

    if title is None:
        title = "Deployment Success Rate Across Kernel Versions" if not use_zh else "不同内核版本下的部署成功率"
    # Put title above legend (swap positions): use suptitle + legend below it.
    # - y larger => title higher; y smaller => title lower.
    #   Typical tuning range: 0.96 ~ 1.00 (depends on figure height and legend height).
    fig.suptitle(title, y=SUPTITLE_Y)
    ax.set_xticks(x)
    ax.set_xticklabels([str(v).strip() for v in versions])
    ax.set_xlabel("Kernel Version" if not use_zh else "内核版本")
    ax.set_ylabel("Success Rate (%)" if not use_zh else "成功率（%）")
    ax.set_ylim(0, 100)
    ax.yaxis.set_major_formatter(
        plt.FuncFormatter(lambda y, _: f"{int(y)}" if y == int(y) else f"{y:.0f}")
    )
    # Keep only y-axis major gridlines.
    ax.grid(True, axis="y", zorder=0)
    ax.grid(False, axis="x")

    # Baseline (initial deploy success aggregated by kernel version): thin neutral dashed line per kernel group.
    baseline_color = BASELINE_COLOR
    baseline_handle = plt.Line2D(
        [0],
        [0],
        color=baseline_color,
        linestyle=BASELINE_DASH,
        linewidth=BASELINE_LINEWIDTH,
        label="Baseline (Initial deploy success)" if not use_zh else "Baseline（初始部署成功率）",
    )
    for i, ver in enumerate(versions):
        total = int(total_by_ver.get(ver) or 0)
        ini = int(ini_by_ver.get(ver) or 0)
        if total <= 0:
            continue
        base = 100.0 * float(ini) / float(total)
        left = float(x[i]) - group_span / 2.0
        right = float(x[i]) + group_span / 2.0
        # Draw baseline above bars for visibility.
        ax.plot(
            [left, right],
            [base, base],
            color=baseline_color,
            linestyle=BASELINE_DASH,
            linewidth=BASELINE_LINEWIDTH,
            zorder=6,
        )

    # Legend: top, horizontal, no frame, consistent order with bars + baseline.
    all_handles = legend_handles + [baseline_handle]
    all_labels = legend_labels + [baseline_handle.get_label()]
    ax.legend(
        handles=all_handles,
        labels=all_labels,
        loc="upper center",
        # - bbox_to_anchor(y) larger => legend higher; smaller => lower.
        #   Typical tuning range: 1.10 ~ 1.30.
        bbox_to_anchor=(0.5, LEGEND_Y),
        ncol=max(1, min(int(LEGEND_MAX_COLS), len(all_handles))),
        frameon=False,
        handlelength=2.0,
        columnspacing=1.2,
    )

    # Leave extra room for suptitle + top legend + value labels.
    # - rect top (last number) smaller => more top margin (axes pushed down).
    #   If legend/title overlaps labels, reduce this (e.g., 0.78, 0.75).
    fig.tight_layout(rect=(0.0, 0.0, 1.0, TIGHT_TOP))
    output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output, bbox_inches=SAVE_BBOX_INCHES, facecolor="#ffffff")
    plt.close(fig)
    print(f"Wrote {output}")


def main() -> None:
    default_root = _repo_root_from_script()
    default_case_summary = default_root / "experiments" / "processed_data" / "llm_case_summary.csv"
    parser = argparse.ArgumentParser(description="Plot deploy success rate from case_summary.csv files.")
    parser.add_argument(
        "--llm-case-summary",
        type=Path,
        default=default_case_summary,
        help="Path to experiments/processed_data/llm_case_summary.csv",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=default_root / "experiments" / "data_process" / "figures" / "deploy_success_rate.png",
        help="Output image path (.png)",
    )
    parser.add_argument("--title", type=str, default=None, help="Figure title override")
    parser.add_argument("--zh", action="store_true", help="Use Chinese axis labels and try CJK fonts")
    parser.add_argument(
        "--font-family",
        type=str,
        default=None,
        help="Matplotlib font family (e.g. Noto Sans CJK SC) for Chinese labels",
    )
    parser.add_argument("--width", type=float, default=DEFAULT_FIG_WIDTH, help="Figure width (inches)")
    parser.add_argument("--height", type=float, default=DEFAULT_FIG_HEIGHT, help="Figure height (inches)")
    parser.add_argument("--dpi", type=int, default=DEFAULT_DPI, help="Figure DPI")
    args = parser.parse_args()

    plot_deploy_success_rate(
        case_summary_csv=args.llm_case_summary.resolve(),
        output=args.output.resolve(),
        title=args.title,
        use_zh=args.zh,
        font_family=args.font_family,
        fig_width=args.width,
        fig_height=args.height,
        dpi=args.dpi,
    )


if __name__ == "__main__":
    main()
