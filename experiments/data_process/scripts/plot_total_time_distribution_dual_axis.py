#!/usr/bin/env python3
"""
Dual-axis figure (publication style): Total time distribution + repair rate per LLM.

Spec (图表设计 § Total Time Distribution):
  - For each LLM_name, compute repair_rate over ALL versions:
      repair_rate = P(final_deploy_state == true | initial_deploy_state == false)
    i.e., among initially-failed cases, the fraction that are finally successful.
  - Plot total_time distribution (boxplot) per LLM on the left y-axis.
  - Plot repair_rate as points (scatter) per LLM on the right y-axis.

Reads: experiments/processed_data/llm_case_summary.csv
Required fields:
  - llm_name
  - initial_deploy_state
  - final_deploy_state
  - total_time
"""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path
from typing import Dict, List, Optional

try:
    import matplotlib.pyplot as plt  # pyright: ignore[reportMissingImports]
except ImportError:
    print("Please install matplotlib: pip install matplotlib", file=sys.stderr)
    raise


# =========================
# 可编辑绘图参数（集中配置）
# =========================
# 画布与导出
DEFAULT_FIG_WIDTH = 6.8
DEFAULT_FIG_HEIGHT = 4.8
DEFAULT_DPI = 300
SAVE_BBOX_INCHES = "tight"

# 字体与字号
AXES_TITLE_SIZE = 13
AXES_LABEL_SIZE = 11
TICK_LABEL_SIZE = 10
POINT_LABEL_SIZE = 9

# 标题/图例/留白
SUPTITLE_Y = 0.8         # suptitle 的 y（越大越靠上）
LEGEND_Y = 1.10           # 图例 bbox_to_anchor 的 y（越大越靠上）
TIGHT_TOP = 0.84          # tight_layout rect top（越小顶部留白越大）

# 视觉风格
GRID_COLOR = "#e6e6e6"
SPINE_COLOR = "#333333"
TEXT_COLOR = "#111111"

# 箱线图样式
# 说明：为了与右轴 repair_rate 点颜色统一，我们让每个 LLM 的箱体使用相同的模型配色。
# 若你想改回统一灰色箱体，把 USE_MODEL_COLOR_FOR_RATE_POINTS 设为 False，
# 并把 BOX_FACE/BOX_EDGE 改回固定灰色即可。
BOX_FACE_FALLBACK = "#d9d9d9"
BOX_EDGE_FALLBACK = "#4c4c4c"
BOX_ALPHA = 0.45
MEDIAN_COLOR = "#111111"
WHISKER_COLOR = "#4c4c4c"
CAP_COLOR = "#4c4c4c"
FLIER_MARKER = "o"
FLIER_SIZE = 2.5
FLIER_ALPHA = 0.20

# repair_rate 点样式（右轴）
RATE_COLOR = "#1f1f1f"
RATE_MARKER = "o"
RATE_SIZE = 35
RATE_LINEWIDTH = 0.0

# LLM 展示顺序与颜色（点颜色可与模型对应，也可统一黑色）
LLM_PLOT_ORDER = ["DeepSeek", "GLM", "Doubao", "MiniMax"]
LLM_COLORS = {
    "DeepSeek": "#4e79a7",
    "GLM": "#59a14f",
    "Doubao": "#f28e2b",
    "MiniMax": "#af7aa1",
}
USE_MODEL_COLOR_FOR_RATE_POINTS = True  # True: repair_rate 点按模型配色；False: 统一 RATE_COLOR


def _repo_root_from_script() -> Path:
    return Path(__file__).resolve().parents[3]


def _parse_bool_cell(raw: str) -> bool:
    s = str(raw).strip().lower()
    return s in ("true", "1", "yes", "t")


def _llm_display_name(raw: str) -> str:
    low = str(raw or "").strip().lower()
    if "deepseek" in low:
        return "DeepSeek"
    if "glm" in low:
        return "GLM"
    if "doubao" in low:
        return "Doubao"
    if "minimax" in low:
        return "MiniMax"
    return str(raw or "").strip() or "Unknown"


def _configure_style(*, use_zh: bool, font_family: Optional[str]) -> None:
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
            "axes.edgecolor": SPINE_COLOR,
            "axes.labelcolor": TEXT_COLOR,
            "axes.titleweight": "normal",
            "axes.titlesize": AXES_TITLE_SIZE,
            "axes.labelsize": AXES_LABEL_SIZE,
            "xtick.labelsize": TICK_LABEL_SIZE,
            "ytick.labelsize": TICK_LABEL_SIZE,
            "grid.color": GRID_COLOR,
            "grid.linestyle": "-",
            "grid.linewidth": 0.8,
            "grid.alpha": 1.0,
            "legend.frameon": False,
        }
    )

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


def plot_total_time_distribution_dual_axis(
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

    try:
        with case_summary_csv.open("r", encoding="utf-8", errors="replace", newline="") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
    except OSError as e:
        print(f"Failed reading: {case_summary_csv}: {e}", file=sys.stderr)
        sys.exit(1)

    if not rows:
        print(f"No rows in {case_summary_csv}", file=sys.stderr)
        sys.exit(1)

    _configure_style(use_zh=use_zh, font_family=font_family)

    # Collect per-LLM total_time and per-LLM repair rate counts.
    time_by_llm: Dict[str, List[float]] = {k: [] for k in LLM_PLOT_ORDER}
    fail_by_llm: Dict[str, int] = {k: 0 for k in LLM_PLOT_ORDER}
    repaired_ok_by_llm: Dict[str, int] = {k: 0 for k in LLM_PLOT_ORDER}

    for row in rows:
        llm = _llm_display_name(str(row.get("llm_name") or ""))
        if llm not in set(LLM_PLOT_ORDER):
            continue
        # total_time distribution: include all cases (as "total time distribution").
        try:
            t = float(row.get("total_time") or 0.0)
        except Exception:
            t = 0.0
        if t > 0:
            time_by_llm[llm].append(t)

        # repair_rate: among initial failures, fraction finally successful.
        if _parse_bool_cell(row.get("initial_deploy_state", "")):
            continue
        fail_by_llm[llm] += 1
        if _parse_bool_cell(row.get("final_deploy_state", "")):
            repaired_ok_by_llm[llm] += 1

    llms = [k for k in LLM_PLOT_ORDER if time_by_llm.get(k) or fail_by_llm.get(k)]
    if not llms:
        print("No data after filtering by LLM_PLOT_ORDER; check input CSV.", file=sys.stderr)
        sys.exit(1)

    # Compute repair rates (%)
    rates: List[float] = []
    for llm in llms:
        denom = int(fail_by_llm.get(llm) or 0)
        numer = int(repaired_ok_by_llm.get(llm) or 0)
        rates.append((100.0 * float(numer) / float(denom)) if denom > 0 else 0.0)

    x = list(range(len(llms)))
    box_data = [time_by_llm.get(llm) or [0.0] for llm in llms]

    fig, ax_left = plt.subplots(figsize=(fig_width, fig_height), dpi=dpi)
    ax_left.spines["top"].set_visible(False)
    ax_left.spines["right"].set_visible(False)

    # Boxplot on left axis
    bp = ax_left.boxplot(
        box_data,
        positions=x,
        widths=0.55,
        patch_artist=True,
        showfliers=True,
        medianprops={"color": MEDIAN_COLOR, "linewidth": 1.2},
        boxprops={"facecolor": BOX_FACE_FALLBACK, "edgecolor": BOX_EDGE_FALLBACK, "alpha": BOX_ALPHA, "linewidth": 1.0},
        whiskerprops={"color": WHISKER_COLOR, "linewidth": 1.0},
        capprops={"color": CAP_COLOR, "linewidth": 1.0},
        flierprops={
            "marker": FLIER_MARKER,
            "markersize": FLIER_SIZE,
            "markerfacecolor": BOX_EDGE_FALLBACK,
            "markeredgecolor": "none",
            "alpha": FLIER_ALPHA,
        },
    )

    # Unify box colors with repair_rate point colors (per-LLM).
    box_patches = bp.get("boxes") or []
    for idx, patch in enumerate(box_patches):
        llm = llms[idx] if idx < len(llms) else ""
        c = LLM_COLORS.get(llm, RATE_COLOR) if USE_MODEL_COLOR_FOR_RATE_POINTS else RATE_COLOR
        try:
            patch.set_facecolor(c)
            patch.set_edgecolor(c)
            patch.set_alpha(BOX_ALPHA)
        except Exception:
            pass

    ax_left.set_xticks(x)
    ax_left.set_xticklabels(llms)
    ax_left.set_xlabel("LLM" if not use_zh else "LLM")
    ax_left.set_ylabel("Per-case Total Time (s)" if not use_zh else "单个用例总耗时（秒）")
    ax_left.grid(True, axis="y", zorder=0)
    ax_left.grid(False, axis="x")

    # Right axis for repair rate points
    ax_right = ax_left.twinx()
    ax_right.spines["top"].set_visible(False)
    ax_right.spines["left"].set_visible(False)
    ax_right.spines["right"].set_color(SPINE_COLOR)
    ax_right.tick_params(axis="y", colors=TEXT_COLOR)
    ax_right.set_ylabel("Repair Rate (%)" if not use_zh else "修复成功率（%）", color=TEXT_COLOR)
    ax_right.set_ylim(0, 100)

    point_colors = []
    for llm in llms:
        if USE_MODEL_COLOR_FOR_RATE_POINTS:
            point_colors.append(LLM_COLORS.get(llm, RATE_COLOR))
        else:
            point_colors.append(RATE_COLOR)

    ax_right.scatter(
        x,
        rates,
        s=RATE_SIZE,
        c=point_colors,
        marker=RATE_MARKER,
        linewidths=RATE_LINEWIDTH,
        zorder=6,
    )

    # Optional: annotate rate values near points (can be disabled by setting POINT_LABEL_SIZE <= 0)
    if POINT_LABEL_SIZE and POINT_LABEL_SIZE > 0:
        for xi, rv in zip(x, rates):
            ax_right.text(
                xi,
                float(rv) + 1.0,
                f"{float(rv):.1f}%",
                ha="center",
                va="bottom",
                fontsize=POINT_LABEL_SIZE,
                color=TEXT_COLOR,
                zorder=7,
                clip_on=False,
            )

    if title is None:
        title = (
            "Per-case Total Time Distribution and Repair Rate"
            if not use_zh
            else "单个用例总耗时分布与修复成功率"
        )
    fig.suptitle(title, y=SUPTITLE_Y)

    # Legend: build explicit handles (boxplot + repair_rate)
    box_handle = plt.Line2D(
        [0],
        [0],
        color="#666666",
        linewidth=6,
        alpha=BOX_ALPHA,
        label="Total time (box)" if not use_zh else "总耗时（箱线图）",
    )
    rate_handle = plt.Line2D(
        [0],
        [0],
        marker=RATE_MARKER,
        color="none",
        markerfacecolor=RATE_COLOR,
        markersize=7,
        label="Repair rate (point)" if not use_zh else "修复成功率（点）",
    )
    ax_left.legend(
        handles=[box_handle, rate_handle],
        loc="upper center",
        bbox_to_anchor=(0.5, LEGEND_Y),
        ncol=2,
        frameon=False,
        handlelength=2.0,
        columnspacing=1.2,
    )

    fig.tight_layout(rect=(0.0, 0.0, 1.0, TIGHT_TOP))
    output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output, bbox_inches=SAVE_BBOX_INCHES, facecolor="#ffffff")
    plt.close(fig)
    print(f"Wrote {output}")


def main() -> None:
    default_root = _repo_root_from_script()
    default_case_summary = default_root / "experiments" / "processed_data" / "llm_case_summary.csv"
    parser = argparse.ArgumentParser(description="Plot total_time distribution + repair_rate (dual axis).")
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
        default=default_root / "experiments" / "data_process" / "figures" / "total_time_distribution_dual_axis.png",
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

    plot_total_time_distribution_dual_axis(
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

