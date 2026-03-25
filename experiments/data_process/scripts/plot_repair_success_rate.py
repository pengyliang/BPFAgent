#!/usr/bin/env python3
"""
Grouped bar chart (publication style): Repair success rate across kernel versions.

Definition (Repair rate):
  Filter cases with initial_deploy_state == false, then compute:
    repair_rate = P(final_deploy_state == true | initial_deploy_state == false)

X-axis: kernel version
Grouped bars: one per LLM (repair rate)

Reads: experiments/processed_data/llm_case_summary.csv
Required fields:
  - llm_name
  - kernel_version
  - initial_deploy_state
  - final_deploy_state
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
DEFAULT_FIG_WIDTH = 7.0
DEFAULT_FIG_HEIGHT = 5.2
DEFAULT_DPI = 300
SAVE_BBOX_INCHES = "tight"

# 字体与字号（论文风格：整体偏紧凑）
AXES_TITLE_SIZE = 13
AXES_LABEL_SIZE = 11
TICK_LABEL_SIZE = 10
VALUE_LABEL_FONTSIZE = 7

# 柱状图布局
GROUP_STEP = 0.8          # 组中心间距（<1 更紧凑，>1 更松）
GROUP_SPAN = 0.70         # 每个组横向占用（越大组间空隙越小）
BAR_WIDTH_RATIO = 0.95    # 柱宽占 bar slot 的比例
VALUE_LABEL_DY = 1.2      # 柱顶数值标签上移量

# 标题/图例/留白（位置调参最常用）
SUPTITLE_Y = 0.650         # suptitle 的 y（越大越靠上）
LEGEND_Y = 1.30           # 图例 bbox_to_anchor 的 y（越大越靠上）
LEGEND_MAX_COLS = 4       # 图例最多列数；超出会自动换行
TIGHT_TOP = 0.80          # tight_layout rect top（越小顶部留白越大）

# 配色（更柔和的论文风格，色盲友好）
LLM_COLORS = {
    "DeepSeek": "#4e79a7",  # soft blue
    "GLM": "#59a14f",       # soft green
    "Doubao": "#f28e2b",    # soft orange
    "MiniMax": "#af7aa1",   # soft purple
}

# LLM 展示顺序（只显示这些；如需显示其他模型，可把它们加入这里）
LLM_PLOT_ORDER = ["DeepSeek", "GLM", "Doubao", "MiniMax"]


def _repo_root_from_script() -> Path:
    return Path(__file__).resolve().parents[3]


def _version_sort_key(v: str) -> Tuple:
    parts = []
    for p in str(v).replace("_", ".").split("."):
        if p.isdigit():
            parts.append(int(p))
        else:
            parts.append(p)
    return tuple(parts)


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


def plot_repair_success_rate(
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

    # Aggregate only initial failures: (llm_display, kernel_version) -> (n_initial_fail, n_repaired_success)
    total_fail: Dict[Tuple[str, str], int] = {}
    repaired_ok: Dict[Tuple[str, str], int] = {}
    versions_set: set[str] = set()
    llms_set: set[str] = set()

    for row in rows:
        raw_llm = str(row.get("llm_name") or "").strip()
        ver = str(row.get("kernel_version") or "").strip()
        if not raw_llm or not ver:
            continue
        if _parse_bool_cell(row.get("initial_deploy_state", "")):
            # Only care about initial failures.
            continue
        llm = _llm_display_name(raw_llm)
        if llm not in set(LLM_PLOT_ORDER):
            continue
        key = (llm, ver)
        versions_set.add(ver)
        llms_set.add(llm)
        total_fail[key] = int(total_fail.get(key) or 0) + 1
        if _parse_bool_cell(row.get("final_deploy_state", "")):
            repaired_ok[key] = int(repaired_ok.get(key) or 0) + 1

    versions = sorted(list(versions_set), key=_version_sort_key)
    llms = [x for x in LLM_PLOT_ORDER if x in llms_set]
    if not versions or not llms:
        print("No valid groups after filtering initial failures; check input CSV.", file=sys.stderr)
        sys.exit(1)

    _configure_style(use_zh=use_zh, font_family=font_family)

    n_v, n_l = len(versions), len(llms)
    rates: List[List[Optional[float]]] = [[None for _ in range(n_l)] for _ in range(n_v)]
    counts: List[List[int]] = [[0 for _ in range(n_l)] for _ in range(n_v)]
    for j, llm in enumerate(llms):
        for i, ver in enumerate(versions):
            key = (llm, ver)
            n = int(total_fail.get(key) or 0)
            if n <= 0:
                continue
            ok = int(repaired_ok.get(key) or 0)
            rates[i][j] = 100.0 * float(ok) / float(n)
            counts[i][j] = n

    x = [float(i) * GROUP_STEP for i in range(n_v)]
    group_span = GROUP_SPAN
    bar_w = group_span / max(n_l, 1)
    offsets = [(float(j) - (n_l - 1) / 2.0) * bar_w for j in range(n_l)]

    fig, ax = plt.subplots(figsize=(fig_width, fig_height), dpi=dpi)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)

    legend_handles = []
    legend_labels = []
    for j, llm in enumerate(llms):
        c = LLM_COLORS.get(llm, "#4c4c4c")
        xs = [xi + offsets[j] for xi in x]
        vals = [rates[i][j] for i in range(n_v)]
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

        for i in range(n_v):
            if not isinstance(vals[i], (int, float)):
                continue
            fin_v = float(vals[i])
            ax.text(
                float(xs[i]),
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
        title = "Repair Success Rate Across Kernel Versions" if not use_zh else "不同内核版本下的修复成功率"
    fig.suptitle(title, y=SUPTITLE_Y)

    ax.set_xticks(x)
    ax.set_xticklabels([str(v).strip() for v in versions])
    ax.set_xlabel("Kernel Version" if not use_zh else "内核版本")
    ax.set_ylabel("Repair Success Rate (%)" if not use_zh else "修复成功率（%）")
    ax.set_ylim(0, 100)
    ax.grid(True, axis="y", zorder=0)
    ax.grid(False, axis="x")

    ax.legend(
        handles=legend_handles,
        labels=legend_labels,
        loc="upper center",
        bbox_to_anchor=(0.5, LEGEND_Y),
        ncol=max(1, min(int(LEGEND_MAX_COLS), len(legend_handles))),
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
    parser = argparse.ArgumentParser(description="Plot repair success rate (final success among initial failures).")
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
        default=default_root / "experiments" / "data_process" / "figures" / "repair_success_rate.png",
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

    plot_repair_success_rate(
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

