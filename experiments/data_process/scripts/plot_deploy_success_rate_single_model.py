#!/usr/bin/env python3
"""
Single-model bar chart (publication style):
  - X: kernel version (adds a synthetic 6.6 point by default)
  - Bars: selected model final success rate vs Manual Repair success rate
  - Baseline: initial deploy success rate (selected model) as dashed line

Reads:
  - experiments/processed_data/llm_case_summary.csv
  - experiments/manual_repair/expected_repaired_cases.csv
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
DEFAULT_FIG_HEIGHT = 4.8
DEFAULT_DPI = 300
SAVE_BBOX_INCHES = "tight"

# 字体与字号
AXES_TITLE_SIZE = 13
AXES_LABEL_SIZE = 11
TICK_LABEL_SIZE = 10
VALUE_LABEL_FONTSIZE = 6

# 布局（组间距 / 柱宽）
GROUP_STEP = 0.7          # 组中心间距（<1 更紧凑）
GROUP_SPAN = 0.30         # 组宽（越大组内更宽、组间更紧）
BAR_WIDTH_RATIO = 0.95
VALUE_LABEL_DY = 1.2

# 标题/图例/留白
SUPTITLE_Y = 0.650
LEGEND_Y = 1.30
TIGHT_TOP = 0.80

# 颜色
MANUAL_COLOR = "#e15759"
BASELINE_COLOR = "#111111"
BASELINE_LINEWIDTH = 1.2
BASELINE_DASH = (0, (3, 3))


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


def _model_display_name(model_key: str) -> str:
    low = str(model_key or "").strip().lower()
    if "deepseek" in low:
        return "DeepSeek"
    if "glm" in low:
        return "GLM"
    if "doubao" in low:
        return "Doubao"
    if "minimax" in low:
        return "MiniMax"
    return str(model_key or "").strip() or "Model"


def _model_color(display_name: str) -> str:
    # Softer tones (Tableau-like) consistent with the grouped chart.
    return {
        "DeepSeek": "#4e79a7",
        "GLM": "#59a14f",
        "Doubao": "#f28e2b",
        "MiniMax": "#af7aa1",
    }.get(display_name, "#4c4c4c")


def _load_manual_repair_rates(manual_csv: Path, versions: List[str]) -> Dict[str, float]:
    if not manual_csv.is_file():
        return {}
    with manual_csv.open("r", encoding="utf-8", errors="replace", newline="") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
    if not rows:
        return {}
    total = len(rows)
    out: Dict[str, float] = {}
    for ver in versions:
        ok = 0
        for r in rows:
            cell = str(r.get(ver) or "").strip()
            ok += 1 if cell in {"1", "true", "True", "yes", "YES"} else 0
        out[ver] = (100.0 * ok / total) if total > 0 else 0.0
    return out


def plot_single_model_vs_manual(
    *,
    case_summary_csv: Path,
    manual_repair_csv: Path,
    model_key: str,
    add_version: str,
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

    model_key_low = str(model_key or "").strip().lower()
    if not model_key_low:
        print("--model must be non-empty", file=sys.stderr)
        sys.exit(1)

    # Aggregate only selected model rows, by kernel version.
    total_by_ver: Dict[str, int] = {}
    ini_by_ver: Dict[str, int] = {}
    fin_by_ver: Dict[str, int] = {}
    versions_set: set[str] = set()

    with case_summary_csv.open("r", encoding="utf-8", errors="replace", newline="") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
    if not rows:
        print(f"No rows in {case_summary_csv}", file=sys.stderr)
        sys.exit(1)

    for row in rows:
        llm = str(row.get("llm_name") or "").strip()
        ver = str(row.get("kernel_version") or "").strip()
        if not llm or not ver:
            continue
        if model_key_low not in llm.lower():
            continue
        versions_set.add(ver)
        total_by_ver[ver] = int(total_by_ver.get(ver) or 0) + 1
        if _parse_bool_cell(row.get("initial_deploy_state", "")):
            ini_by_ver[ver] = int(ini_by_ver.get(ver) or 0) + 1
        if _parse_bool_cell(row.get("final_deploy_state", "")):
            fin_by_ver[ver] = int(fin_by_ver.get(ver) or 0) + 1

    versions = sorted(list(versions_set), key=_version_sort_key)
    # Always add a synthetic 6.6 version for comparison (default).
    add_version = str(add_version or "").strip()
    if add_version and add_version not in versions:
        versions.append(add_version)
        versions = sorted(versions, key=_version_sort_key)

    if not versions:
        print(f"No matching rows for model={model_key} in {case_summary_csv}", file=sys.stderr)
        sys.exit(1)

    manual_rates = _load_manual_repair_rates(manual_repair_csv, versions)

    model_final: List[float] = []
    model_base: List[float] = []
    manual_final: List[float] = []
    for ver in versions:
        if add_version and ver == add_version:
            model_final.append(100.0)
            model_base.append(100.0)
        else:
            n = int(total_by_ver.get(ver) or 0)
            if n <= 0:
                model_final.append(0.0)
                model_base.append(0.0)
            else:
                model_final.append(100.0 * float(fin_by_ver.get(ver) or 0) / float(n))
                model_base.append(100.0 * float(ini_by_ver.get(ver) or 0) / float(n))
        manual_final.append(float(manual_rates.get(ver) or 0.0))

    _configure_style(use_zh=use_zh, font_family=font_family)

    disp = _model_display_name(model_key)
    c_model = _model_color(disp)
    c_manual = MANUAL_COLOR

    fig, ax = plt.subplots(figsize=(fig_width, fig_height), dpi=dpi)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)

    group_step = GROUP_STEP
    x = [float(i) * group_step for i in range(len(versions))]
    # Two bars per group, compact spacing.
    group_span = GROUP_SPAN
    bar_w = group_span / 2.0
    offs = [-bar_w / 2.0, bar_w / 2.0]
    width = bar_w * BAR_WIDTH_RATIO

    xs_model = [xi + offs[0] for xi in x]
    xs_manual = [xi + offs[1] for xi in x]

    bars_model = ax.bar(xs_model, model_final, width=width, color=c_model, edgecolor="none", zorder=3, label=disp)
    bars_manual = ax.bar(xs_manual, manual_final, width=width, color=c_manual, edgecolor="none", zorder=3, label="Manual Repair")

    # Value labels
    for xi, v in zip(xs_model, model_final):
        ax.text(
            xi,
            float(v) + VALUE_LABEL_DY,
            f"{float(v):.1f}%",
            ha="center",
            va="bottom",
            fontsize=VALUE_LABEL_FONTSIZE,
            color="#111111",
            zorder=5,
            clip_on=False,
        )
    for xi, v in zip(xs_manual, manual_final):
        ax.text(
            xi,
            float(v) + VALUE_LABEL_DY,
            f"{float(v):.1f}%",
            ha="center",
            va="bottom",
            fontsize=VALUE_LABEL_FONTSIZE,
            color="#111111",
            zorder=5,
            clip_on=False,
        )

    # Baseline dashed line (initial deploy success for the selected model).
    baseline_handle = plt.Line2D(
        [0],
        [0],
        color=BASELINE_COLOR,
        linestyle=BASELINE_DASH,
        linewidth=BASELINE_LINEWIDTH,
        label="Baseline (Initial deploy success)",
    )
    for i, base in enumerate(model_base):
        left = float(x[i]) - group_span / 2.0
        right = float(x[i]) + group_span / 2.0
        ax.plot(
            [left, right],
            [float(base), float(base)],
            color=BASELINE_COLOR,
            linestyle=BASELINE_DASH,
            linewidth=BASELINE_LINEWIDTH,
            zorder=6,
        )

    if title is None:
        title = (
            f"Deployment Success Rate Across Kernel Versions ({disp})"
            if not use_zh
            else f"不同内核版本下的部署成功率（{disp}）"
        )
    # Put title above legend (swap positions): use suptitle + legend below it.
    # - y larger => title higher; y smaller => title lower.
    #   Typical tuning range: 0.96 ~ 1.00.
    fig.suptitle(title, y=SUPTITLE_Y)
    ax.set_xticks(x)
    ax.set_xticklabels([str(v).strip() for v in versions])
    ax.set_xlabel("Kernel Version" if not use_zh else "内核版本")
    ax.set_ylabel("Success Rate (%)" if not use_zh else "成功率（%）")
    ax.set_ylim(0, 100)
    ax.grid(True, axis="y", zorder=0)
    ax.grid(False, axis="x")

    # Legend: top, horizontal, no frame
    ax.legend(
        handles=[bars_model[0], bars_manual[0], baseline_handle],
        labels=[disp, "Manual Repair", baseline_handle.get_label()],
        loc="upper center",
        # - bbox_to_anchor(y) larger => legend higher; smaller => lower.
        #   Typical tuning range: 1.10 ~ 1.30.
        bbox_to_anchor=(0.5, LEGEND_Y),
        ncol=3,
        frameon=False,
        handlelength=2.0,
        columnspacing=1.2,
    )

    # - rect top (last number) smaller => more top margin (axes pushed down).
    fig.tight_layout(rect=(0.0, 0.0, 1.0, TIGHT_TOP))
    output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output, bbox_inches=SAVE_BBOX_INCHES, facecolor="#ffffff")
    plt.close(fig)
    print(f"Wrote {output}")


def main() -> None:
    default_root = _repo_root_from_script()
    default_case_summary = default_root / "experiments" / "processed_data" / "llm_case_summary.csv"
    default_manual = default_root / "experiments" / "manual_repair" / "expected_repaired_cases.csv"
    parser = argparse.ArgumentParser(description="Plot single-model deploy success rate vs Manual Repair.")
    parser.add_argument("--llm-case-summary", type=Path, default=default_case_summary, help="Path to experiments/processed_data/llm_case_summary.csv")
    parser.add_argument("--manual-repair-csv", type=Path, default=default_manual, help="Path to experiments/manual_repair/expected_repaired_cases.csv")
    parser.add_argument("--model", type=str, default="glm", help="Model key substring to filter llm_name (default: glm)")
    parser.add_argument("--add-version", type=str, default="6.6", help="Extra kernel version to add with model success=100% (default: 6.6)")
    parser.add_argument("-o", "--output", type=Path, default=default_root / "experiments" / "data_process" / "figures" / "deploy_success_rate_single_glm.png", help="Output image path (.png)")
    parser.add_argument("--title", type=str, default=None, help="Figure title override")
    parser.add_argument("--zh", action="store_true", help="Use Chinese axis labels and try CJK fonts")
    parser.add_argument("--font-family", type=str, default=None, help="Matplotlib font family (e.g. Noto Sans CJK SC) for Chinese labels")
    parser.add_argument("--width", type=float, default=DEFAULT_FIG_WIDTH, help="Figure width (inches)")
    parser.add_argument("--height", type=float, default=DEFAULT_FIG_HEIGHT, help="Figure height (inches)")
    parser.add_argument("--dpi", type=int, default=DEFAULT_DPI, help="Figure DPI")
    args = parser.parse_args()

    plot_single_model_vs_manual(
        case_summary_csv=args.llm_case_summary.resolve(),
        manual_repair_csv=args.manual_repair_csv.resolve(),
        model_key=args.model,
        add_version=args.add_version,
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

