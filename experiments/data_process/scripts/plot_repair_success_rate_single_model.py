#!/usr/bin/env python3
"""
Single-model figure (publication style): Repair success rate across kernel versions.

Definition (Repair rate):
  Filter cases with initial_deploy_state == false, then compute:
    repair_rate = P(final_deploy_state == true | initial_deploy_state == false)

This script plots repair_rate for ONE selected model (default: glm) across kernel versions.

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
DEFAULT_FIG_WIDTH = 4.5
DEFAULT_FIG_HEIGHT = 4.2
DEFAULT_DPI = 300
SAVE_BBOX_INCHES = "tight"

# 字体与字号
AXES_TITLE_SIZE = 13
AXES_LABEL_SIZE = 11
TICK_LABEL_SIZE = 10
VALUE_LABEL_FONTSIZE = 8

# 柱状图布局
BAR_WIDTH = 0.40          # 单系列柱宽（0~1 之间更常用）
VALUE_LABEL_DY = 1.2      # 柱顶数值标签上移量

# 标题/图例/留白（位置调参最常用）
SUPTITLE_Y = 0.85         # suptitle 的 y（越大越靠上）
TIGHT_TOP = 0.84          # tight_layout rect top（越小顶部留白越大）

# 网格与配色
GRID_COLOR = "#e6e6e6"
TEXT_COLOR = "#111111"
SPINE_COLOR = "#333333"
MODEL_COLOR = "#59a14f"   # GLM 的柔和绿（可按需要替换）


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


def plot_repair_rate_single_model(
    *,
    case_summary_csv: Path,
    model_key: str,
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

    # (kernel_version) -> counts among initial failures
    total_fail: Dict[str, int] = {}
    repaired_ok: Dict[str, int] = {}
    versions_set: set[str] = set()

    for row in rows:
        llm = str(row.get("llm_name") or "").strip()
        ver = str(row.get("kernel_version") or "").strip()
        if not llm or not ver:
            continue
        if model_key_low not in llm.lower():
            continue
        if _parse_bool_cell(row.get("initial_deploy_state", "")):
            continue
        versions_set.add(ver)
        total_fail[ver] = int(total_fail.get(ver) or 0) + 1
        if _parse_bool_cell(row.get("final_deploy_state", "")):
            repaired_ok[ver] = int(repaired_ok.get(ver) or 0) + 1

    versions = sorted(list(versions_set), key=_version_sort_key)
    if not versions:
        print(f"No initial-failure rows for model={model_key} in {case_summary_csv}", file=sys.stderr)
        sys.exit(1)

    rates: List[float] = []
    for ver in versions:
        denom = int(total_fail.get(ver) or 0)
        numer = int(repaired_ok.get(ver) or 0)
        rates.append((100.0 * float(numer) / float(denom)) if denom > 0 else 0.0)

    _configure_style(use_zh=use_zh, font_family=font_family)

    fig, ax = plt.subplots(figsize=(fig_width, fig_height), dpi=dpi)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)

    x = list(range(len(versions)))
    bars = ax.bar(x, rates, width=BAR_WIDTH, color=MODEL_COLOR, edgecolor="none", zorder=3)

    # Value labels
    for xi, v in zip(x, rates):
        ax.text(
            float(xi),
            float(v) + VALUE_LABEL_DY,
            f"{float(v):.1f}%",
            ha="center",
            va="bottom",
            fontsize=VALUE_LABEL_FONTSIZE,
            color=TEXT_COLOR,
            zorder=5,
            clip_on=False,
        )

    if title is None:
        title = "Repair Success Rate Across Kernel Versions (GLM)" if not use_zh else "不同内核版本下的修复成功率（GLM）"
    fig.suptitle(title, y=SUPTITLE_Y)

    ax.set_xticks(x)
    ax.set_xticklabels([str(v).strip() for v in versions])
    ax.set_xlabel("Kernel Version" if not use_zh else "内核版本")
    ax.set_ylabel("Repair Success Rate (%)" if not use_zh else "修复成功率（%）")
    ax.set_ylim(0, 100)
    ax.grid(True, axis="y", zorder=0)
    ax.grid(False, axis="x")

    fig.tight_layout(rect=(0.0, 0.0, 1.0, TIGHT_TOP))
    output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output, bbox_inches=SAVE_BBOX_INCHES, facecolor="#ffffff")
    plt.close(fig)
    del bars
    print(f"Wrote {output}")


def main() -> None:
    default_root = _repo_root_from_script()
    default_case_summary = default_root / "experiments" / "processed_data" / "llm_case_summary.csv"
    parser = argparse.ArgumentParser(description="Plot single-model repair success rate by kernel version.")
    parser.add_argument(
        "--llm-case-summary",
        type=Path,
        default=default_case_summary,
        help="Path to experiments/processed_data/llm_case_summary.csv",
    )
    parser.add_argument("--model", type=str, default="glm", help="Model key substring to filter llm_name (default: glm)")
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=default_root / "experiments" / "data_process" / "figures" / "repair_success_rate_single_glm.png",
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

    plot_repair_rate_single_model(
        case_summary_csv=args.llm_case_summary.resolve(),
        model_key=args.model,
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

