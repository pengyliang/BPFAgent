#!/usr/bin/env python3
"""
Publication-style figure: GLM repair rate by case category.

Goal:
  Aggregate across ALL kernel versions for GLM runs:
    - Filter cases with initial_deploy_state == false (initial failure).
    - Use case category extracted from case_id prefix before '/' (e.g., feature, helper_func).
    - For each category, compute repair_rate:
        repair_rate = P(final_deploy_state == true | initial_deploy_state == false, category=case_category)
  Plot grouped (single-series) bars with value labels like:
    72.3% (n=53)

Data sources (existing experiment artifacts):
  - experiments/llm/glm-5/<kernel_version>/reports/case_summary.csv
      columns include: case_id, initial_deploy_state, final_deploy_state
    We use initial_deploy_state for filtering, case_id for category, and final_deploy_state as the repair outcome.
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
DEFAULT_FIG_WIDTH = 5
DEFAULT_FIG_HEIGHT = 4.6
DEFAULT_DPI = 300
SAVE_BBOX_INCHES = "tight"

# 字体与字号
AXES_TITLE_SIZE = 13
AXES_LABEL_SIZE = 11
TICK_LABEL_SIZE = 9
VALUE_LABEL_FONTSIZE = 9

# 布局
BAR_WIDTH = 0.5
X_LABEL_ROTATION = 25
X_LABEL_HA = "right"
VALUE_LABEL_DY = 1.2
TIGHT_TOP = 0.86
SUPTITLE_Y = 0.92

# 视觉风格
GRID_COLOR = "#e6e6e6"
SPINE_COLOR = "#333333"
TEXT_COLOR = "#111111"

# 配色（GLM 柔和绿）
BAR_COLOR = "#59a14f"

# 过滤/排序
MIN_N_TO_SHOW = 1          # 类别样本量小于该值则不显示
MAX_CATEGORIES = 20        # 最多显示多少个类别（按样本量排序）
UNKNOWN_LABEL = "(unknown)"


def _repo_root_from_script() -> Path:
    return Path(__file__).resolve().parents[3]


def _parse_bool_cell(raw: str) -> bool:
    s = str(raw).strip().lower()
    return s in ("true", "1", "yes", "t")


def _configure_style(*, font_family: Optional[str]) -> None:
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


def _discover_glm_versions(glm_root: Path) -> List[str]:
    if not glm_root.is_dir():
        return []
    versions = []
    for child in glm_root.iterdir():
        if child.is_dir() and (child / "reports" / "case_summary.csv").is_file():
            versions.append(child.name)
    return sorted(versions)


def _load_case_summary(path: Path) -> Dict[str, Dict[str, str]]:
    out: Dict[str, Dict[str, str]] = {}
    if not path.is_file():
        return out
    with path.open("r", encoding="utf-8", errors="replace", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            cid = str(row.get("case_id") or "").strip()
            if not cid:
                continue
            out[cid] = row
    return out


def _case_category(case_id: str) -> str:
    """Extract category from case_id prefix before '/'."""
    cid = str(case_id or "").strip()
    if not cid:
        return UNKNOWN_LABEL
    if "/" not in cid:
        return cid
    head = cid.split("/", 1)[0].strip()
    return head or UNKNOWN_LABEL


def plot_repair_rate_by_error_type_glm(
    *,
    glm_root: Path,
    output: Path,
    title: Optional[str],
    font_family: Optional[str],
    fig_width: float,
    fig_height: float,
    dpi: int,
) -> None:
    versions = _discover_glm_versions(glm_root)
    if not versions:
        print(f"No GLM version folders found under: {glm_root}", file=sys.stderr)
        sys.exit(1)

    _configure_style(font_family=font_family)

    total_by_type: Dict[str, int] = {}
    ok_by_type: Dict[str, int] = {}

    for ver in versions:
        reports = glm_root / ver / "reports"
        case_summary = reports / "case_summary.csv"

        summary_map = _load_case_summary(case_summary)

        for cid, row in summary_map.items():
            if _parse_bool_cell(row.get("initial_deploy_state", "")):
                continue
            cat = _case_category(cid)
            total_by_type[cat] = int(total_by_type.get(cat) or 0) + 1
            if _parse_bool_cell(row.get("final_deploy_state", "")):
                ok_by_type[cat] = int(ok_by_type.get(cat) or 0) + 1

    items: List[Tuple[str, int, int, float]] = []
    for et, n in total_by_type.items():
        if int(n) < int(MIN_N_TO_SHOW):
            continue
        ok = int(ok_by_type.get(et) or 0)
        rate = (100.0 * float(ok) / float(n)) if n > 0 else 0.0
        items.append((et, n, ok, rate))

    if not items:
        print("No categories to plot after filtering. Check inputs.", file=sys.stderr)
        sys.exit(1)

    # Sort by sample size desc, then by name.
    items.sort(key=lambda t: (-t[1], t[0]))
    items = items[: int(MAX_CATEGORIES)]

    labels = [t[0] for t in items]
    rates = [t[3] for t in items]
    ns = [t[1] for t in items]

    fig, ax = plt.subplots(figsize=(fig_width, fig_height), dpi=dpi)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)

    x = list(range(len(labels)))
    ax.bar(x, rates, width=BAR_WIDTH, color=BAR_COLOR, edgecolor="none", zorder=3)

    # Labels: "72.3% (n=53)"
    for xi, rv, n in zip(x, rates, ns):
        ax.text(
            float(xi),
            float(rv) + VALUE_LABEL_DY,
            f"{float(rv):.1f}% (n={int(n)})",
            ha="center",
            va="bottom",
            fontsize=VALUE_LABEL_FONTSIZE,
            color=TEXT_COLOR,
            zorder=5,
            clip_on=False,
        )

    if title is None:
        title = "Repair Rate by Incompatibility Category"
    fig.suptitle(title, y=SUPTITLE_Y)

    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=X_LABEL_ROTATION, ha=X_LABEL_HA)
    ax.set_xlabel("Incompatibility Category")
    ax.set_ylabel("Repair Rate (%)")
    ax.set_ylim(0, 100)
    ax.grid(True, axis="y", zorder=0)
    ax.grid(False, axis="x")

    fig.tight_layout(rect=(0.0, 0.0, 1.0, TIGHT_TOP))
    output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output, bbox_inches=SAVE_BBOX_INCHES, facecolor="#ffffff")
    plt.close(fig)
    print(f"Wrote {output}")


def main() -> None:
    root = _repo_root_from_script()
    glm_root = root / "experiments" / "llm" / "glm-5"
    parser = argparse.ArgumentParser(description="Plot GLM repair rate by initial error_type category.")
    parser.add_argument(
        "--glm-root",
        type=Path,
        default=glm_root,
        help="Path to experiments/llm/glm-5 (contains <ver>/reports/*.csv)",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=root / "experiments" / "data_process" / "figures" / "repair_rate_by_error_type_glm.png",
        help="Output image path (.png)",
    )
    parser.add_argument("--title", type=str, default=None, help="Figure title override")
    parser.add_argument("--font-family", type=str, default=None, help="Matplotlib font family (e.g. Helvetica)")
    parser.add_argument("--width", type=float, default=DEFAULT_FIG_WIDTH, help="Figure width (inches)")
    parser.add_argument("--height", type=float, default=DEFAULT_FIG_HEIGHT, help="Figure height (inches)")
    parser.add_argument("--dpi", type=int, default=DEFAULT_DPI, help="Figure DPI")
    args = parser.parse_args()

    plot_repair_rate_by_error_type_glm(
        glm_root=args.glm_root.resolve(),
        output=args.output.resolve(),
        title=args.title,
        font_family=args.font_family,
        fig_width=args.width,
        fig_height=args.height,
        dpi=args.dpi,
    )


if __name__ == "__main__":
    main()

