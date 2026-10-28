"""Batch plots, drawn from a batch's summary.json and batch.json (Decision 22).

Each chart compares the three defense modes, so the modes use one ordered
blue ramp (light = no defense, dark = full defense) instead of unrelated
colors. The detection chart's two series use the first two categorical
slots. Both palettes were checked with the dataviz palette validator
(ordinal ramp; two-slot categorical, light mode).

The plots are for the PDF report, so they are drawn in light mode only.
summary.csv is the table view of every chart: each plotted value is there
with its count. A zero bar is labeled "0%" and a metric that does not apply
is labeled "n/a", so an empty slot is never ambiguous.
"""

import json
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from matplotlib.axes import Axes
from matplotlib.figure import Figure
from matplotlib.patches import Patch
from matplotlib.ticker import PercentFormatter

# --- palette and chrome (dataviz reference palette, light mode) -------------

SURFACE = "#fcfcfb"
INK_PRIMARY = "#0b0b0b"
INK_SECONDARY = "#52514e"
INK_MUTED = "#898781"
GRIDLINE = "#e1e0d9"
BASELINE = "#c3c2b7"

# Ordered blue ramp, steps 250 / 450 / 650.
MODE_COLORS = {
    "none": "#86b6ef",
    "detect": "#2a78d6",
    "detect_and_mitigate": "#104281",
}
MODE_LABELS = {
    "none": "No defense",
    "detect": "Detect only",
    "detect_and_mitigate": "Detect and mitigate",
}

# Categorical slots 1 and 2.
SERIES_BLUE = "#2a78d6"
SERIES_ORANGE = "#eb6834"

DPI = 150
FIGURE_SIZE = (9.0, 4.8)
MAX_BAR_PX = 22.0  # bars stay thin: at most 24px (dataviz mark spec)
BAR_GAP_PX = 2.0  # surface gap between touching bars

PLOT_FILES = (
    "attack_success_rate.png",
    "block_rate.png",
    "detection_rate.png",
    "false_positive_rate.png",
    "latency_overhead.png",
)


@dataclass(frozen=True)
class Series:
    label: str
    color: str
    values: Sequence[float | None]  # None = the metric does not apply


def draw_batch_plots(batch_dir: Path) -> tuple[Path, ...]:
    """Draw every plot that has data into batch_dir/plots/; return the files.

    The false-positive chart is drawn only when the batch has normal-use
    cells.
    """
    summary = _read_json(batch_dir / "summary.json")
    batch = _read_json(batch_dir / "batch.json")
    cells: list[dict[str, Any]] = summary["cells"]
    context = _context_line(batch)

    plots_dir = batch_dir / "plots"
    plots_dir.mkdir(exist_ok=True)
    written: list[Path] = []

    attacks = [cell for cell in cells if cell["kind"] == "attack"]
    normal_use = [cell for cell in cells if cell["kind"] == "normal_use"]

    if attacks:
        written.append(
            _mode_rate_chart(
                attacks,
                metric="attack_success_rate",
                modes=("none", "detect", "detect_and_mitigate"),
                title="Attack success rate by defense mode",
                context=context,
                path=plots_dir / "attack_success_rate.png",
            )
        )
        written.append(
            _mode_rate_chart(
                attacks,
                metric="block_rate",
                modes=("none", "detect", "detect_and_mitigate"),
                title="Block rate by defense mode",
                context=context,
                path=plots_dir / "block_rate.png",
            )
        )
        written.append(
            _detection_chart(attacks, context, plots_dir / "detection_rate.png")
        )
        written.append(
            _overhead_chart(attacks, context, plots_dir / "latency_overhead.png")
        )

    if normal_use:
        written.append(
            _false_positive_chart(
                normal_use, context, plots_dir / "false_positive_rate.png"
            )
        )

    return tuple(written)


# --- the charts -------------------------------------------------------------


def _mode_rate_chart(
    cells: Sequence[dict[str, Any]],
    *,
    metric: str,
    modes: Sequence[str],
    title: str,
    context: str,
    path: Path,
) -> Path:
    groups = _ordered_ids(cells)
    series = [
        Series(
            MODE_LABELS[mode],
            MODE_COLORS[mode],
            [_rate_value(_find(cells, group, mode), metric) for group in groups],
        )
        for mode in modes
    ]
    totals = [
        _rate_total(cell, metric) for cell in cells if cell["defense_mode"] in modes
    ]

    figure, (axes,) = _figure(1)
    _grouped_bars(axes, groups, series, percent=True)
    _frame(figure, title, f"{context} · {_sample_size(totals, 'completed run')}")
    _legend(figure, series)
    return _save(figure, path)


def _detection_chart(cells: Sequence[dict[str, Any]], context: str, path: Path) -> Path:
    """Run-level detection next to the prompt-injection content rules.

    The policy check fires on every out-of-policy call by construction, so
    the content-rule rate is the one that shows text-rule quality.
    """
    groups = _ordered_ids(cells)
    modes = ("detect", "detect_and_mitigate")
    figure, panels = _figure(len(modes))
    totals: list[int] = []
    series: list[Series] = []

    for axes, mode in zip(panels, modes, strict=True):
        found = [_find(cells, group, mode) for group in groups]
        series = [
            Series(
                "Any detection (run level)",
                SERIES_BLUE,
                [_rate_value(cell, "detection_rate") for cell in found],
            ),
            Series(
                "Prompt-injection content rules",
                SERIES_ORANGE,
                [_content_rule_value(cell) for cell in found],
            ),
        ]
        totals += [_rate_total(cell, "detection_rate") for cell in found]
        _grouped_bars(axes, groups, series, percent=True)
        axes.set_title(
            MODE_LABELS[mode], loc="left", fontsize=10, color=INK_SECONDARY, pad=8
        )

    _frame(
        figure,
        "Detection rate: all detectors vs content rules only",
        f"{context} · {_sample_size(totals, 'completed run')}",
    )
    _legend(figure, series)
    return _save(figure, path)


def _false_positive_chart(
    cells: Sequence[dict[str, Any]], context: str, path: Path
) -> Path:
    """Per detector: innocent runs it flagged, in the two defended modes."""
    modes = ("detect", "detect_and_mitigate")
    pairs = sorted(
        {
            (cell["cell_id"], detector["detector_id"])
            for cell in cells
            if cell["defense_mode"] in modes
            for detector in cell["detectors"]
        }
    )
    groups = [f"{cell_id}\n{detector_id}" for cell_id, detector_id in pairs]
    series = [
        Series(
            MODE_LABELS[mode],
            MODE_COLORS[mode],
            [
                _detector_flagged(_find(cells, cell_id, mode), detector_id)
                for cell_id, detector_id in pairs
            ],
        )
        for mode in modes
    ]
    totals = [cell["completed"] for cell in cells if cell["defense_mode"] in modes]

    figure, (axes,) = _figure(1)
    _grouped_bars(axes, groups, series, percent=True)
    _frame(
        figure,
        "False-positive rate on normal-use scenarios, per detector",
        f"{context} · {_sample_size(totals, 'completed run')}",
    )
    _legend(figure, series)
    return _save(figure, path)


def _overhead_chart(cells: Sequence[dict[str, Any]], context: str, path: Path) -> Path:
    groups = _ordered_ids(cells)
    modes = ("detect", "detect_and_mitigate")
    series = [
        Series(
            MODE_LABELS[mode],
            MODE_COLORS[mode],
            [_overhead_value(_find(cells, group, mode)) for group in groups],
        )
        for mode in modes
    ]
    pairs = [
        cell["overhead"]["n_pairs"]
        for cell in cells
        if cell["defense_mode"] in modes and cell["overhead"] is not None
    ]

    figure, (axes,) = _figure(1)
    _grouped_bars(axes, groups, series, percent=False)
    axes.set_ylabel("Milliseconds", color=INK_MUTED, fontsize=9)
    _frame(
        figure,
        "Defense latency overhead (median paired difference vs no defense)",
        f"{context} · {_sample_size(pairs, 'paired run')}",
    )
    _legend(figure, series)
    return _save(figure, path)


# --- drawing helpers --------------------------------------------------------


def _figure(panels: int) -> tuple[Figure, list[Axes]]:
    figure = Figure(figsize=FIGURE_SIZE, dpi=DPI, facecolor=SURFACE)
    axes_list = [figure.add_subplot(1, panels, index + 1) for index in range(panels)]

    if panels > 1:
        # One y-scale for every panel, so the panels compare directly.
        for axes in axes_list[1:]:
            axes.sharey(axes_list[0])

    figure.subplots_adjust(top=0.72, bottom=0.14, left=0.08, right=0.98, wspace=0.12)
    return figure, axes_list


def _grouped_bars(
    axes: Axes,
    groups: Sequence[str],
    series: Sequence[Series],
    *,
    percent: bool,
) -> None:
    axes.set_facecolor(SURFACE)

    width_px = axes.get_position().width * FIGURE_SIZE[0] * DPI
    px_per_unit = width_px / max(len(groups), 1)
    bar_width = min(MAX_BAR_PX / px_per_unit, 0.8 / max(len(series), 1))
    step = bar_width + BAR_GAP_PX / px_per_unit
    first_offset = -step * (len(series) - 1) / 2

    for index, item in enumerate(series):
        for position, value in enumerate(item.values):
            x = position + first_offset + index * step

            if value is None:
                _note(axes, x, "n/a")
            elif value == 0:
                _note(axes, x, "0%" if percent else "0")
            else:
                axes.bar(x, value, width=bar_width, color=item.color, zorder=2)

    axes.set_xticks(range(len(groups)), labels=list(groups))
    axes.set_xlim(-0.5, len(groups) - 0.5)

    if percent:
        axes.set_ylim(0, 1)
        axes.set_yticks([0, 0.25, 0.5, 0.75, 1.0])
        axes.yaxis.set_major_formatter(PercentFormatter(xmax=1.0, decimals=0))

    axes.axhline(0, color=BASELINE, linewidth=1, zorder=3)
    axes.grid(axis="y", color=GRIDLINE, linewidth=1, linestyle="-", zorder=0)
    axes.set_axisbelow(True)

    for side in ("top", "right", "left", "bottom"):
        axes.spines[side].set_visible(False)

    axes.tick_params(axis="both", length=0, labelsize=9, colors=INK_MUTED)
    axes.tick_params(axis="x", labelcolor=INK_SECONDARY)


def _note(axes: Axes, x: float, text: str) -> None:
    """A small muted label at the baseline where no bar is drawn."""
    axes.annotate(
        text,
        xy=(x, 0),
        xytext=(0, 3),
        textcoords="offset points",
        ha="center",
        va="bottom",
        fontsize=7,
        color=INK_MUTED,
        rotation=90,
        zorder=4,
    )


def _frame(figure: Figure, title: str, subtitle: str) -> None:
    figure.text(0.08, 0.95, title, fontsize=13, color=INK_PRIMARY, weight="semibold")
    figure.text(0.08, 0.895, subtitle, fontsize=9, color=INK_SECONDARY)


def _legend(figure: Figure, series: Sequence[Series]) -> None:
    figure.legend(
        handles=[Patch(color=item.color, label=item.label) for item in series],
        loc="upper left",
        bbox_to_anchor=(0.075, 0.875),
        ncol=len(series),
        frameon=False,
        fontsize=9,
        labelcolor=INK_SECONDARY,
        handlelength=1.0,
        handleheight=1.0,
        columnspacing=1.6,
    )


def _save(figure: Figure, path: Path) -> Path:
    figure.savefig(path, facecolor=SURFACE, metadata={"Software": None})
    return path


# --- reading summary.json ---------------------------------------------------


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))

    if not isinstance(value, dict):
        raise TypeError(f"{path} must contain a JSON object")

    return value


def _context_line(batch: dict[str, Any]) -> str:
    matrix = batch["matrix"]
    seeds = ", ".join(str(seed) for seed in matrix["seeds"])
    backend = str(matrix["backend"]).capitalize()
    return f"{backend} backend · batch {batch['batch_id']} · seed {seeds}"


def _ordered_ids(cells: Sequence[dict[str, Any]]) -> list[str]:
    return sorted({cell["cell_id"] for cell in cells})


def _find(cells: Sequence[dict[str, Any]], cell_id: str, mode: str) -> dict[str, Any]:
    for cell in cells:
        if cell["cell_id"] == cell_id and cell["defense_mode"] == mode:
            return cell

    return {}


def _optional_float(value: object) -> float | None:
    """A JSON number, or None where the metric does not apply."""
    if value is None:
        return None

    if not isinstance(value, (int, float)):
        raise TypeError(f"Expected a number in summary.json, got {value!r}")

    return float(value)


def _rate_value(cell: dict[str, Any], metric: str) -> float | None:
    rate = cell.get(metric)
    return None if rate is None else _optional_float(rate["value"])


def _rate_total(cell: dict[str, Any], metric: str) -> int:
    rate = cell.get(metric)
    return 0 if rate is None else int(rate["total"])


def _content_rule_value(cell: dict[str, Any]) -> float | None:
    for detector in cell.get("detectors", []):
        group = detector["groups"].get("content_rules")

        if group is not None:
            return _optional_float(group["value"])

    return None


def _detector_flagged(cell: dict[str, Any], detector_id: str) -> float | None:
    for detector in cell.get("detectors", []):
        if detector["detector_id"] == detector_id:
            return _optional_float(detector["flagged"]["value"])

    return None


def _overhead_value(cell: dict[str, Any]) -> float | None:
    overhead = cell.get("overhead")
    return None if overhead is None else _optional_float(overhead["median_ms"])


def _sample_size(counts: Sequence[int], unit: str) -> str:
    """'n = 1 completed run per bar', or a range when bars differ."""
    shown = [count for count in counts if count > 0]

    if not shown:
        return f"no {unit}s"

    low, high = min(shown), max(shown)
    plural = "" if high == 1 else "s"
    span = str(low) if low == high else f"{low}–{high}"
    return f"n = {span} {unit}{plural} per bar"
