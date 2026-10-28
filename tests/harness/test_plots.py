import asyncio
import copy
import json
import shutil
from datetime import UTC, datetime
from pathlib import Path

import pytest

from harness.experiment import load_matrix, run_batch
from harness.plots import PLOT_FILES, _sample_size, draw_batch_plots

MATRIX_FILE = Path("experiments/matrix_fake.yaml")
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
ATTACK_PLOTS = [
    "attack_success_rate.png",
    "block_rate.png",
    "detection_rate.png",
    "latency_overhead.png",
]


@pytest.fixture(scope="module")
def fake_batch(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """One real 18-run Fake batch, shared by the tests in this module."""
    outcome = asyncio.run(
        run_batch(
            load_matrix(MATRIX_FILE),
            matrix_file=MATRIX_FILE,
            output_root=tmp_path_factory.mktemp("results"),
            git_sha="test_sha",
            git_dirty=False,
            started_at=datetime(2026, 10, 28, 15, 30, 0, tzinfo=UTC),
        )
    )
    return outcome.batch_dir


def copy_batch(batch_dir: Path, tmp_path: Path) -> Path:
    target = tmp_path / batch_dir.name
    shutil.copytree(batch_dir, target)
    return target


def test_attack_plots_are_written_as_png(fake_batch: Path, tmp_path: Path) -> None:
    batch_dir = copy_batch(fake_batch, tmp_path)

    written = draw_batch_plots(batch_dir)

    assert [path.name for path in written] == ATTACK_PLOTS
    assert set(ATTACK_PLOTS) <= set(PLOT_FILES)

    for path in written:
        assert path.parent == batch_dir / "plots"
        content = path.read_bytes()
        assert content.startswith(PNG_SIGNATURE)
        assert len(content) > 5_000


def test_no_false_positive_plot_without_normal_use_cells(
    fake_batch: Path, tmp_path: Path
) -> None:
    batch_dir = copy_batch(fake_batch, tmp_path)

    draw_batch_plots(batch_dir)

    assert not (batch_dir / "plots" / "false_positive_rate.png").exists()


def test_false_positive_plot_is_drawn_for_normal_use_cells(
    fake_batch: Path, tmp_path: Path
) -> None:
    batch_dir = copy_batch(fake_batch, tmp_path)
    summary_path = batch_dir / "summary.json"
    summary = json.loads(summary_path.read_text(encoding="utf-8"))

    # Turn two defended PI1a cells into normal-use cells: same structure as
    # summarize() writes, with attack-only metrics not applicable.
    for cell in summary["cells"]:
        if cell["cell_id"] == "AC-PI1a" and cell["defense_mode"] != "none":
            normal = copy.deepcopy(cell)
            normal.update(
                kind="normal_use",
                cell_id="benign_pi_note",
                attack_success_rate=None,
                block_rate=None,
                detection_rate=None,
                false_negative_rate=None,
                relative_asr_reduction=None,
            )
            summary["cells"].append(normal)

    summary_path.write_text(json.dumps(summary), encoding="utf-8")

    written = draw_batch_plots(batch_dir)

    assert [path.name for path in written] == [
        *ATTACK_PLOTS,
        "false_positive_rate.png",
    ]


def test_plots_can_be_redrawn(fake_batch: Path, tmp_path: Path) -> None:
    batch_dir = copy_batch(fake_batch, tmp_path)

    first = draw_batch_plots(batch_dir)
    second = draw_batch_plots(batch_dir)

    assert first == second


@pytest.mark.parametrize(
    ("counts", "expected"),
    [
        ([1, 1, 1], "n = 1 completed run per bar"),
        ([10, 10], "n = 10 completed runs per bar"),
        ([8, 10, 0], "n = 8–10 completed runs per bar"),
        ([0], "no completed runs"),
    ],
)
def test_sample_size_names_the_runs_behind_each_bar(
    counts: list[int], expected: str
) -> None:
    assert _sample_size(counts, "completed run") == expected
