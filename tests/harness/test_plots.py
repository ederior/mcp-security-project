import asyncio
import copy
import json
import shutil
from datetime import UTC, datetime
from pathlib import Path

import pytest

from harness.experiment import Matrix, load_matrix, run_batch
from harness.plots import PLOT_FILES, _sample_size, draw_batch_plots

MATRIX_FILE = Path("experiments/matrix_fake.yaml")
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
ATTACK_PLOTS = [
    "attack_success_rate.png",
    "block_rate.png",
    "detection_rate.png",
    "latency_overhead.png",
]


def attack_only_matrix() -> Matrix:
    """The six attacks without the normal-use corpus, so no FPR plot."""
    matrix = load_matrix(MATRIX_FILE)
    attacks = [
        e for e in matrix.scenarios if e.file.parent == Path("scenarios/attacks")
    ]
    return matrix.model_copy(update={"scenarios": attacks})


@pytest.fixture(scope="module")
def fake_batch(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """One real 18-run attack batch, shared by the tests in this module."""
    outcome = asyncio.run(
        run_batch(
            attack_only_matrix(),
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


def test_no_false_positive_plot_without_normal_use_runs(
    fake_batch: Path, tmp_path: Path
) -> None:
    batch_dir = copy_batch(fake_batch, tmp_path)

    draw_batch_plots(batch_dir)

    # Attack-only confusion rows have no normal-use split to plot.
    assert list((batch_dir / "plots").glob("false_positive_rate*")) == []


def test_one_false_positive_plot_per_corpus_split(
    fake_batch: Path, tmp_path: Path
) -> None:
    batch_dir = copy_batch(fake_batch, tmp_path)
    summary_path = batch_dir / "summary.json"
    summary = json.loads(summary_path.read_text(encoding="utf-8"))

    # Give every defended confusion row a development and a holdout twin,
    # in the structure detector_confusion() writes.
    for row in list(summary["detectors"]):
        for split in ("development", "final_holdout"):
            twin = copy.deepcopy(row)
            twin.update(
                normal_use_split=split,
                false_positives=1,
                true_negatives=9,
                false_positive_rate={"count": 1, "total": 10, "value": 0.1},
            )
            summary["detectors"].append(twin)

    summary_path.write_text(json.dumps(summary), encoding="utf-8")

    written = draw_batch_plots(batch_dir)

    assert [path.name for path in written] == [
        *ATTACK_PLOTS,
        "false_positive_rate_development.png",
        "false_positive_rate_final_holdout.png",
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
