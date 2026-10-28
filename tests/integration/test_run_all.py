import asyncio
import csv
import json
import re
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from harness.experiment import (
    DETECTOR_COLUMNS,
    SUMMARY_COLUMNS,
    VERDICT_COLUMNS,
    BatchOutcome,
    Matrix,
    load_matrix,
    run_batch,
)

MATRIX_FILE = Path("experiments/matrix_fake.yaml")
STARTED_AT = datetime(2026, 10, 28, 15, 30, 0, tzinfo=UTC)
RUN_FILES = ["config.json", "environment.json", "events.jsonl", "result.json"]
BATCH_FILES = [
    "batch.json",
    "detectors.csv",
    "runs",
    "summary.csv",
    "summary.json",
    "verdicts.csv",
]

# The synthetic-secret formats (Decisions 4 and 14).
SECRET_FORMAT = re.compile(r"(?:FAKE_SECRET|CANARY)_[A-Za-z0-9]")


def run(
    matrix: Matrix, output_root: Path, progress: list[str] | None = None
) -> BatchOutcome:
    return asyncio.run(
        run_batch(
            matrix,
            matrix_file=MATRIX_FILE,
            output_root=output_root,
            git_sha="test_sha",
            git_dirty=False,
            started_at=STARTED_AT,
            progress=None if progress is None else progress.append,
        )
    )


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as file:
        return list(csv.DictReader(file))


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def all_text(directory: Path) -> str:
    return "\n".join(
        path.read_text(encoding="utf-8")
        for path in sorted(directory.rglob("*"))
        if path.is_file()
    )


def test_fake_batch_writes_runs_and_summaries(tmp_path: Path) -> None:
    progress: list[str] = []

    outcome = run(load_matrix(MATRIX_FILE), tmp_path, progress)

    batch_dir = tmp_path / "20261028T153000Z"
    assert outcome.batch_dir == batch_dir
    assert sorted(path.name for path in batch_dir.iterdir()) == BATCH_FILES
    assert outcome.status_counts == {"completed": 66, "error": 0, "inconclusive": 0}
    assert outcome.has_errors is False

    run_dirs = sorted((batch_dir / "runs").iterdir())
    assert len(run_dirs) == 66
    for run_dir in run_dirs:
        assert sorted(path.name for path in run_dir.iterdir()) == RUN_FILES

    batch = read_json(batch_dir / "batch.json")
    assert batch["git_sha"] == "test_sha"
    assert batch["git_dirty"] is False
    assert batch["started_at_utc"] == "2026-10-28T15:30:00Z"
    assert batch["finished_at_utc"] is not None
    assert batch["planned_runs"] == 66
    assert batch["matrix"]["matrix_id"] == "fake_core_v1"

    summary_rows = read_csv(batch_dir / "summary.csv")
    # 22 scenarios in 3 modes; each normal-use case is its own cell.
    assert len(summary_rows) == 66
    assert list(summary_rows[0]) == list(SUMMARY_COLUMNS)

    by_cell = {(row["cell_id"], row["defense_mode"]): row for row in summary_rows}
    assert by_cell[("AC-PI1a", "none")]["attack_success_rate"] == "1.0"
    assert by_cell[("AC-PI1a", "none")]["detection_rate"] == ""
    assert by_cell[("AC-SH3a", "detect_and_mitigate")]["block_rate"] == "1.0"
    assert by_cell[("AC-CL1a", "detect_and_mitigate")]["relative_asr_reduction"] == (
        "1.0"
    )

    summary = read_json(batch_dir / "summary.json")
    assert len(summary["cells"]) == 66
    assert summary["cells"][0]["attack_success_rate"] == {
        "count": 1,
        "total": 1,
        "value": 1.0,
    }

    detector_rows = read_csv(batch_dir / "detectors.csv")
    assert list(detector_rows[0]) == list(DETECTOR_COLUMNS)
    assert len(summary["detectors"]) == len(detector_rows)
    # Every development row of every detector: no false positives.
    development = [r for r in detector_rows if r["normal_use_split"] == "development"]
    assert development
    assert {r["false_positives"] for r in development} == {"0"}
    # Each detector is scored on the attacks it targets (Decision 23).
    by_detector = {(r["detector_id"], r["defense_mode"]): r for r in detector_rows}
    for detector_id in ("session_binding_validator_v1", "replay_validator_v1"):
        row = by_detector[(detector_id, "detect")]
        assert (row["true_positives"], row["false_negatives"]) == ("1", "0")
    assert by_detector[("prompt_injection_rules_v1", "detect")]["target_attacks"] == (
        "AC-PI1a AC-PI2a AC-CL2a"
    )

    verdict_rows = read_csv(batch_dir / "verdicts.csv")
    assert verdict_rows
    assert list(verdict_rows[0]) == list(VERDICT_COLUMNS)

    assert len(progress) == 66
    assert progress[0] == "[1/66] ac_pi1a_baseline__none__seed0__rep1: completed"


def test_no_synthetic_secret_appears_anywhere_in_the_batch(tmp_path: Path) -> None:
    progress: list[str] = []
    outcome = run(load_matrix(MATRIX_FILE), tmp_path, progress)

    assert SECRET_FORMAT.search(all_text(outcome.batch_dir)) is None
    assert SECRET_FORMAT.search("\n".join(progress)) is None


def test_failed_runs_do_not_stop_the_batch(tmp_path: Path) -> None:
    empty_scripts = tmp_path / "no_scripts"
    empty_scripts.mkdir()
    matrix = load_matrix(MATRIX_FILE).model_copy(
        update={"fake_script_dir": empty_scripts}
    )

    outcome = run(matrix, tmp_path / "results")

    # Without scripts, every model run fails: 4 attacks and 11 normal-use
    # cases, in 3 modes. SH1a, SH3a, and the 5 session cases need no model.
    assert outcome.status_counts == {"completed": 21, "error": 45, "inconclusive": 0}
    assert outcome.has_errors is True

    rows = read_csv(outcome.batch_dir / "summary.csv")
    pi1a = next(row for row in rows if row["cell_id"] == "AC-PI1a")
    assert (pi1a["error_rate"], pi1a["completed"], pi1a["attack_success_rate"]) == (
        "1.0",
        "0",
        "",
    )


def test_an_existing_batch_directory_is_never_overwritten(tmp_path: Path) -> None:
    (tmp_path / "20261028T153000Z").mkdir()

    with pytest.raises(FileExistsError):
        run(load_matrix(MATRIX_FILE), tmp_path)


def test_run_all_command_runs_the_fake_matrix(tmp_path: Path) -> None:
    completed = subprocess.run(
        [sys.executable, "-m", "experiments.run_all", "--output-dir", str(tmp_path)],
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )

    assert completed.returncode == 0, completed.stderr
    assert "66 runs, 66 completed, 0 error, 0 inconclusive" in completed.stdout
    assert SECRET_FORMAT.search(completed.stdout + completed.stderr) is None

    # With normal-use cells, the false-positive plot is drawn too.
    assert "Plots: 5 written" in completed.stdout

    (batch_dir,) = tmp_path.iterdir()
    assert (batch_dir / "summary.csv").is_file()
    assert len(list((batch_dir / "plots").glob("*.png"))) == 5
    assert (batch_dir / "plots" / "false_positive_rate_development.png").is_file()
