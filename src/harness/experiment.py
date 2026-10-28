"""Batch experiments: load a matrix, run every cell, write summaries.

A batch is written to ``<output_root>/<batch_id>/`` (Decision 22):

- ``batch.json``: the matrix, Git SHA, whether tracked files had uncommitted
  changes, start and end time, and run counts per execution status;
- ``runs/<run_id>/``: the four files of every run;
- ``summary.json``: every cell metric, including per-detector rates;
- ``summary.csv``: one row per cell with the core metrics;
- ``verdicts.csv``: runs per cell, detector, and reason code;
- ``detectors.csv``: each detector's confusion matrix per mode and corpus
  split (Decision 23).

The summaries are computed from the run files on disk, not from memory, so
they always describe exactly what was written.
"""

import csv
import json
import subprocess
from collections import Counter
from collections.abc import Callable, Sequence
from dataclasses import dataclass, fields, is_dataclass
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Any, Self

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

from contracts.results import ExecutionStatus
from contracts.scenario import Backend, DefenseMode, Scenario
from defenses.detection import prompt_injection, secret_scanner, session_validator
from harness.artifacts import format_utc, make_batch_id, make_run_id
from harness.dispatch import (
    BackendFactory,
    fake_script_factory,
    run_one,
    with_defense_mode,
)
from harness.metrics import (
    CellSummary,
    DetectorConfusion,
    Rate,
    VerdictCount,
    detector_confusion,
    load_run_record,
    summarize,
    verdict_counts,
)
from harness.scenario_loader import load_scenario

SUMMARY_COLUMNS = (
    "kind",
    "cell_id",
    "defense_mode",
    "backend",
    "runs",
    "completed",
    "error_rate",
    "error_count",
    "inconclusive_rate",
    "inconclusive_count",
    "attack_success_rate",
    "attack_success_count",
    "block_rate",
    "block_count",
    "detection_rate",
    "detection_count",
    "false_negative_rate",
    "false_negative_count",
    "relative_asr_reduction",
    "mitigation_false_positive_rate",
    "mitigation_false_positive_count",
    "total_latency_median_ms",
    "total_latency_min_ms",
    "total_latency_max_ms",
    "total_latency_p95_ms",
    "backend_latency_median_ms",
    "detection_latency_median_ms",
    "mitigation_latency_median_ms",
    "overhead_median_ms",
    "overhead_pairs",
)

VERDICT_COLUMNS = (
    "kind",
    "cell_id",
    "defense_mode",
    "backend",
    "detector_id",
    "reason_code",
    "detected",
    "warning",
    "runs_with_reason",
    "completed_runs",
)

DETECTOR_COLUMNS = (
    "detector_id",
    "defense_mode",
    "backend",
    "normal_use_split",
    "target_attacks",
    "true_positives",
    "false_negatives",
    "false_positives",
    "true_negatives",
    "true_positive_rate",
    "false_positive_rate",
    "normal_use_warnings",
)


# --- the matrix -------------------------------------------------------------

# The detectors whose confusion matrix is reported (Decision 23). The
# mitigations in a control set are not detectors and need no targets.
DETECTOR_IDS = frozenset(
    {
        prompt_injection.DETECTOR_ID,
        session_validator.BINDING_VALIDATOR_ID,
        session_validator.REPLAY_VALIDATOR_ID,
        secret_scanner.DETECTOR_ID,
    }
)


class MatrixScenario(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    file: Path
    control_set: str = Field(min_length=1)


class Matrix(BaseModel):
    """An experiment matrix, stored as YAML. Paths are relative to the
    repository root, where every command runs."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    matrix_id: str = Field(min_length=1, pattern=r"^[a-z0-9_]+$")
    backend: Backend
    fake_script_dir: Path | None = None
    defense_modes: list[DefenseMode] = Field(min_length=1)
    seeds: list[int] = Field(min_length=1)
    repetitions: int = Field(ge=1)
    control_sets: dict[str, list[str]]
    # The attacks each detector is built for: only their runs are the
    # detector's positives (Decision 23, amendment).
    detector_targets: dict[str, list[str]] = Field(default_factory=dict)
    scenarios: list[MatrixScenario] = Field(min_length=1)

    @model_validator(mode="after")
    def check_matrix(self) -> Self:
        if len(set(self.defense_modes)) != len(self.defense_modes):
            raise ValueError("defense_modes must not repeat")

        if len(set(self.seeds)) != len(self.seeds) or min(self.seeds) < 0:
            raise ValueError("seeds must be distinct and non-negative")

        if any(not controls for controls in self.control_sets.values()):
            raise ValueError("every control set needs at least one control")

        unknown = {entry.control_set for entry in self.scenarios} - set(
            self.control_sets
        )
        if unknown:
            raise ValueError(f"Unknown control sets: {', '.join(sorted(unknown))}")

        files = [entry.file for entry in self.scenarios]
        if len(set(files)) != len(files):
            raise ValueError("a scenario file is listed twice")

        unknown_detectors = set(self.detector_targets) - DETECTOR_IDS
        if unknown_detectors:
            raise ValueError(
                f"Unknown detectors in detector_targets: "
                f"{', '.join(sorted(unknown_detectors))}"
            )

        used_detectors = {
            control
            for entry in self.scenarios
            for control in self.control_sets[entry.control_set]
            if control in DETECTOR_IDS
        }
        untargeted = used_detectors - set(self.detector_targets)
        if untargeted:
            raise ValueError(
                f"Detectors without detector_targets: {', '.join(sorted(untargeted))}"
            )

        if any(not attacks for attacks in self.detector_targets.values()):
            raise ValueError("every detector needs at least one target attack")

        if self.backend == Backend.GEMINI:
            raise ValueError("The Gemini backend is not available yet")

        if self.backend == Backend.FAKE and self.fake_script_dir is None:
            raise ValueError("a Fake matrix needs fake_script_dir")

        return self


def load_matrix(path: str | Path) -> Matrix:
    matrix_path = Path(path)

    if not matrix_path.is_file():
        raise FileNotFoundError(f"Matrix file does not exist: {matrix_path}")

    with matrix_path.open("r", encoding="utf-8") as file:
        raw: Any = yaml.safe_load(file)

    if not isinstance(raw, dict):
        raise TypeError("Matrix YAML must contain a top-level mapping")

    return Matrix.model_validate(raw)


@dataclass(frozen=True)
class PlannedRun:
    run_id: str
    scenario: Scenario


def plan_runs(matrix: Matrix) -> tuple[PlannedRun, ...]:
    """Every run of the matrix, in a fixed order: scenario, seed, repetition,
    then defense mode. Fails before anything runs if the matrix is unusable."""
    planned: list[PlannedRun] = []

    for entry in matrix.scenarios:
        base = load_scenario(entry.file)

        if base.defense_mode != DefenseMode.NONE:
            raise ValueError(f"{entry.file} must keep defense_mode: none")

        if base.backend != matrix.backend:
            raise ValueError(f"{entry.file} is for another backend")

        controls = matrix.control_sets[entry.control_set]

        for seed in matrix.seeds:
            for repetition in range(1, matrix.repetitions + 1):
                for mode in matrix.defense_modes:
                    scenario = with_defense_mode(
                        base, mode, controls, seed=seed, repetition=repetition
                    )
                    planned.append(PlannedRun(make_run_id(scenario), scenario))

    run_ids = [run.run_id for run in planned]
    if len(set(run_ids)) != len(run_ids):
        raise ValueError("two scenario files share a scenario_id")

    # A target that is not in the matrix would quietly leave a detector
    # without positives (Decision 23, amendment).
    planned_attacks = {run.scenario.attack_id for run in planned}
    missing = {
        attack
        for attacks in matrix.detector_targets.values()
        for attack in attacks
        if attack not in planned_attacks
    }
    if missing:
        raise ValueError(
            f"detector_targets names attacks not in the matrix: "
            f"{', '.join(sorted(missing))}"
        )

    return tuple(planned)


def backend_factory_for(matrix: Matrix) -> BackendFactory:
    if matrix.backend == Backend.FAKE and matrix.fake_script_dir is not None:
        return fake_script_factory(matrix.fake_script_dir)

    raise ValueError(f"No backend factory for {matrix.backend.value}")


# --- running a batch --------------------------------------------------------


@dataclass(frozen=True)
class BatchOutcome:
    batch_id: str
    batch_dir: Path
    status_counts: dict[str, int]
    summaries: tuple[CellSummary, ...]

    @property
    def run_count(self) -> int:
        return sum(self.status_counts.values())

    @property
    def has_errors(self) -> bool:
        return self.status_counts[ExecutionStatus.ERROR.value] > 0


async def run_batch(
    matrix: Matrix,
    *,
    matrix_file: Path,
    output_root: Path,
    git_sha: str,
    git_dirty: bool,
    started_at: datetime | None = None,
    progress: Callable[[str], None] | None = None,
) -> BatchOutcome:
    """Run every planned run, then write the summaries.

    A failed run never stops the batch and is never retried. ``progress``
    receives one line per run with its ID and execution status only.
    """
    started_at = started_at or datetime.now(UTC)
    planned = plan_runs(matrix)
    backend_factory = backend_factory_for(matrix)

    batch_id = make_batch_id(started_at)
    batch_dir = output_root / batch_id
    runs_dir = batch_dir / "runs"

    # An existing batch directory is never reused (Decision 22).
    batch_dir.mkdir(parents=True, exist_ok=False)
    runs_dir.mkdir()

    batch_info: dict[str, Any] = {
        "batch_id": batch_id,
        "matrix_id": matrix.matrix_id,
        "matrix_file": matrix_file.as_posix(),
        "matrix": matrix.model_dump(mode="json"),
        "git_sha": git_sha,
        "git_dirty": git_dirty,
        "started_at_utc": format_utc(started_at),
        "finished_at_utc": None,
        "planned_runs": len(planned),
        "status_counts": None,
    }
    _write_json(batch_dir / "batch.json", batch_info)

    for index, planned_run in enumerate(planned, start=1):
        harness_run = await run_one(
            planned_run.scenario,
            run_id=planned_run.run_id,
            backend_factory=backend_factory,
            artifact_dir=runs_dir,
            git_sha=git_sha,
        )

        if progress is not None:
            status = harness_run.result.execution_status.value
            progress(f"[{index}/{len(planned)}] {planned_run.run_id}: {status}")

    records = [load_run_record(runs_dir / run.run_id) for run in planned]
    summaries = summarize(records)
    confusion = detector_confusion(records, matrix.detector_targets)

    _write_json(
        batch_dir / "summary.json",
        {
            "batch_id": batch_id,
            "cells": to_jsonable(summaries),
            "detectors": to_jsonable(confusion),
        },
    )
    _write_csv(
        batch_dir / "summary.csv",
        SUMMARY_COLUMNS,
        [summary_row(summary) for summary in summaries],
    )
    _write_csv(
        batch_dir / "verdicts.csv",
        VERDICT_COLUMNS,
        [verdict_row(row) for row in verdict_counts(records)],
    )
    _write_csv(
        batch_dir / "detectors.csv",
        DETECTOR_COLUMNS,
        [detector_row(row) for row in confusion],
    )

    counted = Counter(record.result.execution_status.value for record in records)
    status_counts = {status.value: counted[status.value] for status in ExecutionStatus}

    batch_info["finished_at_utc"] = format_utc(datetime.now(UTC))
    batch_info["status_counts"] = status_counts
    _write_json(batch_dir / "batch.json", batch_info)

    return BatchOutcome(
        batch_id=batch_id,
        batch_dir=batch_dir,
        status_counts=status_counts,
        summaries=summaries,
    )


def git_state() -> tuple[str, bool]:
    """The HEAD commit, and whether tracked files have uncommitted changes.

    Untracked files are ignored: they cannot change the code that ran.
    """

    def git(*args: str) -> str:
        completed = subprocess.run(
            ["git", *args], check=True, capture_output=True, text=True
        )
        return completed.stdout.strip()

    return git("rev-parse", "HEAD"), bool(
        git("status", "--porcelain", "--untracked-files=no")
    )


# --- serialization ----------------------------------------------------------


def to_jsonable(value: Any) -> Any:
    """Turn metric dataclasses into JSON values; a Rate keeps its value too."""
    if isinstance(value, Rate):
        return {"count": value.count, "total": value.total, "value": value.value}

    if is_dataclass(value) and not isinstance(value, type):
        return {
            field.name: to_jsonable(getattr(value, field.name))
            for field in fields(value)
        }

    if isinstance(value, Enum):
        return value.value

    if isinstance(value, dict):
        return {str(key): to_jsonable(item) for key, item in value.items()}

    if isinstance(value, (list, tuple)):
        return [to_jsonable(item) for item in value]

    return value


def summary_row(summary: CellSummary) -> dict[str, Any]:
    row: dict[str, Any] = {
        "kind": summary.kind.value,
        "cell_id": summary.cell_id,
        "defense_mode": summary.defense_mode.value,
        "backend": summary.backend.value,
        "runs": summary.runs,
        "completed": summary.completed,
        "relative_asr_reduction": summary.relative_asr_reduction,
        "total_latency_median_ms": summary.latency["total"].median_ms,
        "total_latency_min_ms": summary.latency["total"].min_ms,
        "total_latency_max_ms": summary.latency["total"].max_ms,
        "total_latency_p95_ms": summary.latency["total"].p95_ms,
        "backend_latency_median_ms": summary.latency["backend"].median_ms,
        "detection_latency_median_ms": summary.latency["detection"].median_ms,
        "mitigation_latency_median_ms": summary.latency["mitigation"].median_ms,
        "overhead_median_ms": (
            summary.overhead.median_ms if summary.overhead is not None else None
        ),
        "overhead_pairs": (
            summary.overhead.n_pairs if summary.overhead is not None else None
        ),
    }

    rates: Sequence[tuple[str, Rate | None]] = (
        ("error", summary.error_rate),
        ("inconclusive", summary.inconclusive_rate),
        ("attack_success", summary.attack_success_rate),
        ("block", summary.block_rate),
        ("detection", summary.detection_rate),
        ("false_negative", summary.false_negative_rate),
        ("mitigation_false_positive", summary.mitigation_false_positive_rate),
    )

    for name, rate in rates:
        row[f"{name}_rate"] = rate.value if rate is not None else None
        row[f"{name}_count"] = rate.count if rate is not None else None

    return row


def verdict_row(row: VerdictCount) -> dict[str, Any]:
    return {
        "kind": row.kind.value,
        "cell_id": row.cell_id,
        "defense_mode": row.defense_mode.value,
        "backend": row.backend.value,
        "detector_id": row.detector_id,
        "reason_code": row.reason_code,
        "detected": row.detected,
        "warning": row.warning,
        "runs_with_reason": row.runs_with_reason,
        "completed_runs": row.completed_runs,
    }


def _write_json(path: Path, value: Any) -> None:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def _write_csv(
    path: Path, columns: Sequence[str], rows: Sequence[dict[str, Any]]
) -> None:
    """Write rows; a metric that does not apply is an empty cell."""
    with path.open("w", encoding="utf-8", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=list(columns))
        writer.writeheader()

        for row in rows:
            writer.writerow(
                {
                    column: "" if row[column] is None else row[column]
                    for column in columns
                }
            )


def detector_row(row: DetectorConfusion) -> dict[str, Any]:
    return {
        "detector_id": row.detector_id,
        "defense_mode": row.defense_mode.value,
        "backend": row.backend.value,
        "normal_use_split": row.normal_use_split,
        "target_attacks": " ".join(row.target_attack_ids),
        "true_positives": row.true_positives,
        "false_negatives": row.false_negatives,
        "false_positives": row.false_positives,
        "true_negatives": row.true_negatives,
        "true_positive_rate": row.true_positive_rate.value,
        "false_positive_rate": row.false_positive_rate.value,
        "normal_use_warnings": row.normal_use_warnings,
    }
