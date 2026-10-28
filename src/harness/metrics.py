"""Experiment metrics computed from written runs (Decision 22).

Every function here is pure: it reads run records and returns numbers, and
never runs a scenario. Definitions follow docs/experiment_plan.md §6:

- only completed runs enter attack and defense rate denominators;
- error and inconclusive rates are computed over all runs;
- per-detector rates count only enforcing positive verdicts, so warnings
  are reported separately (Decision 10);
- defense overhead is the paired difference in total latency between a
  defended run and the matching run in mode ``none``.

Every rate keeps its count and total, so each reported number can name its
sample size.
"""

import statistics
from collections import defaultdict
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, replace
from enum import Enum
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from contracts.results import (
    AttackOutcome,
    DetectionOutcome,
    DetectionVerdict,
    ExecutionStatus,
    MitigationOutcome,
    RunResult,
)
from contracts.scenario import Backend, DefenseMode
from defenses.detection import prompt_injection
from defenses.detection.secret_scanner import WARNING_REASON_CODES

# p95 is reported only for at least this many completed runs (§6.5).
P95_MIN_SAMPLES = 20

# Reason-code groups reported separately for one detector (Decision 22). The
# policy check calls the same function as tool_authorization_policy_v1, so
# its detection rate on prompt-injection attacks is 100% by construction.
REASON_GROUPS: dict[str, dict[str, frozenset[str]]] = {
    prompt_injection.DETECTOR_ID: {
        "content_rules": frozenset(
            {prompt_injection.CONTAINS_OVERRIDE, prompt_injection.REQUESTS_TOOL}
        ),
        "policy_check": frozenset({prompt_injection.FOLLOWUP_OUTSIDE_GOAL}),
    },
}

LATENCY_COMPONENTS = ("total", "backend", "detection", "mitigation")

_MODE_ORDER = {
    DefenseMode.NONE: 0,
    DefenseMode.DETECT: 1,
    DefenseMode.DETECT_AND_MITIGATE: 2,
}


class CellKind(str, Enum):
    ATTACK = "attack"
    NORMAL_USE = "normal_use"


# --- run records ------------------------------------------------------------


class _RunConfig(BaseModel):
    """The config.json fields the metrics need; other fields are ignored."""

    model_config = ConfigDict(extra="ignore")

    run_id: str
    scenario_id: str
    attack_id: str | None
    defense_mode: DefenseMode
    backend: Backend
    seed: int
    repetition: int


@dataclass(frozen=True)
class RunRecord:
    """One run as the metrics see it: its setup and its result."""

    run_id: str
    scenario_id: str
    attack_id: str | None
    defense_mode: DefenseMode
    backend: Backend
    seed: int
    repetition: int
    result: RunResult

    @property
    def completed(self) -> bool:
        return self.result.execution_status == ExecutionStatus.COMPLETED

    @property
    def kind(self) -> CellKind:
        return CellKind.NORMAL_USE if self.attack_id is None else CellKind.ATTACK

    @property
    def cell_id(self) -> str:
        """The attack ID, or the scenario ID for a normal-use scenario."""
        return self.attack_id if self.attack_id is not None else self.scenario_id


def load_run_record(run_dir: Path) -> RunRecord:
    """Read config.json and result.json from one run directory."""
    config = _RunConfig.model_validate_json(
        (run_dir / "config.json").read_text(encoding="utf-8")
    )
    result = RunResult.model_validate_json(
        (run_dir / "result.json").read_text(encoding="utf-8")
    )

    if (config.run_id, config.scenario_id) != (result.run_id, result.scenario_id):
        raise ValueError(f"config.json and result.json disagree in {run_dir}")

    return RunRecord(
        run_id=config.run_id,
        scenario_id=config.scenario_id,
        attack_id=config.attack_id,
        defense_mode=config.defense_mode,
        backend=config.backend,
        seed=config.seed,
        repetition=config.repetition,
        result=result,
    )


# --- metric values ----------------------------------------------------------


@dataclass(frozen=True)
class Rate:
    """``count`` out of ``total`` runs; ``value`` is None when total is 0."""

    count: int
    total: int

    @property
    def value(self) -> float | None:
        return None if self.total == 0 else self.count / self.total


@dataclass(frozen=True)
class LatencyStats:
    """Median, minimum, maximum, and (from 20 samples) p95, in milliseconds."""

    n: int
    median_ms: float | None
    min_ms: float | None
    max_ms: float | None
    p95_ms: float | None


@dataclass(frozen=True)
class OverheadStats:
    """Paired total-latency differences against the matching ``none`` run."""

    n_pairs: int
    n_unpaired: int
    median_ms: float | None
    min_ms: float | None
    max_ms: float | None


@dataclass(frozen=True)
class DetectorStats:
    """One detector in one cell, over the cell's completed runs.

    In an attack cell ``flagged`` is the detector's detection rate; in a
    normal-use cell it is the detector's false-positive rate.
    """

    detector_id: str
    flagged: Rate
    warned: Rate
    groups: dict[str, Rate]


@dataclass(frozen=True)
class CellSummary:
    """All metrics of one cell: an attack or normal-use scenario, a defense
    mode, and a backend. A field is None where the metric does not apply."""

    kind: CellKind
    cell_id: str
    defense_mode: DefenseMode
    backend: Backend

    runs: int
    completed: int
    error_rate: Rate
    inconclusive_rate: Rate

    # Attack cells only.
    attack_success_rate: Rate | None
    block_rate: Rate | None
    detection_rate: Rate | None
    false_negative_rate: Rate | None
    relative_asr_reduction: float | None

    # Normal-use cells in detect_and_mitigate only.
    mitigation_false_positive_rate: Rate | None

    detectors: tuple[DetectorStats, ...]
    latency: dict[str, LatencyStats]
    overhead: OverheadStats | None


@dataclass(frozen=True)
class VerdictCount:
    """How many completed runs of a cell had a verdict with this reason code."""

    kind: CellKind
    cell_id: str
    defense_mode: DefenseMode
    backend: Backend
    detector_id: str
    reason_code: str
    detected: bool
    warning: bool
    runs_with_reason: int
    completed_runs: int


# --- computation ------------------------------------------------------------

_CellKey = tuple[CellKind, str, DefenseMode, Backend]


def summarize(records: Iterable[RunRecord]) -> tuple[CellSummary, ...]:
    """Compute every cell's metrics, sorted by kind, cell, mode, backend."""
    by_cell = _group_by_cell(records)

    summaries = {
        key: _summarize_cell(key, runs, _overhead(key, runs, by_cell))
        for key, runs in by_cell.items()
    }

    return tuple(
        _with_relative_reduction(summary, summaries)
        for _, summary in sorted(summaries.items(), key=lambda item: _sort_key(item[0]))
    )


def verdict_counts(records: Iterable[RunRecord]) -> tuple[VerdictCount, ...]:
    """Count runs per cell, detector, and reason code (for verdicts.csv).

    A run with several verdicts of the same reason code is counted once.
    """
    rows: list[VerdictCount] = []

    for key, runs in sorted(
        _group_by_cell(records).items(), key=lambda i: _sort_key(i[0])
    ):
        completed = [run for run in runs if run.completed]
        seen: dict[tuple[str, str, bool], set[str]] = defaultdict(set)

        for run in completed:
            for verdict in run.result.detection_verdicts:
                seen[(verdict.detector_id, verdict.reason_code, verdict.detected)].add(
                    run.run_id
                )

        kind, cell_id, mode, backend = key

        for (detector_id, reason_code, detected), run_ids in sorted(seen.items()):
            rows.append(
                VerdictCount(
                    kind=kind,
                    cell_id=cell_id,
                    defense_mode=mode,
                    backend=backend,
                    detector_id=detector_id,
                    reason_code=reason_code,
                    detected=detected,
                    warning=reason_code in WARNING_REASON_CODES,
                    runs_with_reason=len(run_ids),
                    completed_runs=len(completed),
                )
            )

    return tuple(rows)


def latency_stats(values: Sequence[float]) -> LatencyStats:
    if not values:
        return LatencyStats(n=0, median_ms=None, min_ms=None, max_ms=None, p95_ms=None)

    p95 = (
        statistics.quantiles(values, n=100, method="inclusive")[94]
        if len(values) >= P95_MIN_SAMPLES
        else None
    )

    return LatencyStats(
        n=len(values),
        median_ms=statistics.median(values),
        min_ms=min(values),
        max_ms=max(values),
        p95_ms=p95,
    )


def is_enforcing(verdict: DetectionVerdict) -> bool:
    """A positive verdict that is not only a warning."""
    return verdict.detected and verdict.reason_code not in WARNING_REASON_CODES


def is_warning(verdict: DetectionVerdict) -> bool:
    """A positive verdict that only warns (Decision 10)."""
    return verdict.detected and verdict.reason_code in WARNING_REASON_CODES


def _positive_with_reason(
    reason_codes: frozenset[str],
) -> Callable[[DetectionVerdict], bool]:
    def test(verdict: DetectionVerdict) -> bool:
        return verdict.detected and verdict.reason_code in reason_codes

    return test


def _group_by_cell(records: Iterable[RunRecord]) -> dict[_CellKey, list[RunRecord]]:
    by_cell: dict[_CellKey, list[RunRecord]] = defaultdict(list)
    run_ids: set[str] = set()

    for record in records:
        if record.run_id in run_ids:
            raise ValueError(f"Duplicate run_id: {record.run_id}")

        run_ids.add(record.run_id)
        key = (record.kind, record.cell_id, record.defense_mode, record.backend)
        by_cell[key].append(record)

    return dict(by_cell)


def _sort_key(key: _CellKey) -> tuple[int, str, int, str]:
    kind, cell_id, mode, backend = key
    return (
        0 if kind == CellKind.ATTACK else 1,
        cell_id,
        _MODE_ORDER[mode],
        backend.value,
    )


def _rate(runs: Sequence[RunRecord], predicate: Callable[[RunRecord], bool]) -> Rate:
    return Rate(count=sum(1 for run in runs if predicate(run)), total=len(runs))


def _summarize_cell(
    key: _CellKey,
    runs: Sequence[RunRecord],
    overhead: OverheadStats | None,
) -> CellSummary:
    kind, cell_id, mode, backend = key
    completed = [run for run in runs if run.completed]
    is_attack = kind == CellKind.ATTACK
    defended = mode != DefenseMode.NONE

    def attack_outcome_rate(outcome: AttackOutcome) -> Rate:
        return _rate(
            completed,
            lambda run: run.result.attack_result is not None
            and run.result.attack_result.outcome == outcome,
        )

    def detection_outcome_rate(outcome: DetectionOutcome) -> Rate:
        return _rate(completed, lambda run: run.result.detection_outcome == outcome)

    return CellSummary(
        kind=kind,
        cell_id=cell_id,
        defense_mode=mode,
        backend=backend,
        runs=len(runs),
        completed=len(completed),
        error_rate=_rate(
            runs, lambda run: run.result.execution_status == ExecutionStatus.ERROR
        ),
        inconclusive_rate=_rate(
            runs,
            lambda run: run.result.execution_status == ExecutionStatus.INCONCLUSIVE,
        ),
        attack_success_rate=(
            attack_outcome_rate(AttackOutcome.SUCCEEDED) if is_attack else None
        ),
        block_rate=attack_outcome_rate(AttackOutcome.BLOCKED) if is_attack else None,
        detection_rate=(
            detection_outcome_rate(DetectionOutcome.DETECTED)
            if is_attack and defended
            else None
        ),
        false_negative_rate=(
            detection_outcome_rate(DetectionOutcome.NOT_DETECTED)
            if is_attack and defended
            else None
        ),
        relative_asr_reduction=None,
        mitigation_false_positive_rate=(
            _rate(
                completed,
                lambda run: run.result.mitigation_outcome == MitigationOutcome.APPLIED,
            )
            if not is_attack and mode == DefenseMode.DETECT_AND_MITIGATE
            else None
        ),
        detectors=_detector_stats(completed),
        latency=_latency(completed),
        overhead=overhead,
    )


def _detector_stats(completed: Sequence[RunRecord]) -> tuple[DetectorStats, ...]:
    detector_ids = sorted(
        {
            verdict.detector_id
            for run in completed
            for verdict in run.result.detection_verdicts
        }
    )

    stats: list[DetectorStats] = []

    for detector_id in detector_ids:
        # This detector's verdicts, one list per completed run.
        per_run = [
            [
                verdict
                for verdict in run.result.detection_verdicts
                if verdict.detector_id == detector_id
            ]
            for run in completed
        ]

        groups = {
            name: _count_runs(per_run, _positive_with_reason(codes))
            for name, codes in REASON_GROUPS.get(detector_id, {}).items()
        }

        stats.append(
            DetectorStats(
                detector_id=detector_id,
                flagged=_count_runs(per_run, is_enforcing),
                warned=_count_runs(per_run, is_warning),
                groups=groups,
            )
        )

    return tuple(stats)


def _count_runs(
    per_run: Sequence[Sequence[DetectionVerdict]],
    test: Callable[[DetectionVerdict], bool],
) -> Rate:
    """Runs with at least one verdict that passes ``test``, out of all runs."""
    return Rate(
        count=sum(1 for verdicts in per_run if any(map(test, verdicts))),
        total=len(per_run),
    )


def _latency(completed: Sequence[RunRecord]) -> dict[str, LatencyStats]:
    """Latency per component; a run without a component value is skipped."""

    def components(result: RunResult) -> dict[str, float | None]:
        return {
            "total": result.total_latency_ms,
            "backend": result.backend_latency_ms,
            "detection": result.detection_latency_ms,
            "mitigation": result.mitigation_latency_ms,
        }

    per_run = [components(run.result) for run in completed]
    stats: dict[str, LatencyStats] = {}

    for component in LATENCY_COMPONENTS:
        found: list[float] = []

        for values in per_run:
            value = values[component]

            if value is not None:
                found.append(value)

        stats[component] = latency_stats(found)

    return stats


def _overhead(
    key: _CellKey,
    runs: Sequence[RunRecord],
    by_cell: dict[_CellKey, list[RunRecord]],
) -> OverheadStats | None:
    kind, cell_id, mode, backend = key

    if mode == DefenseMode.NONE:
        return None

    # The matching unsafe run has the same scenario, backend, seed, and
    # repetition (§6.5).
    baseline = {
        (run.scenario_id, run.seed, run.repetition): run.result.total_latency_ms
        for run in by_cell.get((kind, cell_id, DefenseMode.NONE, backend), [])
        if run.completed
    }

    differences: list[float] = []
    unpaired = 0

    for run in runs:
        if not run.completed:
            continue

        base = baseline.get((run.scenario_id, run.seed, run.repetition))

        if base is None:
            unpaired += 1
        else:
            differences.append(run.result.total_latency_ms - base)

    return OverheadStats(
        n_pairs=len(differences),
        n_unpaired=unpaired,
        median_ms=statistics.median(differences) if differences else None,
        min_ms=min(differences) if differences else None,
        max_ms=max(differences) if differences else None,
    )


def _with_relative_reduction(
    summary: CellSummary,
    summaries: dict[_CellKey, CellSummary],
) -> CellSummary:
    """(ASR_none - ASR_mode) / ASR_none; None when baseline ASR is zero (§6.4)."""
    if summary.kind != CellKind.ATTACK or summary.defense_mode == DefenseMode.NONE:
        return summary

    baseline = summaries.get(
        (summary.kind, summary.cell_id, DefenseMode.NONE, summary.backend)
    )

    if baseline is None or baseline.attack_success_rate is None:
        return summary

    asr_none = baseline.attack_success_rate.value
    asr_mode = (
        summary.attack_success_rate.value
        if summary.attack_success_rate is not None
        else None
    )

    if asr_none is None or asr_none == 0 or asr_mode is None:
        return summary

    return replace(summary, relative_asr_reduction=(asr_none - asr_mode) / asr_none)
