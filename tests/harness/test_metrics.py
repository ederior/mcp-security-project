import asyncio
import json
from collections.abc import Sequence
from pathlib import Path

import pytest

from contracts.results import (
    AttackOutcome,
    AttackResult,
    DetectionOutcome,
    DetectionVerdict,
    ExecutionStatus,
    MitigationOutcome,
    RunResult,
)
from contracts.scenario import Backend, DefenseMode
from harness.dispatch import fake_script_factory, run_one, with_defense_mode
from harness.metrics import (
    UNASSIGNED_SPLIT,
    CellKind,
    CellSummary,
    RunRecord,
    detector_confusion,
    latency_stats,
    load_run_record,
    summarize,
    verdict_counts,
)
from harness.scenario_loader import load_scenario

PI_DETECTOR = "prompt_injection_rules_v1"
SCANNER = "synthetic_secret_scanner_v1"
SIGNAL = "test_success_signal"


def verdict(detector_id: str, reason_code: str, detected: bool) -> DetectionVerdict:
    return DetectionVerdict(
        detector_id=detector_id,
        detector_version="v1",
        attack_family="test_family",
        scenario_id="test_scenario",
        detected=detected,
        reason_code=reason_code,
        confidence=1.0 if detected else 0.0,
        latency_ms=0.1,
    )


def record(
    run_id: str,
    *,
    attack_id: str | None = "AC-PI1a",
    mode: DefenseMode = DefenseMode.DETECT,
    outcome: AttackOutcome = AttackOutcome.SUCCEEDED,
    verdicts: Sequence[DetectionVerdict] = (),
    mitigation: MitigationOutcome | None = None,
    status: ExecutionStatus = ExecutionStatus.COMPLETED,
    total_ms: float = 10.0,
    seed: int = 0,
    corpus_split: str | None = None,
) -> RunRecord:
    """A hand-built run that satisfies every RunResult rule."""
    if status != ExecutionStatus.COMPLETED:
        result = RunResult(
            run_id=run_id,
            scenario_id="test_scenario",
            execution_status=status,
            total_latency_ms=total_ms,
            error_reason_code="unexpected_error",
        )
    else:
        if attack_id is None:
            attack_result = AttackResult(
                scenario_id="test_scenario", outcome=AttackOutcome.NOT_APPLICABLE
            )
        else:
            attack_result = AttackResult(
                scenario_id="test_scenario",
                attack_id=attack_id,
                expected_success_signal=SIGNAL,
                observed_signal_ids=(
                    [SIGNAL] if outcome == AttackOutcome.SUCCEEDED else []
                ),
                outcome=outcome,
            )

        defended = mode != DefenseMode.NONE

        if defended and not verdicts:
            # A defended run always has at least one verdict (RunResult rule).
            verdicts = [verdict(PI_DETECTOR, "followup_within_user_goal", False)]

        detection = (
            DetectionOutcome.NOT_APPLICABLE
            if not defended
            else (
                DetectionOutcome.DETECTED
                if any(v.detected for v in verdicts)
                else DetectionOutcome.NOT_DETECTED
            )
        )
        result = RunResult(
            run_id=run_id,
            scenario_id="test_scenario",
            execution_status=status,
            attack_result=attack_result,
            detection_outcome=detection,
            mitigation_outcome=mitigation
            or (
                MitigationOutcome.NOT_APPLIED
                if defended
                else MitigationOutcome.NOT_APPLICABLE
            ),
            detection_verdicts=list(verdicts),
            total_latency_ms=total_ms,
        )

    return RunRecord(
        run_id=run_id,
        scenario_id="test_scenario",
        attack_id=attack_id,
        defense_mode=mode,
        backend=Backend.FAKE,
        seed=seed,
        repetition=1,
        result=result,
        corpus_split=corpus_split,
    )


def cell(
    summaries: Sequence[CellSummary], cell_id: str, mode: DefenseMode
) -> CellSummary:
    (found,) = [s for s in summaries if s.cell_id == cell_id and s.defense_mode == mode]
    return found


def detector(summary: CellSummary, detector_id: str) -> object:
    (found,) = [d for d in summary.detectors if d.detector_id == detector_id]
    return found


# --- rates ------------------------------------------------------------------


def test_rates_use_completed_runs_and_reliability_uses_all_runs() -> None:
    summary = cell(
        summarize(
            [
                record("r1"),
                record("r2"),
                record("r3", outcome=AttackOutcome.NOT_TRIGGERED),
                record("r4", status=ExecutionStatus.ERROR),
                record("r5", status=ExecutionStatus.INCONCLUSIVE),
            ]
        ),
        "AC-PI1a",
        DefenseMode.DETECT,
    )

    assert (summary.runs, summary.completed) == (5, 3)
    assert summary.attack_success_rate is not None
    assert (summary.attack_success_rate.count, summary.attack_success_rate.total) == (
        2,
        3,
    )
    assert summary.block_rate is not None and summary.block_rate.value == 0.0
    assert summary.error_rate.value == pytest.approx(1 / 5)
    assert summary.inconclusive_rate.value == pytest.approx(1 / 5)


def test_detection_rates_are_not_applicable_without_defense() -> None:
    summary = cell(
        summarize([record("r1", mode=DefenseMode.NONE)]), "AC-PI1a", DefenseMode.NONE
    )

    assert summary.detection_rate is None
    assert summary.false_negative_rate is None
    assert summary.detectors == ()
    assert summary.overhead is None
    assert summary.relative_asr_reduction is None


def test_detection_rate_and_fnr_in_detect_mode() -> None:
    summary = cell(
        summarize(
            [
                record(
                    "r1",
                    verdicts=[verdict(PI_DETECTOR, "followup_outside_user_goal", True)],
                ),
                record(
                    "r2",
                    verdicts=[verdict(PI_DETECTOR, "followup_within_user_goal", False)],
                ),
            ]
        ),
        "AC-PI1a",
        DefenseMode.DETECT,
    )

    assert summary.detection_rate is not None and summary.detection_rate.value == 0.5
    assert summary.false_negative_rate is not None
    assert summary.false_negative_rate.value == 0.5


def test_warnings_are_not_detections_for_the_detector() -> None:
    summary = cell(
        summarize(
            [
                record(
                    "r1",
                    attack_id="AC-CL1a",
                    verdicts=[verdict(SCANNER, "registered_canary_detected", True)],
                ),
                record(
                    "r2",
                    attack_id="AC-CL1a",
                    verdicts=[
                        verdict(SCANNER, "synthetic_secret_pattern_detected", True)
                    ],
                ),
            ]
        ),
        "AC-CL1a",
        DefenseMode.DETECT,
    )

    (scanner,) = summary.detectors
    assert (scanner.flagged.count, scanner.warned.count) == (1, 1)
    # The run-level detection_outcome is unchanged by Decision 22, so the
    # warning-only run still counts there.
    assert summary.detection_rate is not None and summary.detection_rate.count == 2


def test_prompt_injection_detector_is_split_into_content_rules_and_policy() -> None:
    summary = cell(
        summarize(
            [
                record(
                    "r1",
                    verdicts=[
                        verdict(
                            PI_DETECTOR, "untrusted_content_contains_override", True
                        ),
                        verdict(PI_DETECTOR, "followup_outside_user_goal", True),
                    ],
                ),
                record(
                    "r2",
                    verdicts=[
                        verdict(PI_DETECTOR, "no_injection_indicators", False),
                        verdict(PI_DETECTOR, "followup_outside_user_goal", True),
                    ],
                ),
            ]
        ),
        "AC-PI1a",
        DefenseMode.DETECT,
    )

    (rules,) = summary.detectors
    assert rules.flagged.value == 1.0
    assert rules.groups["content_rules"].value == 0.5
    assert rules.groups["policy_check"].value == 1.0


def test_normal_use_cells_report_false_positives() -> None:
    flagged = [verdict(PI_DETECTOR, "followup_outside_user_goal", True)]
    clean = [verdict(PI_DETECTOR, "followup_within_user_goal", False)]
    summaries = summarize(
        [
            record(
                "b1",
                attack_id=None,
                mode=DefenseMode.DETECT_AND_MITIGATE,
                verdicts=flagged,
                mitigation=MitigationOutcome.APPLIED,
            ),
            record(
                "b2",
                attack_id=None,
                mode=DefenseMode.DETECT_AND_MITIGATE,
                verdicts=clean,
            ),
            record("b3", attack_id=None, mode=DefenseMode.DETECT, verdicts=flagged),
        ]
    )

    secure = cell(summaries, "test_scenario", DefenseMode.DETECT_AND_MITIGATE)
    assert secure.kind == CellKind.NORMAL_USE
    assert secure.attack_success_rate is None
    assert secure.block_rate is None
    assert secure.detection_rate is None
    assert secure.mitigation_false_positive_rate is not None
    assert secure.mitigation_false_positive_rate.value == 0.5
    (rules,) = secure.detectors
    assert rules.flagged.value == 0.5

    partial = cell(summaries, "test_scenario", DefenseMode.DETECT)
    assert partial.mitigation_false_positive_rate is None


def test_relative_asr_reduction() -> None:
    summaries = summarize(
        [
            *(record(f"n{i}", mode=DefenseMode.NONE, seed=i) for i in range(4)),
            *(record(f"d{i}", seed=i) for i in range(4)),
            record("s0", mode=DefenseMode.DETECT_AND_MITIGATE, seed=0),
            *(
                record(
                    f"s{i}",
                    mode=DefenseMode.DETECT_AND_MITIGATE,
                    outcome=AttackOutcome.BLOCKED,
                    seed=i,
                )
                for i in range(1, 4)
            ),
        ]
    )

    assert cell(summaries, "AC-PI1a", DefenseMode.NONE).relative_asr_reduction is None
    assert cell(summaries, "AC-PI1a", DefenseMode.DETECT).relative_asr_reduction == 0.0
    assert cell(
        summaries, "AC-PI1a", DefenseMode.DETECT_AND_MITIGATE
    ).relative_asr_reduction == pytest.approx(0.75)


def test_relative_asr_reduction_is_not_applicable_at_zero_baseline() -> None:
    summaries = summarize(
        [
            record("n0", mode=DefenseMode.NONE, outcome=AttackOutcome.NOT_TRIGGERED),
            record("d0", outcome=AttackOutcome.NOT_TRIGGERED),
        ]
    )

    assert cell(summaries, "AC-PI1a", DefenseMode.DETECT).relative_asr_reduction is None


# --- latency ----------------------------------------------------------------


def test_latency_stats_gate_p95_at_twenty_samples() -> None:
    small = latency_stats([3.0, 1.0, 2.0])
    assert (small.n, small.median_ms, small.min_ms, small.max_ms) == (3, 2.0, 1.0, 3.0)
    assert small.p95_ms is None

    large = latency_stats([float(value) for value in range(1, 21)])
    assert large.p95_ms == pytest.approx(19.05)

    empty = latency_stats([])
    assert (empty.n, empty.median_ms, empty.p95_ms) == (0, None, None)


def test_latency_skips_runs_without_a_component() -> None:
    summary = cell(
        summarize([record("r1", mode=DefenseMode.NONE, total_ms=5.0)]),
        "AC-PI1a",
        DefenseMode.NONE,
    )

    assert summary.latency["total"].median_ms == 5.0
    assert summary.latency["detection"].n == 0


def test_overhead_pairs_runs_by_scenario_backend_seed_and_repetition() -> None:
    summaries = summarize(
        [
            record("n0", mode=DefenseMode.NONE, seed=0, total_ms=10.0),
            record("n1", mode=DefenseMode.NONE, seed=1, total_ms=20.0),
            record("n2", mode=DefenseMode.NONE, seed=2, status=ExecutionStatus.ERROR),
            record("d0", seed=0, total_ms=13.0),
            record("d1", seed=1, total_ms=25.0),
            record("d2", seed=2, total_ms=40.0),
        ]
    )

    overhead = cell(summaries, "AC-PI1a", DefenseMode.DETECT).overhead
    assert overhead is not None
    # Seed 2 has no completed unsafe run, so it cannot be paired.
    assert (overhead.n_pairs, overhead.n_unpaired) == (2, 1)
    assert (overhead.median_ms, overhead.min_ms, overhead.max_ms) == (4.0, 3.0, 5.0)


# --- structure --------------------------------------------------------------


def test_duplicate_run_ids_are_rejected() -> None:
    with pytest.raises(ValueError, match="Duplicate run_id"):
        summarize([record("same"), record("same")])


def test_cells_are_sorted_attacks_first_then_by_id_and_mode() -> None:
    summaries = summarize(
        [
            record("b1", attack_id=None, mode=DefenseMode.NONE),
            record("p2", attack_id="AC-PI2a", mode=DefenseMode.DETECT_AND_MITIGATE),
            record("p1", attack_id="AC-PI1a", mode=DefenseMode.DETECT),
            record("p0", attack_id="AC-PI1a", mode=DefenseMode.NONE),
        ]
    )

    assert [(s.cell_id, s.defense_mode) for s in summaries] == [
        ("AC-PI1a", DefenseMode.NONE),
        ("AC-PI1a", DefenseMode.DETECT),
        ("AC-PI2a", DefenseMode.DETECT_AND_MITIGATE),
        ("test_scenario", DefenseMode.NONE),
    ]


def test_verdict_counts_count_runs_not_verdicts() -> None:
    rows = verdict_counts(
        [
            record(
                "r1",
                attack_id="AC-CL1a",
                verdicts=[
                    verdict(SCANNER, "synthetic_secret_pattern_detected", True),
                    verdict(SCANNER, "synthetic_secret_pattern_detected", True),
                ],
            ),
            record(
                "r2",
                attack_id="AC-CL1a",
                verdicts=[verdict(SCANNER, "no_synthetic_secret", False)],
            ),
        ]
    )

    assert [
        (r.reason_code, r.runs_with_reason, r.completed_runs, r.warning) for r in rows
    ] == [
        ("no_synthetic_secret", 1, 2, False),
        ("synthetic_secret_pattern_detected", 1, 2, True),
    ]


# --- detector confusion matrix (Decision 23) --------------------------------


# Each detector's target attacks, as in experiments/matrix_fake.yaml.
TARGETS = {
    PI_DETECTOR: ["AC-PI1a", "AC-PI2a", "AC-CL2a"],
    SCANNER: ["AC-CL1a"],
    "session_binding_validator_v1": ["AC-SH1a"],
    "replay_validator_v1": ["AC-SH3a"],
}


def flagged(detected: bool = True) -> list[DetectionVerdict]:
    reason = "followup_outside_user_goal" if detected else "followup_within_user_goal"
    return [verdict(PI_DETECTOR, reason, detected)]


def test_confusion_counts_attacks_against_each_normal_use_split() -> None:
    rows = detector_confusion(
        [
            record("a1", verdicts=flagged()),
            record("a2", verdicts=flagged(False)),
            *(
                record(
                    run_id,
                    attack_id=None,
                    verdicts=flagged(detected),
                    corpus_split=split,
                )
                for run_id, detected, split in [
                    ("d1", True, "development"),
                    ("d2", False, "development"),
                    ("d3", False, "development"),
                    ("h1", False, "final_holdout"),
                ]
            ),
        ],
        TARGETS,
    )

    assert [
        (
            r.normal_use_split,
            r.true_positives,
            r.false_negatives,
            r.false_positives,
            r.true_negatives,
        )
        for r in rows
    ] == [("development", 1, 1, 1, 2), ("final_holdout", 1, 1, 0, 1)]
    development, _ = rows
    assert development.true_positive_rate.value == 0.5
    assert development.false_positive_rate.value == pytest.approx(1 / 3)


def test_confusion_counts_warnings_apart_from_false_positives() -> None:
    (row,) = detector_confusion(
        [
            record(
                "a1",
                attack_id="AC-CL1a",
                verdicts=[verdict(SCANNER, "registered_canary_detected", True)],
            ),
            record(
                "b1",
                attack_id=None,
                corpus_split="development",
                verdicts=[verdict(SCANNER, "synthetic_secret_pattern_detected", True)],
            ),
        ],
        TARGETS,
    )

    assert (row.true_positives, row.false_positives, row.true_negatives) == (1, 0, 1)
    assert row.normal_use_warnings == 1


def test_confusion_without_normal_use_runs_has_no_split() -> None:
    (row,) = detector_confusion([record("a1", verdicts=flagged())], TARGETS)

    assert row.normal_use_split is None
    assert row.false_positive_rate.total == 0
    assert row.false_positive_rate.value is None


def test_confusion_counts_only_completed_runs_the_detector_judged() -> None:
    rows = detector_confusion(
        [
            record("a1", verdicts=flagged()),
            # Not judged: no defense, failed, or another detector only.
            record("a2", mode=DefenseMode.NONE),
            record("a3", status=ExecutionStatus.ERROR),
            record(
                "a4",
                attack_id="AC-CL1a",
                verdicts=[verdict(SCANNER, "no_synthetic_secret", False)],
            ),
        ],
        TARGETS,
    )

    pi_row = next(r for r in rows if r.detector_id == PI_DETECTOR)
    assert (pi_row.true_positives, pi_row.false_negatives) == (1, 0)
    assert {r.detector_id for r in rows} == {PI_DETECTOR, SCANNER}


def test_normal_use_runs_without_a_split_are_unassigned() -> None:
    (row,) = detector_confusion(
        [record("b1", attack_id=None, verdicts=flagged(False))], TARGETS
    )

    assert row.normal_use_split == UNASSIGNED_SPLIT


def test_only_target_attacks_are_positives() -> None:
    # Both session validators judge both session attacks. Each correct "no"
    # on the attack it does not target must not count as a miss.
    binding = "session_binding_validator_v1"
    replay = "replay_validator_v1"
    rows = detector_confusion(
        [
            record(
                "sh1a",
                attack_id="AC-SH1a",
                verdicts=[
                    verdict(binding, "session_user_mismatch", True),
                    verdict(replay, "nonce_not_seen", False),
                ],
            ),
            record(
                "sh3a",
                attack_id="AC-SH3a",
                verdicts=[
                    verdict(binding, "session_user_matches", False),
                    verdict(replay, "duplicate_nonce", True),
                ],
            ),
        ],
        TARGETS,
    )

    by_detector = {row.detector_id: row for row in rows}
    for detector_id, target in ((binding, "AC-SH1a"), (replay, "AC-SH3a")):
        row = by_detector[detector_id]
        assert (row.true_positives, row.false_negatives) == (1, 0)
        assert row.target_attack_ids == (target,)


def test_a_detector_without_targets_is_rejected() -> None:
    with pytest.raises(ValueError, match="No target attacks"):
        detector_confusion([record("a1", verdicts=flagged())], {SCANNER: ["AC-CL1a"]})


def test_confusion_rejects_duplicate_run_ids() -> None:
    with pytest.raises(ValueError, match="Duplicate run_id"):
        detector_confusion([record("same"), record("same")], TARGETS)


# --- reading real runs ------------------------------------------------------

ATTACK_DIR = Path("scenarios/attacks")
FAKE_SCRIPTS = fake_script_factory(Path("experiments/fake_scripts"))
PI_CONTROLS = ["prompt_injection_rules_v1", "tool_authorization_policy_v1"]
SESSION_CONTROLS = ["session_binding_validator_v1", "replay_validator_v1"]
SECRET_CONTROLS = ["synthetic_secret_scanner_v1", "synthetic_secret_redactor_v1"]

# Same mapping as tests/harness/test_dispatch.py; the batch command will read
# it from experiments/matrix_fake.yaml.
ATTACKS: dict[str, tuple[str, list[str]]] = {
    "AC-PI1a": ("ac_pi1a.yaml", PI_CONTROLS),
    "AC-PI2a": ("ac_pi2a.yaml", PI_CONTROLS),
    "AC-SH1a": ("ac_sh1a.yaml", SESSION_CONTROLS),
    "AC-SH3a": ("ac_sh3a.yaml", SESSION_CONTROLS),
    "AC-CL1a": ("ac_cl1a.yaml", SECRET_CONTROLS),
    "AC-CL2a": ("ac_cl2a.yaml", PI_CONTROLS),
}


def write_matrix(tmp_path: Path) -> list[RunRecord]:
    """Run the 18 attack cells into tmp_path and read them back."""
    records: list[RunRecord] = []

    for file_name, controls in ATTACKS.values():
        base = load_scenario(ATTACK_DIR / file_name)

        for mode in DefenseMode:
            scenario = with_defense_mode(base, mode, controls)
            run_id = f"{scenario.scenario_id}__{mode.value}"
            asyncio.run(
                run_one(
                    scenario,
                    run_id=run_id,
                    backend_factory=FAKE_SCRIPTS,
                    artifact_dir=tmp_path,
                    git_sha="test_sha",
                )
            )
            records.append(load_run_record(tmp_path / run_id))

    return records


def test_the_eighteen_fake_cells_summarize_as_decided(tmp_path: Path) -> None:
    summaries = summarize(write_matrix(tmp_path))

    assert len(summaries) == 18

    for attack_id in ATTACKS:
        unsafe = cell(summaries, attack_id, DefenseMode.NONE)
        partial = cell(summaries, attack_id, DefenseMode.DETECT)
        secure = cell(summaries, attack_id, DefenseMode.DETECT_AND_MITIGATE)

        assert unsafe.attack_success_rate is not None
        assert unsafe.attack_success_rate.value == 1.0
        assert partial.detection_rate is not None
        assert partial.detection_rate.value == 1.0
        assert partial.relative_asr_reduction == 0.0
        assert secure.block_rate is not None and secure.block_rate.value == 1.0
        assert secure.relative_asr_reduction == 1.0
        assert secure.overhead is not None and secure.overhead.n_pairs == 1
        assert all(s.error_rate.value == 0.0 for s in (unsafe, partial, secure))

    # PI2a has no tool result to inspect: only the policy check fires, which
    # is why the content-rule group is reported on its own.
    (pi2a_rules,) = cell(summaries, "AC-PI2a", DefenseMode.DETECT).detectors
    assert pi2a_rules.groups["content_rules"].value == 0.0
    assert pi2a_rules.groups["policy_check"].value == 1.0

    (pi1a_rules,) = cell(summaries, "AC-PI1a", DefenseMode.DETECT).detectors
    assert pi1a_rules.groups["content_rules"].value == 1.0


def test_load_run_record_rejects_mismatched_files(tmp_path: Path) -> None:
    scenario = with_defense_mode(
        load_scenario(ATTACK_DIR / "ac_pi1a.yaml"), DefenseMode.DETECT, PI_CONTROLS
    )
    asyncio.run(
        run_one(
            scenario,
            run_id="pi1a_mismatch",
            backend_factory=FAKE_SCRIPTS,
            artifact_dir=tmp_path,
            git_sha="test_sha",
        )
    )
    config_path = tmp_path / "pi1a_mismatch" / "config.json"
    config = json.loads(config_path.read_text(encoding="utf-8"))
    config["run_id"] = "another_run"
    config_path.write_text(json.dumps(config), encoding="utf-8")

    with pytest.raises(ValueError, match="disagree"):
        load_run_record(tmp_path / "pi1a_mismatch")
