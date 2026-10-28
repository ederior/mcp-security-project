from pathlib import Path
from typing import Any

import pytest
import yaml

from contracts.results import (
    AttackOutcome,
    AttackResult,
    DetectionOutcome,
    ExecutionStatus,
    MitigationOutcome,
    RunResult,
)
from contracts.scenario import Backend, DefenseMode
from harness.experiment import (
    Matrix,
    load_matrix,
    plan_runs,
    summary_row,
    to_jsonable,
)
from harness.metrics import Rate, RunRecord, summarize

MATRIX_FILE = Path("experiments/matrix_fake.yaml")

PI_CONTROLS = ["prompt_injection_rules_v1", "tool_authorization_policy_v1"]
SESSION_CONTROLS = ["session_binding_validator_v1", "replay_validator_v1"]
SECRET_CONTROLS = ["synthetic_secret_scanner_v1", "synthetic_secret_redactor_v1"]

# The controls of each attack, as Decision 22 lists them.
DECIDED_CONTROLS = {
    "AC-PI1a": PI_CONTROLS,
    "AC-PI2a": PI_CONTROLS,
    "AC-SH1a": SESSION_CONTROLS,
    "AC-SH3a": SESSION_CONTROLS,
    "AC-CL1a": SECRET_CONTROLS,
    "AC-CL2a": PI_CONTROLS,
}


def raw_matrix() -> dict[str, Any]:
    raw = yaml.safe_load(MATRIX_FILE.read_text(encoding="utf-8"))
    assert isinstance(raw, dict)
    return raw


def decided_controls(scenario_id: str, attack_id: str | None) -> list[str]:
    """Decision 22 for attacks; Decision 23 for the normal-use corpus."""
    if attack_id is not None:
        return DECIDED_CONTROLS[attack_id]

    if scenario_id == "secret_benign_dev_authorized_sink_public_text":
        return PI_CONTROLS  # the AC-CL2a controls

    prefixes = {"pi_": PI_CONTROLS, "session_": SESSION_CONTROLS}
    prefixes["secret_"] = SECRET_CONTROLS
    (controls,) = [c for p, c in prefixes.items() if scenario_id.startswith(p)]
    return controls


def test_fake_matrix_plans_attacks_and_the_development_corpus() -> None:
    planned = plan_runs(load_matrix(MATRIX_FILE))

    # 6 attacks and 16 normal-use cases, each in 3 modes.
    assert len(planned) == 66
    assert len({run.run_id for run in planned}) == 66
    assert sum(run.scenario.attack_id is not None for run in planned) == 18

    for run in planned:
        scenario = run.scenario
        assert run.run_id == (
            f"{scenario.scenario_id}__{scenario.defense_mode.value}__seed0__rep1"
        )
        assert scenario.enabled_controls == (
            []
            if scenario.defense_mode == DefenseMode.NONE
            else decided_controls(scenario.scenario_id, scenario.attack_id)
        )


def test_seeds_and_repetitions_expand_in_a_fixed_order() -> None:
    raw = raw_matrix()
    raw["scenarios"] = raw["scenarios"][:1]
    raw["detector_targets"] = {"prompt_injection_rules_v1": ["AC-PI1a"]}
    raw["seeds"] = [0, 1]
    raw["repetitions"] = 2

    run_ids = [run.run_id for run in plan_runs(Matrix.model_validate(raw))]

    assert len(run_ids) == 12
    assert run_ids[:4] == [
        "ac_pi1a_baseline__none__seed0__rep1",
        "ac_pi1a_baseline__detect__seed0__rep1",
        "ac_pi1a_baseline__detect_and_mitigate__seed0__rep1",
        "ac_pi1a_baseline__none__seed0__rep2",
    ]


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"control_sets": {"session": SESSION_CONTROLS}}, "Unknown control sets"),
        ({"defense_modes": ["none", "none"]}, "must not repeat"),
        ({"seeds": [-1]}, "non-negative"),
        ({"backend": "gemini"}, "not available yet"),
        ({"fake_script_dir": None}, "needs fake_script_dir"),
        (
            {"control_sets": {"prompt_injection": [], "session": [], "secret": []}},
            "at least one control",
        ),
        ({"unknown_field": 1}, "Extra inputs"),
    ],
)
def test_invalid_matrices_are_rejected(change: dict[str, Any], message: str) -> None:
    raw = raw_matrix() | change

    with pytest.raises(ValueError, match=message):
        Matrix.model_validate(raw)


@pytest.mark.parametrize(
    ("targets", "message"),
    [
        (
            {"prompt_injection_rule_v1": ["AC-PI1a"]},
            "Unknown detectors in detector_targets",
        ),
        ({"prompt_injection_rules_v1": []}, "at least one target attack"),
    ],
)
def test_invalid_detector_targets_are_rejected(
    targets: dict[str, list[str]], message: str
) -> None:
    raw = raw_matrix()
    raw["detector_targets"] = {**raw["detector_targets"], **targets}

    with pytest.raises(ValueError, match=message):
        Matrix.model_validate(raw)


def test_a_used_detector_needs_targets() -> None:
    raw = raw_matrix()
    del raw["detector_targets"]["replay_validator_v1"]

    with pytest.raises(
        ValueError, match="without detector_targets: replay_validator_v1"
    ):
        Matrix.model_validate(raw)


def test_targets_must_be_attacks_in_the_matrix() -> None:
    raw = raw_matrix()
    raw["detector_targets"]["replay_validator_v1"] = ["AC-SH3a", "AC-SH9z"]

    with pytest.raises(ValueError, match="not in the matrix: AC-SH9z"):
        plan_runs(Matrix.model_validate(raw))


def test_duplicate_scenario_files_are_rejected() -> None:
    raw = raw_matrix()
    raw["scenarios"] = raw["scenarios"] + raw["scenarios"][:1]

    with pytest.raises(ValueError, match="listed twice"):
        Matrix.model_validate(raw)


def test_scenario_files_must_keep_defense_mode_none(tmp_path: Path) -> None:
    scenario = yaml.safe_load(
        Path("scenarios/attacks/ac_pi1a.yaml").read_text(encoding="utf-8")
    )
    scenario["defense_mode"] = "detect"
    scenario["enabled_controls"] = PI_CONTROLS
    scenario_file = tmp_path / "defended.yaml"
    scenario_file.write_text(yaml.safe_dump(scenario), encoding="utf-8")

    raw = raw_matrix()
    raw["scenarios"] = [{"file": str(scenario_file), "control_set": "prompt_injection"}]

    with pytest.raises(ValueError, match="defense_mode: none"):
        plan_runs(Matrix.model_validate(raw))


def test_two_files_with_one_scenario_id_are_rejected(tmp_path: Path) -> None:
    copy = tmp_path / "copy_of_pi1a.yaml"
    copy.write_text(
        Path("scenarios/attacks/ac_pi1a.yaml").read_text(encoding="utf-8"),
        encoding="utf-8",
    )

    raw = raw_matrix()
    raw["scenarios"] = [
        {"file": "scenarios/attacks/ac_pi1a.yaml", "control_set": "prompt_injection"},
        {"file": str(copy), "control_set": "prompt_injection"},
    ]

    with pytest.raises(ValueError, match="share a scenario_id"):
        plan_runs(Matrix.model_validate(raw))


def test_missing_matrix_file_is_reported(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        load_matrix(tmp_path / "missing.yaml")


def test_to_jsonable_keeps_rate_values_and_enum_names() -> None:
    assert to_jsonable(Rate(count=1, total=4)) == {
        "count": 1,
        "total": 4,
        "value": 0.25,
    }
    assert to_jsonable(Rate(count=0, total=0))["value"] is None
    assert to_jsonable({"mode": DefenseMode.DETECT}) == {"mode": "detect"}


def test_summary_row_leaves_non_applicable_metrics_empty() -> None:
    result = RunResult(
        run_id="r1",
        scenario_id="s",
        execution_status=ExecutionStatus.COMPLETED,
        attack_result=AttackResult(
            scenario_id="s",
            attack_id="AC-PI1a",
            expected_success_signal="signal",
            observed_signal_ids=["signal"],
            outcome=AttackOutcome.SUCCEEDED,
        ),
        detection_outcome=DetectionOutcome.NOT_APPLICABLE,
        mitigation_outcome=MitigationOutcome.NOT_APPLICABLE,
        total_latency_ms=1.0,
    )
    unsafe_run = RunRecord(
        run_id="r1",
        scenario_id="s",
        attack_id="AC-PI1a",
        defense_mode=DefenseMode.NONE,
        backend=Backend.FAKE,
        seed=0,
        repetition=1,
        result=result,
    )

    # Detection metrics and overhead do not apply in mode none.
    (summary,) = summarize([unsafe_run])
    row = summary_row(summary)

    assert row["attack_success_rate"] == 1.0
    assert row["detection_rate"] is None
    assert row["overhead_pairs"] is None
