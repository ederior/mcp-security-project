import asyncio
import json
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from contracts.events import EventType, ToolEvent
from contracts.results import (
    AttackOutcome,
    DetectionOutcome,
    ExecutionStatus,
    MitigationOutcome,
)
from contracts.scenario import DefenseMode, Scenario
from harness.dispatch import (
    BackendFactory,
    classify_failure,
    fake_script_factory,
    run_one,
    with_defense_mode,
)
from harness.runner import HarnessRun, ToolRoundLimitExceeded
from harness.scenario_loader import load_scenario
from llm_backend.base import (
    BackendResponse,
    BackendUnavailable,
    LLMBackend,
    ToolCall,
    ToolResult,
)
from llm_backend.fake import CANARY_PLACEHOLDER, FakeBackend, FakeScriptError

ATTACK_DIR = Path("scenarios/attacks")
SMOKE_SCENARIO = Path("scenarios/benign/smoke.yaml")
FAKE_SCRIPTS = fake_script_factory(Path("experiments/fake_scripts"))
STARTED_AT = datetime(2026, 10, 28, 15, 30, 0, tzinfo=UTC)
RUN_FILES = ["config.json", "environment.json", "events.jsonl", "result.json"]

PI_CONTROLS = ["prompt_injection_rules_v1", "tool_authorization_policy_v1"]
SESSION_CONTROLS = ["session_binding_validator_v1", "replay_validator_v1"]
SECRET_CONTROLS = ["synthetic_secret_scanner_v1", "synthetic_secret_redactor_v1"]

# Attack file and family controls, as Decision 22 lists them. The batch
# command reads the same mapping from experiments/matrix_fake.yaml.
ATTACKS: dict[str, tuple[str, list[str]]] = {
    "AC-PI1a": ("ac_pi1a.yaml", PI_CONTROLS),
    "AC-PI2a": ("ac_pi2a.yaml", PI_CONTROLS),
    "AC-SH1a": ("ac_sh1a.yaml", SESSION_CONTROLS),
    "AC-SH3a": ("ac_sh3a.yaml", SESSION_CONTROLS),
    "AC-CL1a": ("ac_cl1a.yaml", SECRET_CONTROLS),
    "AC-CL2a": ("ac_cl2a.yaml", PI_CONTROLS),
}

# The outcome triple every attack must give in each mode (Decisions 16-21).
EXPECTED: dict[
    DefenseMode, tuple[AttackOutcome, DetectionOutcome, MitigationOutcome]
] = {
    DefenseMode.NONE: (
        AttackOutcome.SUCCEEDED,
        DetectionOutcome.NOT_APPLICABLE,
        MitigationOutcome.NOT_APPLICABLE,
    ),
    DefenseMode.DETECT: (
        AttackOutcome.SUCCEEDED,
        DetectionOutcome.DETECTED,
        MitigationOutcome.NOT_APPLIED,
    ),
    DefenseMode.DETECT_AND_MITIGATE: (
        AttackOutcome.BLOCKED,
        DetectionOutcome.DETECTED,
        MitigationOutcome.APPLIED,
    ),
}


def attack_in_mode(attack_id: str, mode: DefenseMode) -> Scenario:
    file_name, controls = ATTACKS[attack_id]
    return with_defense_mode(load_scenario(ATTACK_DIR / file_name), mode, controls)


def execute(
    scenario: Scenario,
    run_id: str,
    tmp_path: Path,
    backend_factory: BackendFactory = FAKE_SCRIPTS,
) -> HarnessRun:
    return asyncio.run(
        run_one(
            scenario,
            run_id=run_id,
            backend_factory=backend_factory,
            artifact_dir=tmp_path,
            git_sha="test_sha",
            started_at=STARTED_AT,
        )
    )


def read_events(run_dir: Path) -> list[ToolEvent]:
    lines = (run_dir / "events.jsonl").read_text(encoding="utf-8").splitlines()
    return [ToolEvent.model_validate_json(line) for line in lines]


def read_json(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def all_artifact_text(run_dir: Path) -> str:
    return "\n".join(path.read_text(encoding="utf-8") for path in run_dir.iterdir())


def fixed_backend(backend: LLMBackend) -> BackendFactory:
    def factory(scenario: Scenario) -> tuple[LLMBackend, str | None]:
        return backend, None

    return factory


# --- the 18 attack cells ----------------------------------------------------


@pytest.mark.parametrize("mode", list(EXPECTED), ids=lambda mode: mode.value)
@pytest.mark.parametrize("attack_id", list(ATTACKS))
def test_every_attack_gives_its_decided_outcome_in_every_mode(
    attack_id: str, mode: DefenseMode, tmp_path: Path
) -> None:
    scenario = attack_in_mode(attack_id, mode)
    run_id = f"{scenario.scenario_id}__{mode.value}"

    harness_run = execute(scenario, run_id, tmp_path)
    result = harness_run.result

    assert result.execution_status == ExecutionStatus.COMPLETED
    assert result.attack_result is not None
    assert (
        result.attack_result.outcome,
        result.detection_outcome,
        result.mitigation_outcome,
    ) == EXPECTED[mode]

    run_dir = tmp_path / run_id
    assert sorted(path.name for path in run_dir.iterdir()) == RUN_FILES

    events = read_events(run_dir)
    assert events[0].event_type == EventType.RUN_STARTED
    assert events[-1].event_type == EventType.RUN_COMPLETED
    assert [event.event_index for event in events] == list(range(len(events)))

    config = read_json(run_dir / "config.json")
    assert config["attack_id"] == attack_id
    assert config["defense_mode"] == mode.value
    assert config["enabled_controls"] == (
        [] if mode == DefenseMode.NONE else ATTACKS[attack_id][1]
    )
    # Self-writing CL runs get the script and start time added afterwards.
    assert config["fake_script_id"] == (
        None if attack_id in {"AC-SH1a", "AC-SH3a"} else scenario.scenario_id
    )
    environment = read_json(run_dir / "environment.json")
    assert environment["started_at_utc"] == "2026-10-28T15:30:00Z"

    assert "FAKE_SECRET_" not in all_artifact_text(run_dir)


# --- runs that do not complete ----------------------------------------------


class UnavailableBackend(LLMBackend):
    async def begin(self, prompt: str, *, seed: int) -> BackendResponse:
        raise BackendUnavailable("simulated HTTP 503")

    async def continue_after_tools(
        self, tool_results: Sequence[ToolResult]
    ) -> BackendResponse:
        raise AssertionError("not reached")


def looping_backend() -> FakeBackend:
    health_check = BackendResponse(tool_calls=(ToolCall(name="health_check"),))
    return FakeBackend((*([health_check] * 9), BackendResponse(final_text="Done")))


def assert_failed_run(
    harness_run: HarnessRun,
    run_dir: Path,
    status: ExecutionStatus,
    reason_code: str,
) -> None:
    result = harness_run.result
    assert result.execution_status == status
    assert result.error_reason_code == reason_code
    assert result.attack_result is None

    assert sorted(path.name for path in run_dir.iterdir()) == RUN_FILES
    # run_completed cannot carry a failed run (Decision 22, scope limits).
    assert [event.event_type for event in read_events(run_dir)] == [
        EventType.RUN_STARTED
    ]


def test_tool_round_limit_is_an_error_run(tmp_path: Path) -> None:
    scenario = load_scenario(SMOKE_SCENARIO)

    harness_run = execute(
        scenario, "smoke_loop", tmp_path, fixed_backend(looping_backend())
    )

    run_dir = tmp_path / "smoke_loop"
    assert_failed_run(
        harness_run, run_dir, ExecutionStatus.ERROR, "tool_round_limit_exceeded"
    )
    assert "Maximum number" not in all_artifact_text(run_dir)


def test_backend_unavailable_is_an_inconclusive_run(tmp_path: Path) -> None:
    harness_run = execute(
        load_scenario(SMOKE_SCENARIO),
        "smoke_unavailable",
        tmp_path,
        fixed_backend(UnavailableBackend()),
    )

    assert_failed_run(
        harness_run,
        tmp_path / "smoke_unavailable",
        ExecutionStatus.INCONCLUSIVE,
        "backend_unavailable",
    )


def test_unplayable_fake_script_is_a_configuration_error(tmp_path: Path) -> None:
    # The script copies a canary before any tool result was received.
    backend = FakeBackend((BackendResponse(final_text=CANARY_PLACEHOLDER),))

    harness_run = execute(
        load_scenario(SMOKE_SCENARIO),
        "smoke_bad_script",
        tmp_path,
        fixed_backend(backend),
    )

    assert_failed_run(
        harness_run,
        tmp_path / "smoke_bad_script",
        ExecutionStatus.ERROR,
        "configuration_error",
    )


def test_missing_fake_script_is_a_configuration_error(tmp_path: Path) -> None:
    # The smoke scenario has no script in experiments/fake_scripts.
    harness_run = execute(load_scenario(SMOKE_SCENARIO), "smoke_no_script", tmp_path)

    assert harness_run.result.execution_status == ExecutionStatus.ERROR
    assert harness_run.result.error_reason_code == "configuration_error"


def test_unknown_attack_is_a_configuration_error(tmp_path: Path) -> None:
    scenario = load_scenario(ATTACK_DIR / "ac_pi1a.yaml").model_copy(
        update={"attack_id": "AC-XX9a"}
    )

    harness_run = execute(
        scenario, "unknown_attack", tmp_path, fixed_backend(looping_backend())
    )

    assert harness_run.result.error_reason_code == "configuration_error"


def test_unexpected_failure_text_is_never_stored_or_printed(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    def broken_factory(scenario: Scenario) -> tuple[LLMBackend, str | None]:
        raise RuntimeError("boom with sensitive detail")

    harness_run = execute(
        load_scenario(SMOKE_SCENARIO), "smoke_boom", tmp_path, broken_factory
    )

    run_dir = tmp_path / "smoke_boom"
    assert_failed_run(harness_run, run_dir, ExecutionStatus.ERROR, "unexpected_error")
    assert "sensitive detail" not in all_artifact_text(run_dir)

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""


# --- run_one setup rules ----------------------------------------------------


def test_protocol_attacks_never_ask_for_a_backend(tmp_path: Path) -> None:
    def no_backend(scenario: Scenario) -> tuple[LLMBackend, str | None]:
        raise AssertionError("SH attacks must not create a backend")

    for attack_id in ("AC-SH1a", "AC-SH3a"):
        scenario = attack_in_mode(attack_id, DefenseMode.NONE)
        harness_run = execute(scenario, attack_id, tmp_path, no_backend)

        assert harness_run.result.execution_status == ExecutionStatus.COMPLETED


def test_existing_run_directory_stops_before_running(tmp_path: Path) -> None:
    (tmp_path / "taken").mkdir()

    with pytest.raises(FileExistsError):
        execute(load_scenario(SMOKE_SCENARIO), "taken", tmp_path)


def test_git_sha_is_required_with_an_artifact_dir(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="git_sha"):
        asyncio.run(
            run_one(
                load_scenario(SMOKE_SCENARIO),
                run_id="smoke_no_sha",
                backend_factory=FAKE_SCRIPTS,
                artifact_dir=tmp_path,
            )
        )


def test_run_without_artifact_dir_writes_nothing(tmp_path: Path) -> None:
    scenario = attack_in_mode("AC-PI1a", DefenseMode.DETECT)

    harness_run = asyncio.run(
        run_one(scenario, run_id="pi1a_memory_only", backend_factory=FAKE_SCRIPTS)
    )

    assert harness_run.result.execution_status == ExecutionStatus.COMPLETED
    assert list(tmp_path.iterdir()) == []


# --- helpers ----------------------------------------------------------------


def test_with_defense_mode_sets_controls_and_keeps_the_original() -> None:
    original = load_scenario(ATTACK_DIR / "ac_pi1a.yaml")

    defended = with_defense_mode(
        original, DefenseMode.DETECT, PI_CONTROLS, seed=3, repetition=2
    )
    undefended = with_defense_mode(defended, DefenseMode.NONE, PI_CONTROLS)

    assert defended.enabled_controls == PI_CONTROLS
    assert (defended.seed, defended.repetition) == (3, 2)
    assert undefended.enabled_controls == []
    assert original.defense_mode == DefenseMode.NONE


def test_with_defense_mode_validates_the_copy() -> None:
    original = load_scenario(ATTACK_DIR / "ac_pi1a.yaml")

    # A defended mode without controls breaks a Scenario rule.
    with pytest.raises(ValidationError, match="enabled_controls"):
        with_defense_mode(original, DefenseMode.DETECT, [])


@pytest.mark.parametrize(
    ("error", "status", "reason_code"),
    [
        (BackendUnavailable(), ExecutionStatus.INCONCLUSIVE, "backend_unavailable"),
        (ToolRoundLimitExceeded(), ExecutionStatus.ERROR, "tool_round_limit_exceeded"),
        (FakeScriptError(), ExecutionStatus.ERROR, "configuration_error"),
        (ValueError(), ExecutionStatus.ERROR, "configuration_error"),
        (TypeError(), ExecutionStatus.ERROR, "configuration_error"),
        (RuntimeError(), ExecutionStatus.ERROR, "unexpected_error"),
        (KeyError(), ExecutionStatus.ERROR, "unexpected_error"),
    ],
    ids=lambda value: type(value).__name__ if isinstance(value, Exception) else None,
)
def test_classify_failure(
    error: Exception, status: ExecutionStatus, reason_code: str
) -> None:
    assert classify_failure(error) == (status, reason_code)
