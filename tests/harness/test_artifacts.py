import asyncio
import json
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest

from contracts.events import EventType, ToolEvent
from contracts.results import ExecutionStatus, RunResult
from contracts.scenario import DefenseMode, Scenario
from harness.artifacts import (
    RECORDED_PACKAGES,
    bracket_events,
    make_batch_id,
    make_run_id,
    write_run_artifacts,
)
from harness.runner import HarnessRun, run_scenario
from harness.scenario_loader import load_scenario
from llm_backend.base import BackendResponse, ToolCall
from llm_backend.fake import FakeBackend

SMOKE_SCENARIO = Path("scenarios/benign/smoke.yaml")
PI1A_SCENARIO = Path("scenarios/attacks/ac_pi1a.yaml")
STARTED_AT = datetime(2026, 10, 28, 15, 30, 0, tzinfo=UTC)
RUN_FILES = ["config.json", "environment.json", "events.jsonl", "result.json"]


def make_smoke_backend() -> FakeBackend:
    return FakeBackend(
        (
            BackendResponse(
                tool_calls=(
                    ToolCall(
                        name="health_check",
                        arguments={},
                    ),
                )
            ),
            BackendResponse(final_text="Server is healthy"),
        )
    )


def smoke_run(run_id: str) -> tuple[HarnessRun, Scenario]:
    scenario = load_scenario(SMOKE_SCENARIO)
    harness_run = asyncio.run(
        run_scenario(scenario, make_smoke_backend(), run_id=run_id)
    )
    return harness_run, scenario


def write(harness_run: HarnessRun, scenario: Scenario, output_dir: Path) -> Path:
    return write_run_artifacts(
        harness_run,
        scenario,
        output_dir=output_dir,
        git_sha="abc123",
        started_at=STARTED_AT,
    )


def read_events(run_dir: Path) -> list[ToolEvent]:
    lines = (run_dir / "events.jsonl").read_text(encoding="utf-8").splitlines()
    return [ToolEvent.model_validate_json(line) for line in lines]


def error_run(scenario: Scenario, run_id: str) -> HarnessRun:
    return HarnessRun(
        result=RunResult(
            run_id=run_id,
            scenario_id=scenario.scenario_id,
            execution_status=ExecutionStatus.ERROR,
            total_latency_ms=1.0,
            error_reason_code="unexpected_error",
        ),
        events=(),
        final_text="",
    )


def test_write_run_artifacts_creates_the_four_run_files(tmp_path: Path) -> None:
    harness_run, scenario = smoke_run("smoke_artifact_run")

    run_dir = write(harness_run, scenario, tmp_path)

    assert run_dir == tmp_path / "smoke_artifact_run"
    assert sorted(path.name for path in run_dir.iterdir()) == RUN_FILES

    result = RunResult.model_validate_json(
        (run_dir / "result.json").read_text(encoding="utf-8")
    )
    assert result == harness_run.result


def test_events_are_bracketed_by_run_started_and_run_completed(
    tmp_path: Path,
) -> None:
    harness_run, scenario = smoke_run("smoke_bracketed_run")

    events = read_events(write(harness_run, scenario, tmp_path))

    assert [event.event_type for event in events] == [
        EventType.RUN_STARTED,
        EventType.TOOL_REQUESTED,
        EventType.TOOL_COMPLETED,
        EventType.RUN_COMPLETED,
    ]
    assert [event.event_index for event in events] == [0, 1, 2, 3]
    assert {event.run_id for event in events} == {"smoke_bracketed_run"}

    started, completed = events[0], events[-1]
    assert started.actor_intent == scenario.actor_intent
    assert started.malicious_input_source == scenario.malicious_input_source
    assert started.defense_mode == DefenseMode.NONE
    assert started.attack_id is None and started.attack_name is None

    assert harness_run.result.attack_result is not None
    assert completed.execution_status == ExecutionStatus.COMPLETED
    assert completed.attack_outcome == harness_run.result.attack_result.outcome
    assert completed.detection_outcome == harness_run.result.detection_outcome
    assert completed.mitigation_outcome == harness_run.result.mitigation_outcome
    assert completed.latency_ms == harness_run.result.total_latency_ms


def test_attack_run_started_carries_attack_identity() -> None:
    scenario = load_scenario(PI1A_SCENARIO)
    result = RunResult(
        run_id="pi1a_bracket",
        scenario_id=scenario.scenario_id,
        execution_status=ExecutionStatus.ERROR,
        total_latency_ms=0.0,
        error_reason_code="unexpected_error",
    )

    (started,) = bracket_events(scenario, result, ())

    assert started.attack_id == "AC-PI1a"
    assert started.attack_name == scenario.attack_name
    assert started.victim_user_id == "user_2"


def test_error_run_has_run_started_but_no_run_completed(tmp_path: Path) -> None:
    # The frozen ToolEvent contract requires outcomes in run_completed, which
    # an error RunResult must not have (Decision 22, scope limits).
    scenario = load_scenario(SMOKE_SCENARIO)

    events = read_events(write(error_run(scenario, "smoke_error"), scenario, tmp_path))

    assert [event.event_type for event in events] == [EventType.RUN_STARTED]


def test_bracket_events_rejects_already_bracketed_events() -> None:
    harness_run, scenario = smoke_run("smoke_double_bracket")
    bracketed = bracket_events(scenario, harness_run.result, harness_run.events)

    with pytest.raises(ValueError, match="already contain"):
        bracket_events(scenario, harness_run.result, bracketed)


def test_bracket_events_rejects_a_result_from_another_scenario() -> None:
    harness_run, _ = smoke_run("smoke_mismatch")
    other = load_scenario(PI1A_SCENARIO)

    with pytest.raises(ValueError, match="does not match"):
        bracket_events(other, harness_run.result, harness_run.events)


def test_config_contains_the_experiment_plan_fields(tmp_path: Path) -> None:
    harness_run, scenario = smoke_run("smoke_config")

    run_dir = write_run_artifacts(
        harness_run,
        scenario,
        output_dir=tmp_path,
        git_sha="abc123",
        started_at=STARTED_AT,
        fake_script_id="benign_smoke",
    )
    config = json.loads((run_dir / "config.json").read_text(encoding="utf-8"))

    assert config == {
        "actor_intent": "innocent",
        "actor_user_id": "user_1",
        "attack_id": None,
        "attack_name": None,
        "backend": "fake",
        "corpus_split": None,
        "defense_mode": "none",
        "enabled_controls": [],
        "fake_script_id": "benign_smoke",
        "malicious_input_source": "none",
        "model_id": None,
        "repetition": 1,
        "run_id": "smoke_config",
        "sampling_config": {},
        "scenario_id": "benign_smoke",
        "seed": 0,
        "success_signal": None,
        "victim_user_id": None,
    }


def test_environment_records_sha_versions_os_and_start_time(tmp_path: Path) -> None:
    harness_run, scenario = smoke_run("smoke_environment")

    run_dir = write(harness_run, scenario, tmp_path)
    environment = json.loads((run_dir / "environment.json").read_text(encoding="utf-8"))

    assert environment["git_sha"] == "abc123"
    assert environment["python_version"].startswith("3.11")
    assert sorted(environment["packages"]) == sorted(RECORDED_PACKAGES)
    assert environment["packages"]["pydantic"] is not None
    assert set(environment["os"]) == {"system", "release", "machine"}
    assert environment["started_at_utc"] == "2026-10-28T15:30:00Z"


def test_existing_run_directory_is_never_overwritten(tmp_path: Path) -> None:
    harness_run, scenario = smoke_run("smoke_no_overwrite")
    run_dir = write(harness_run, scenario, tmp_path)
    first_result = (run_dir / "result.json").read_text(encoding="utf-8")

    with pytest.raises(FileExistsError):
        write(harness_run, scenario, tmp_path)

    assert (run_dir / "result.json").read_text(encoding="utf-8") == first_result


def test_artifacts_do_not_store_sensitive_scenario_fields(tmp_path: Path) -> None:
    harness_run, scenario = smoke_run("smoke_safe_artifacts")

    run_dir = write(harness_run, scenario, tmp_path)
    combined = "\n".join(
        path.read_text(encoding="utf-8") for path in sorted(run_dir.iterdir())
    )

    assert scenario.user_prompt not in combined
    assert scenario.nonce not in combined


def test_make_run_id_names_scenario_mode_seed_and_repetition() -> None:
    scenario = load_scenario(PI1A_SCENARIO).model_copy(
        update={"defense_mode": DefenseMode.DETECT, "seed": 3, "repetition": 2}
    )

    assert make_run_id(scenario) == "ac_pi1a_baseline__detect__seed3__rep2"


def test_make_batch_id_uses_utc() -> None:
    israel_time = timezone(timedelta(hours=2))
    local = datetime(2026, 10, 28, 17, 30, 0, tzinfo=israel_time)

    assert make_batch_id(local) == "20261028T153000Z"


def test_naive_timestamps_are_rejected() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        # The missing time zone is the point of this test.
        make_batch_id(datetime(2026, 10, 28, 15, 30, 0))  # noqa: DTZ001
