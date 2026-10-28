import asyncio
from collections.abc import Sequence
from pathlib import Path

import pytest

from contracts.events import EventType, ToolEvent
from contracts.results import (
    AttackOutcome,
    DetectionOutcome,
    ExecutionStatus,
    MitigationOutcome,
)
from contracts.scenario import DefenseMode, Scenario
from defenses.detection import prompt_injection
from defenses.mitigation import tool_policy
from harness.runner import HarnessRun, ToolRoundLimitExceeded, run_scenario
from harness.scenario_loader import load_scenario
from llm_backend.base import (
    BackendResponse,
    BackendUnavailable,
    LLMBackend,
    ToolCall,
    ToolResult,
)
from llm_backend.fake import FakeBackend

SMOKE_SCENARIO = Path("scenarios/benign/smoke.yaml")


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


def test_smoke_scenario_completes() -> None:
    async def run() -> None:
        scenario = load_scenario(SMOKE_SCENARIO)
        backend = make_smoke_backend()

        harness_run = await run_scenario(
            scenario,
            backend,
            run_id="smoke_run_001",
        )

        assert harness_run.result.execution_status == ExecutionStatus.COMPLETED
        assert harness_run.result.attack_result is not None
        assert harness_run.result.attack_result.outcome == AttackOutcome.NOT_APPLICABLE
        assert harness_run.result.detection_outcome == DetectionOutcome.NOT_APPLICABLE
        assert harness_run.result.mitigation_outcome == MitigationOutcome.NOT_APPLICABLE
        assert harness_run.final_text == "Server is healthy"

    asyncio.run(run())


def test_smoke_scenario_emits_tool_events() -> None:
    async def run() -> None:
        scenario = load_scenario(SMOKE_SCENARIO)
        backend = make_smoke_backend()

        harness_run = await run_scenario(
            scenario,
            backend,
            run_id="smoke_run_002",
        )

        assert len(harness_run.events) == 2

        requested, completed = harness_run.events

        assert requested.event_type == EventType.TOOL_REQUESTED
        assert completed.event_type == EventType.TOOL_COMPLETED

        assert requested.tool_name == "health_check"
        assert completed.tool_name == "health_check"

        assert requested.event_index == 0
        assert completed.event_index == 1

        assert completed.success is True
        assert completed.result_fingerprint is not None

    asyncio.run(run())


def smoke_in_mode(mode: DefenseMode) -> Scenario:
    scenario = load_scenario(SMOKE_SCENARIO)
    controls = (
        []
        if mode == DefenseMode.NONE
        else [prompt_injection.DETECTOR_ID, tool_policy.MITIGATION_ID]
    )

    # model_validate runs the Scenario checks again on the changed copy.
    return Scenario.model_validate(
        {**scenario.model_dump(), "defense_mode": mode, "enabled_controls": controls}
    )


def out_of_policy_backend() -> FakeBackend:
    # The smoke policy allows only health_check, so this innocent run
    # proposes a call outside its policy.
    return FakeBackend(
        (
            BackendResponse(
                tool_calls=(
                    ToolCall(name="get_user_profile", arguments={"user_id": "user_2"}),
                )
            ),
            BackendResponse(final_text="Done"),
        )
    )


def events_of(harness_run: HarnessRun, event_type: EventType) -> list[ToolEvent]:
    return [event for event in harness_run.events if event.event_type == event_type]


@pytest.mark.parametrize(
    ("mode", "detection", "mitigation", "tool_executed"),
    [
        (
            DefenseMode.NONE,
            DetectionOutcome.NOT_APPLICABLE,
            MitigationOutcome.NOT_APPLICABLE,
            True,
        ),
        (
            DefenseMode.DETECT,
            DetectionOutcome.DETECTED,
            MitigationOutcome.NOT_APPLIED,
            True,
        ),
        (
            DefenseMode.DETECT_AND_MITIGATE,
            DetectionOutcome.DETECTED,
            MitigationOutcome.APPLIED,
            False,
        ),
    ],
)
def test_innocent_out_of_policy_call_is_measured_not_raised(
    mode: DefenseMode,
    detection: DetectionOutcome,
    mitigation: MitigationOutcome,
    tool_executed: bool,
) -> None:
    backend = out_of_policy_backend()

    harness_run = asyncio.run(
        run_scenario(smoke_in_mode(mode), backend, run_id=f"smoke_oop_{mode.value}")
    )
    result = harness_run.result

    # Detected in detect mode and blocked in detect_and_mitigate: on an
    # innocent run these are the false positives the metrics count.
    assert result.execution_status == ExecutionStatus.COMPLETED
    assert result.attack_result is not None
    assert result.attack_result.outcome == AttackOutcome.NOT_APPLICABLE
    assert result.detection_outcome == detection
    assert result.mitigation_outcome == mitigation

    (requested,) = events_of(harness_run, EventType.TOOL_REQUESTED)
    assert requested.classification == "unauthorized"
    assert requested.reason_code == "not_authorized_by_scenario_policy"

    completed = events_of(harness_run, EventType.TOOL_COMPLETED)
    assert bool(completed) is tool_executed
    assert events_of(harness_run, EventType.ATTACK_SIGNAL_OBSERVED) == []

    (model_result,) = backend.tool_result_history[0]
    assert model_result.is_error is not tool_executed


def test_unknown_tool_is_still_an_error() -> None:
    backend = FakeBackend(
        (
            BackendResponse(tool_calls=(ToolCall(name="delete_everything"),)),
            BackendResponse(final_text="should not be reached"),
        )
    )

    with pytest.raises(RuntimeError, match="Unknown local tool"):
        asyncio.run(
            run_scenario(
                load_scenario(SMOKE_SCENARIO), backend, run_id="smoke_unknown_tool"
            )
        )


def test_tool_round_limit_raises_its_own_error() -> None:
    health_check = BackendResponse(tool_calls=(ToolCall(name="health_check"),))
    backend = FakeBackend(
        (health_check, health_check, health_check, BackendResponse(final_text="Done"))
    )

    with pytest.raises(ToolRoundLimitExceeded, match="exceeded: 2") as raised:
        asyncio.run(
            run_scenario(
                load_scenario(SMOKE_SCENARIO),
                backend,
                run_id="smoke_round_limit",
                max_tool_rounds=2,
            )
        )

    # A subclass of RuntimeError, so existing handlers still catch it.
    assert isinstance(raised.value, RuntimeError)


class UnavailableBackend(LLMBackend):
    async def begin(self, prompt: str, *, seed: int) -> BackendResponse:
        raise BackendUnavailable("simulated HTTP 503")

    async def continue_after_tools(
        self, tool_results: Sequence[ToolResult]
    ) -> BackendResponse:
        raise AssertionError("not reached")


def test_backend_unavailable_reaches_the_caller_unchanged() -> None:
    # The experiment entry point classifies it as inconclusive (Decision 22),
    # so the runner must not wrap or swallow it.
    with pytest.raises(BackendUnavailable):
        asyncio.run(
            run_scenario(
                load_scenario(SMOKE_SCENARIO),
                UnavailableBackend(),
                run_id="smoke_unavailable",
            )
        )
