import asyncio
from pathlib import Path

import pytest

from contracts.events import EventType
from contracts.results import (
    AttackOutcome,
    DetectionOutcome,
    ExecutionStatus,
    MitigationOutcome,
)
from harness.runner import run_scenario
from harness.scenario_loader import load_scenario
from llm_backend.base import BackendResponse, ToolCall
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
            BackendResponse(
                final_text="Server is healthy"
            ),
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

        assert (
            harness_run.result.execution_status
            == ExecutionStatus.COMPLETED
        )
        assert (
            harness_run.result.attack_result.outcome
            == AttackOutcome.NOT_APPLICABLE
        )
        assert (
            harness_run.result.detection_outcome
            == DetectionOutcome.NOT_APPLICABLE
        )
        assert (
            harness_run.result.mitigation_outcome
            == MitigationOutcome.NOT_APPLICABLE
        )
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


def test_disallowed_tool_is_rejected() -> None:
    async def run() -> None:
        scenario = load_scenario(SMOKE_SCENARIO)

        backend = FakeBackend(
            (
                BackendResponse(
                    tool_calls=(
                        ToolCall(
                            name="get_user_profile",
                            arguments={"user_id": "user_2"},
                        ),
                    )
                ),
                BackendResponse(
                    final_text="should not be reached"
                ),
            )
        )

        with pytest.raises(
            RuntimeError,
            match="Tool is not allowed",
        ):
            await run_scenario(
                scenario,
                backend,
                run_id="smoke_run_003",
            )

    asyncio.run(run())
