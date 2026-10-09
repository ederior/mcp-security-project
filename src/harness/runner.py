from collections.abc import Callable
from dataclasses import dataclass
from time import perf_counter
from typing import Any

from contracts.events import ToolEvent
from contracts.results import (
    AttackOutcome,
    AttackResult,
    DetectionOutcome,
    ExecutionStatus,
    MitigationOutcome,
    RunResult,
)
from contracts.scenario import DefenseMode, Scenario
from llm_backend.base import LLMBackend, ToolCall, ToolResult
from mcp_server.events import ToolEventRecorder, infer_operation
from mcp_server.server import (
    get_user_profile,
    health_check,
    list_notes,
    read_note,
    search_notes,
)

_LOCAL_TOOLS: dict[str, Callable[..., Any]] = {
    "health_check": health_check,
    "list_notes": list_notes,
    "read_note": read_note,
    "search_notes": search_notes,
    "get_user_profile": get_user_profile,
}


def _is_tool_call_authorized(
    scenario: Scenario,
    tool_call: ToolCall,
) -> bool:
    if tool_call.name not in scenario.allowed_tools:
        return False

    if infer_operation(tool_call.name) not in scenario.allowed_operations:
        return False

    target_user_id = tool_call.arguments.get("user_id")

    if target_user_id is None:
        return True

    return (
        isinstance(target_user_id, str)
        and target_user_id in scenario.allowed_target_user_ids
    )


def _get_tool_fixture(
    scenario: Scenario,
    tool_call: ToolCall,
) -> tuple[Any, str | None] | None:
    tool_data = scenario.metadata.get("tool_data")

    if not isinstance(tool_data, dict):
        return None

    tool_fixtures = tool_data.get(tool_call.name)

    if not isinstance(tool_fixtures, dict):
        return None

    if tool_call.name != "read_note":
        return None

    note_id = tool_call.arguments.get("note_id")

    if not isinstance(note_id, str):
        return None

    raw_fixture = tool_fixtures.get(note_id)

    if not isinstance(raw_fixture, dict):
        return None

    if "result" not in raw_fixture:
        raise RuntimeError(
            f"Tool fixture is missing result: {tool_call.name}/{note_id}"
        )

    classification = raw_fixture.get("classification")

    if classification is not None and not isinstance(classification, str):
        raise RuntimeError(
            f"Tool fixture has invalid classification: {tool_call.name}/{note_id}"
        )

    return raw_fixture["result"], classification


@dataclass(frozen=True)
class HarnessRun:
    result: RunResult
    events: tuple[ToolEvent, ...]
    final_text: str


def _build_attack_result(
    scenario: Scenario,
    observed_signal_ids: list[str],
) -> AttackResult:
    if scenario.attack_id is None:
        return AttackResult(
            scenario_id=scenario.scenario_id,
            attack_id=None,
            expected_success_signal=None,
            observed_signal_ids=[],
            outcome=AttackOutcome.NOT_APPLICABLE,
        )

    success_observed = scenario.success_signal in observed_signal_ids

    return AttackResult(
        scenario_id=scenario.scenario_id,
        attack_id=scenario.attack_id,
        expected_success_signal=scenario.success_signal,
        observed_signal_ids=observed_signal_ids,
        outcome=(
            AttackOutcome.SUCCEEDED if success_observed else AttackOutcome.NOT_TRIGGERED
        ),
    )


async def run_scenario(
    scenario: Scenario,
    backend: LLMBackend,
    *,
    run_id: str,
    max_tool_rounds: int = 8,
) -> HarnessRun:
    if scenario.defense_mode != DefenseMode.NONE:
        raise ValueError("The N2.2 smoke harness supports defense_mode='none' only")

    if max_tool_rounds < 1:
        raise ValueError("max_tool_rounds must be at least 1")

    recorder = ToolEventRecorder(
        run_id=run_id,
        scenario_id=scenario.scenario_id,
        actor_user_id=scenario.actor_user_id,
    )

    total_started = perf_counter()
    backend_latency_ms = 0.0
    observed_signal_ids: list[str] = []

    backend_started = perf_counter()
    response = await backend.begin(
        scenario.user_prompt,
        seed=scenario.seed,
    )
    backend_latency_ms += (perf_counter() - backend_started) * 1000.0

    tool_rounds = 0

    while response.final_text is None:
        tool_rounds += 1

        if tool_rounds > max_tool_rounds:
            raise RuntimeError("Maximum number of tool rounds exceeded")

        tool_results: list[ToolResult] = []

        for tool_call in response.tool_calls:

            authorized = _is_tool_call_authorized(
                scenario,
                tool_call,
            )

            if not authorized and scenario.attack_id is None:
                raise RuntimeError(f"Tool is not allowed by scenario: {tool_call.name}")

            tool = _LOCAL_TOOLS.get(tool_call.name)

            if tool is None:
                raise RuntimeError(f"Unknown local tool: {tool_call.name}")

            recorder.record_tool_requested(
                tool_name=tool_call.name,
                arguments=tool_call.arguments,
                allowed=authorized,
                classification=None if authorized else "unauthorized",
                reason_code=(
                    None if authorized else "not_authorized_by_scenario_policy"
                ),
            )

            tool_started = perf_counter()

            fixture = _get_tool_fixture(
                scenario,
                tool_call,
            )

            if fixture is None:
                raw_result = tool(**tool_call.arguments)
                result_classification = None
            else:
                raw_result, result_classification = fixture

            is_error = False

            tool_latency_ms = (perf_counter() - tool_started) * 1000.0

            if (
                not authorized
                and scenario.attack_id is not None
                and scenario.success_signal is not None
            ):
                signal_id = scenario.success_signal

                recorder.record_attack_signal_observed(
                    attack_id=scenario.attack_id,
                    signal_id=signal_id,
                )

                observed_signal_ids.append(signal_id)

            normalized_result = {
                "result": raw_result,
                "is_error": is_error,
            }

            recorder.record_tool_completed(
                tool_name=tool_call.name,
                result=normalized_result,
                latency_ms=tool_latency_ms,
                classification=result_classification,
            )

            tool_results.append(
                ToolResult(
                    name=tool_call.name,
                    result=raw_result,
                    is_error=is_error,
                )
            )

        backend_started = perf_counter()
        response = await backend.continue_after_tools(tool_results)
        backend_latency_ms += (perf_counter() - backend_started) * 1000.0

    total_latency_ms = (perf_counter() - total_started) * 1000.0

    result = RunResult(
        run_id=run_id,
        scenario_id=scenario.scenario_id,
        execution_status=ExecutionStatus.COMPLETED,
        attack_result=_build_attack_result(
            scenario,
            observed_signal_ids,
        ),
        detection_outcome=DetectionOutcome.NOT_APPLICABLE,
        mitigation_outcome=MitigationOutcome.NOT_APPLICABLE,
        detection_verdicts=[],
        total_latency_ms=total_latency_ms,
        backend_latency_ms=backend_latency_ms,
    )

    return HarnessRun(
        result=result,
        events=tuple(recorder.events),
        final_text=response.final_text,
    )
