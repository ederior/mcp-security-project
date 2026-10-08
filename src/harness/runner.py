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
from llm_backend.base import LLMBackend, ToolResult
from mcp_server.events import ToolEventRecorder
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


@dataclass(frozen=True)
class HarnessRun:
    result: RunResult
    events: tuple[ToolEvent, ...]
    final_text: str


def _build_attack_result(
    scenario: Scenario,
) -> AttackResult:
    if scenario.attack_id is None:
        return AttackResult(
            scenario_id=scenario.scenario_id,
            attack_id=None,
            expected_success_signal=None,
            observed_signal_ids=[],
            outcome=AttackOutcome.NOT_APPLICABLE,
        )

    return AttackResult(
        scenario_id=scenario.scenario_id,
        attack_id=scenario.attack_id,
        expected_success_signal=scenario.success_signal,
        observed_signal_ids=[],
        outcome=AttackOutcome.NOT_TRIGGERED,
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
            if tool_call.name not in scenario.allowed_tools:
                raise RuntimeError(f"Tool is not allowed by scenario: {tool_call.name}")

            tool = _LOCAL_TOOLS.get(tool_call.name)

            if tool is None:
                raise RuntimeError(f"Unknown local tool: {tool_call.name}")

            recorder.record_tool_requested(
                tool_name=tool_call.name,
                arguments=tool_call.arguments,
            )

            tool_started = perf_counter()

            raw_result = tool(**tool_call.arguments)
            is_error = False

            tool_latency_ms = (perf_counter() - tool_started) * 1000.0

            normalized_result = {
                "result": raw_result,
                "is_error": is_error,
            }

            recorder.record_tool_completed(
                tool_name=tool_call.name,
                result=normalized_result,
                latency_ms=tool_latency_ms,
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
        attack_result=_build_attack_result(scenario),
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
