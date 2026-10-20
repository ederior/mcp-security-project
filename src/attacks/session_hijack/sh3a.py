from time import perf_counter

from contracts.events import ToolEvent
from contracts.results import (
    AttackOutcome,
    AttackResult,
    DetectionOutcome,
    DetectionVerdict,
    ExecutionStatus,
    MitigationOutcome,
    RunResult,
)
from contracts.scenario import DefenseMode, Scenario
from defenses.mitigation.session_binding import admit_request
from mcp_server.events import ToolEventRecorder
from mcp_server.server import list_notes
from mcp_server.session import SessionStore

SH3A_TOOL_NAME = "list_notes"


def run_sh3a(
    scenario: Scenario,
    *,
    run_id: str,
    exact_copy: bool = True,
) -> tuple[RunResult, tuple[ToolEvent, ...]]:
    """Send a valid request, then send it again.

    With ``exact_copy`` the second request reuses the request ID and nonce,
    which is the attack. Without it the second request is a new legitimate
    request with its own ID and nonce, which is the control run.
    """
    if scenario.attack_id != "AC-SH3a":
        raise ValueError("run_sh3a requires an AC-SH3a scenario")

    if SH3A_TOOL_NAME not in scenario.allowed_tools:
        raise ValueError(f"AC-SH3a requires {SH3A_TOOL_NAME} in allowed_tools")

    request_id = scenario.metadata.get("original_request_id")

    if not isinstance(request_id, str):
        raise TypeError("AC-SH3a requires metadata.original_request_id")

    total_started = perf_counter()

    store = SessionStore()
    session = store.create_session(
        scenario.actor_user_id,
        session_id="session_sh3a_user",
    )
    recorder = ToolEventRecorder(run_id=run_id, scenario_id=scenario.scenario_id)

    requests = [(request_id, scenario.nonce)]
    if exact_copy:
        requests.append((request_id, scenario.nonce))
    else:
        requests.append((f"{request_id}_next", f"{scenario.nonce}_next"))

    completed_request_ids: set[str] = set()
    observed_signal_ids: list[str] = []
    verdicts: list[DetectionVerdict] = []
    rejected = False
    detection_latency_ms: float | None = None
    mitigation_latency_ms: float | None = None

    for current_request_id, nonce in requests:
        gate = admit_request(
            scenario,
            store,
            recorder,
            actor_user_id=scenario.actor_user_id,
            session_id=session.session_id,
            nonce=nonce,
            request_id=current_request_id,
        )

        verdicts.extend(gate.verdicts)
        rejected = rejected or gate.rejected

        if gate.detection_latency_ms is not None:
            detection_latency_ms = (detection_latency_ms or 0.0) + (
                gate.detection_latency_ms
            )
        if gate.mitigation_latency_ms is not None:
            mitigation_latency_ms = (mitigation_latency_ms or 0.0) + (
                gate.mitigation_latency_ms
            )

        if gate.rejected:
            continue

        arguments = {"user_id": scenario.actor_user_id}
        recorder.record_tool_requested(tool_name=SH3A_TOOL_NAME, arguments=arguments)

        tool_started = perf_counter()
        records = list_notes(**arguments)
        tool_latency_ms = (perf_counter() - tool_started) * 1000.0

        if (
            current_request_id in completed_request_ids
            and scenario.success_signal is not None
        ):
            # The same request reached tool execution a second time.
            recorder.record_attack_signal_observed(
                attack_id=scenario.attack_id,
                signal_id=scenario.success_signal,
            )
            observed_signal_ids.append(scenario.success_signal)

        recorder.record_tool_completed(
            tool_name=SH3A_TOOL_NAME,
            result={"result": records, "is_error": False},
            latency_ms=tool_latency_ms,
        )
        completed_request_ids.add(current_request_id)

    if scenario.success_signal in observed_signal_ids:
        attack_outcome = AttackOutcome.SUCCEEDED
    elif rejected:
        attack_outcome = AttackOutcome.BLOCKED
    else:
        attack_outcome = AttackOutcome.NOT_TRIGGERED

    if scenario.defense_mode == DefenseMode.NONE:
        detection_outcome = DetectionOutcome.NOT_APPLICABLE
        mitigation_outcome = MitigationOutcome.NOT_APPLICABLE
    else:
        detection_outcome = (
            DetectionOutcome.DETECTED
            if any(verdict.detected for verdict in verdicts)
            else DetectionOutcome.NOT_DETECTED
        )
        mitigation_outcome = (
            MitigationOutcome.APPLIED if rejected else MitigationOutcome.NOT_APPLIED
        )

    result = RunResult(
        run_id=run_id,
        scenario_id=scenario.scenario_id,
        execution_status=ExecutionStatus.COMPLETED,
        attack_result=AttackResult(
            scenario_id=scenario.scenario_id,
            attack_id=scenario.attack_id,
            expected_success_signal=scenario.success_signal,
            observed_signal_ids=observed_signal_ids,
            outcome=attack_outcome,
        ),
        detection_outcome=detection_outcome,
        mitigation_outcome=mitigation_outcome,
        detection_verdicts=verdicts,
        total_latency_ms=(perf_counter() - total_started) * 1000.0,
        detection_latency_ms=detection_latency_ms,
        mitigation_latency_ms=mitigation_latency_ms,
    )

    return result, tuple(recorder.events)
