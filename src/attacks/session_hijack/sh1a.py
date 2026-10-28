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
from defenses.mitigation.session_binding import admit_request
from mcp_server.events import ToolEventRecorder
from mcp_server.server import list_notes
from mcp_server.session import SessionStore

SH1A_TOOL_NAME = "list_notes"


def _returns_only_owner_data(
    records: list[dict[str, Any]],
    owner_user_id: str,
) -> bool:
    return bool(records) and all(
        record.get("owner_id") == owner_user_id for record in records
    )


def run_sh1a(
    scenario: Scenario,
    *,
    run_id: str,
) -> tuple[RunResult, tuple[ToolEvent, ...]]:
    if scenario.attack_id != "AC-SH1a":
        raise ValueError("run_sh1a requires an AC-SH1a scenario")

    if scenario.victim_user_id is None:
        raise ValueError("AC-SH1a requires victim_user_id")

    if SH1A_TOOL_NAME not in scenario.allowed_tools:
        raise ValueError(f"AC-SH1a requires {SH1A_TOOL_NAME} in allowed_tools")

    total_started = perf_counter()

    store = SessionStore()

    session = store.create_session(
        scenario.victim_user_id,
        session_id="session_sh1a_victim",
    )

    recorder = ToolEventRecorder(
        run_id=run_id,
        scenario_id=scenario.scenario_id,
    )

    gate = admit_request(
        scenario,
        store,
        recorder,
        actor_user_id=scenario.actor_user_id,
        session_id=session.session_id,
        nonce=scenario.nonce,
        request_id="request_sh1a",
    )
    context = gate.context

    observed_signal_ids: list[str] = []

    if not gate.rejected:
        # Vulnerable behavior: the server trusts the presented session as proof
        # of authorization and scopes the data to the session owner, not to the
        # user who actually sent the request.
        data_owner_user_id = context.session_owner_user_id
        arguments = {"user_id": data_owner_user_id}
        target_authorized = data_owner_user_id in scenario.allowed_target_user_ids

        recorder.record_tool_requested(
            tool_name=SH1A_TOOL_NAME,
            arguments=arguments,
            allowed=target_authorized,
            classification=None if target_authorized else "unauthorized",
            reason_code=(
                None if target_authorized else "not_authorized_by_scenario_policy"
            ),
        )

        records = list_notes(**arguments)

        accessed_other_user_data = (
            data_owner_user_id != context.actor_user_id
            and _returns_only_owner_data(records, data_owner_user_id)
        )

        if (
            context.user_mismatch
            and accessed_other_user_data
            and scenario.success_signal is not None
        ):
            recorder.record_attack_signal_observed(
                attack_id=scenario.attack_id,
                signal_id=scenario.success_signal,
            )
            observed_signal_ids.append(scenario.success_signal)

        recorder.record_tool_completed(
            tool_name=SH1A_TOOL_NAME,
            result={
                "result": records,
                "is_error": False,
            },
            latency_ms=0.0,
            classification=("session_owner_data" if accessed_other_user_data else None),
        )

    if scenario.success_signal in observed_signal_ids:
        attack_outcome = AttackOutcome.SUCCEEDED
    elif gate.rejected:
        attack_outcome = AttackOutcome.BLOCKED
    else:
        attack_outcome = AttackOutcome.NOT_TRIGGERED

    if scenario.defense_mode == DefenseMode.NONE:
        detection_outcome = DetectionOutcome.NOT_APPLICABLE
        mitigation_outcome = MitigationOutcome.NOT_APPLICABLE
    else:
        detection_outcome = (
            DetectionOutcome.DETECTED
            if any(verdict.detected for verdict in gate.verdicts)
            else DetectionOutcome.NOT_DETECTED
        )
        mitigation_outcome = (
            MitigationOutcome.APPLIED
            if gate.rejected
            else MitigationOutcome.NOT_APPLIED
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
        detection_verdicts=list(gate.verdicts),
        total_latency_ms=(perf_counter() - total_started) * 1000.0,
        detection_latency_ms=gate.detection_latency_ms,
        mitigation_latency_ms=gate.mitigation_latency_ms,
    )

    return result, tuple(recorder.events)
