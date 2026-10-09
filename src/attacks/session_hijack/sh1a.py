from contracts.events import ToolEvent
from contracts.results import AttackOutcome, AttackResult
from contracts.scenario import Scenario
from mcp_server.events import ToolEventRecorder
from mcp_server.server import health_check
from mcp_server.session import SessionStore, SessionValidationMode


def run_sh1a_baseline(
    scenario: Scenario,
    *,
    run_id: str,
) -> tuple[AttackResult, tuple[ToolEvent, ...]]:
    if scenario.attack_id != "AC-SH1a":
        raise ValueError("run_sh1a_baseline requires an AC-SH1a scenario")

    if scenario.victim_user_id is None:
        raise ValueError("AC-SH1a requires victim_user_id")

    store = SessionStore()

    session = store.create_session(
        scenario.victim_user_id,
        session_id="session_sh1a_victim",
    )

    context = store.begin_request(
        actor_user_id=scenario.actor_user_id,
        session_id=session.session_id,
        nonce=scenario.nonce,
        validation_mode=SessionValidationMode.VULNERABLE,
        request_id="request_sh1a",
    )

    recorder = ToolEventRecorder(
        run_id=run_id,
        scenario_id=scenario.scenario_id,
        actor_user_id=context.actor_user_id,
        session_owner_user_id=context.session_owner_user_id,
        session_fingerprint=context.session_fingerprint,
    )

    recorder.record_request_received(
        request_id=context.request_id,
        nonce_fingerprint=context.nonce_fingerprint,
    )

    observed_signal_ids: list[str] = []

    if context.accepted:
        recorder.record_tool_requested(
            tool_name="health_check",
            arguments={},
        )

        result = health_check()

        if context.user_mismatch and scenario.success_signal is not None:
            recorder.record_attack_signal_observed(
                attack_id=scenario.attack_id,
                signal_id=scenario.success_signal,
            )
            observed_signal_ids.append(scenario.success_signal)

        recorder.record_tool_completed(
            tool_name="health_check",
            result={
                "result": result,
                "is_error": False,
            },
            latency_ms=0.0,
        )

    attack_result = AttackResult(
        scenario_id=scenario.scenario_id,
        attack_id=scenario.attack_id,
        expected_success_signal=scenario.success_signal,
        observed_signal_ids=observed_signal_ids,
        outcome=(
            AttackOutcome.SUCCEEDED
            if scenario.success_signal in observed_signal_ids
            else AttackOutcome.NOT_TRIGGERED
        ),
    )

    return attack_result, tuple(recorder.events)
