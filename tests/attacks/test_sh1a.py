from pathlib import Path

from attacks.session_hijack.sh1a import run_sh1a_baseline
from contracts.events import EventType
from contracts.results import AttackOutcome
from harness.scenario_loader import load_scenario

SH1A_SCENARIO = Path("scenarios/attacks/ac_sh1a.yaml")


def test_sh1a_mismatched_session_reaches_tool_execution() -> None:
    scenario = load_scenario(SH1A_SCENARIO)

    attack_result, events = run_sh1a_baseline(
        scenario,
        run_id="sh1a_run_001",
    )

    assert len(events) == 4

    (
        request_received,
        tool_requested,
        attack_signal,
        tool_completed,
    ) = events

    assert request_received.event_type == EventType.REQUEST_RECEIVED
    assert request_received.actor_user_id == "user_2"
    assert request_received.session_owner_user_id == "user_1"
    assert request_received.session_fingerprint is not None
    assert request_received.nonce_fingerprint is not None

    assert tool_requested.event_type == EventType.TOOL_REQUESTED
    assert tool_requested.tool_name == "health_check"

    assert attack_signal.event_type == EventType.ATTACK_SIGNAL_OBSERVED
    assert attack_signal.attack_id == "AC-SH1a"
    assert attack_signal.signal_id == "mismatched_session_request_processed"

    assert tool_completed.event_type == EventType.TOOL_COMPLETED
    assert tool_completed.tool_name == "health_check"
    assert tool_completed.success is True

    assert attack_result.outcome == AttackOutcome.SUCCEEDED
    assert attack_result.expected_success_signal == (
        "mismatched_session_request_processed"
    )
    assert attack_result.observed_signal_ids == [
        "mismatched_session_request_processed"
    ]
