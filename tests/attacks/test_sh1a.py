from pathlib import Path

from attacks.session_hijack.sh1a import run_sh1a_baseline
from contracts.events import EventType
from contracts.results import AttackOutcome
from harness.scenario_loader import load_scenario
from mcp_server.events import fingerprint
from mcp_server.server import list_notes

SH1A_SCENARIO = Path("scenarios/attacks/ac_sh1a.yaml")


def test_sh1a_mismatched_session_reads_session_owner_data() -> None:
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
    assert tool_requested.tool_name == "list_notes"
    assert tool_requested.operation == "list"
    assert tool_requested.target_user_id == "user_1"
    assert tool_requested.target_user_id not in scenario.allowed_target_user_ids
    assert tool_requested.classification == "unauthorized"

    assert attack_signal.event_type == EventType.ATTACK_SIGNAL_OBSERVED
    assert attack_signal.attack_id == "AC-SH1a"
    assert attack_signal.signal_id == "mismatched_session_request_processed"

    # The event stays sanitized, but its fingerprint proves that user_2 received
    # exactly the owner-scoped notes of user_1.
    owner_notes = list_notes("user_1")
    assert owner_notes
    assert all(note["owner_id"] == "user_1" for note in owner_notes)

    assert tool_completed.event_type == EventType.TOOL_COMPLETED
    assert tool_completed.tool_name == "list_notes"
    assert tool_completed.success is True
    assert tool_completed.classification == "session_owner_data"
    assert tool_completed.result_fingerprint == fingerprint(owner_notes)
    assert tool_completed.result_fingerprint != fingerprint(list_notes("user_2"))

    assert attack_result.outcome == AttackOutcome.SUCCEEDED
    assert attack_result.expected_success_signal == (
        "mismatched_session_request_processed"
    )
    assert attack_result.observed_signal_ids == ["mismatched_session_request_processed"]


def test_sh1a_owner_using_own_session_does_not_trigger_signal() -> None:
    scenario = load_scenario(SH1A_SCENARIO).model_copy(
        update={
            "actor_user_id": "user_1",
            "allowed_target_user_ids": ["user_1"],
        }
    )

    attack_result, events = run_sh1a_baseline(
        scenario,
        run_id="sh1a_run_control",
    )

    assert [event.event_type for event in events] == [
        EventType.REQUEST_RECEIVED,
        EventType.TOOL_REQUESTED,
        EventType.TOOL_COMPLETED,
    ]
    assert events[1].classification == "allowed"
    assert attack_result.outcome == AttackOutcome.NOT_TRIGGERED
    assert attack_result.observed_signal_ids == []


def test_sh1a_events_do_not_contain_raw_identifiers_or_note_data() -> None:
    scenario = load_scenario(SH1A_SCENARIO)

    _, events = run_sh1a_baseline(
        scenario,
        run_id="sh1a_run_sanitized",
    )

    serialized = "\n".join(event.model_dump_json() for event in events)

    assert "session_sh1a_victim" not in serialized
    assert scenario.nonce not in serialized

    for note in list_notes("user_1"):
        assert note["note_id"] not in serialized
        assert note["title"] not in serialized
