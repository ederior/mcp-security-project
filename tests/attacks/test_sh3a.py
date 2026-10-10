from pathlib import Path

from attacks.session_hijack.sh3a import run_sh3a
from contracts.events import EventType, ToolEvent
from contracts.results import (
    AttackOutcome,
    DetectionOutcome,
    MitigationOutcome,
)
from contracts.scenario import DefenseMode, Scenario
from harness.scenario_loader import load_scenario
from mcp_server.server import list_notes

SH3A_SCENARIO = Path("scenarios/attacks/ac_sh3a.yaml")
SESSION_CONTROLS = ["session_binding_validator_v1", "replay_validator_v1"]


def sh3a_scenario(mode: DefenseMode) -> Scenario:
    scenario = load_scenario(SH3A_SCENARIO)
    controls = [] if mode == DefenseMode.NONE else SESSION_CONTROLS
    return scenario.model_copy(
        update={"defense_mode": mode, "enabled_controls": controls}
    )


def event_types(events: tuple[ToolEvent, ...]) -> list[EventType]:
    return [event.event_type for event in events]


def test_sh3a_copied_request_executes_twice_without_defense() -> None:
    result, events = run_sh3a(sh3a_scenario(DefenseMode.NONE), run_id="sh3a_run_001")

    assert event_types(events) == [
        EventType.REQUEST_RECEIVED,
        EventType.TOOL_REQUESTED,
        EventType.TOOL_COMPLETED,
        EventType.REQUEST_RECEIVED,
        EventType.TOOL_REQUESTED,
        EventType.ATTACK_SIGNAL_OBSERVED,
        EventType.TOOL_COMPLETED,
    ]

    # Both requests carry the same identifier and nonce fingerprint.
    first_request, copy_request = events[0], events[3]
    assert first_request.request_id == copy_request.request_id == "request_sh3a"
    assert first_request.nonce_fingerprint == copy_request.nonce_fingerprint

    signal = events[5]
    assert signal.attack_id == "AC-SH3a"
    assert signal.signal_id == "duplicate_request_processed"

    assert result.attack_result is not None
    assert result.attack_result.outcome == AttackOutcome.SUCCEEDED
    assert result.attack_result.observed_signal_ids == ["duplicate_request_processed"]
    assert result.detection_outcome == DetectionOutcome.NOT_APPLICABLE
    assert result.mitigation_outcome == MitigationOutcome.NOT_APPLICABLE


def test_sh3a_detect_mode_flags_the_copy_but_still_executes_it() -> None:
    result, events = run_sh3a(sh3a_scenario(DefenseMode.DETECT), run_id="sh3a_detect")

    assert event_types(events).count(EventType.TOOL_COMPLETED) == 2
    assert EventType.MITIGATION_APPLIED not in event_types(events)

    assert [verdict.reason_code for verdict in result.detection_verdicts] == [
        "session_user_matches",
        "nonce_not_seen",
        "session_user_matches",
        "duplicate_nonce",
    ]

    assert result.attack_result is not None
    assert result.attack_result.outcome == AttackOutcome.SUCCEEDED
    assert result.detection_outcome == DetectionOutcome.DETECTED
    assert result.mitigation_outcome == MitigationOutcome.NOT_APPLIED


def test_sh3a_detect_and_mitigate_rejects_copy_before_any_tool() -> None:
    result, events = run_sh3a(
        sh3a_scenario(DefenseMode.DETECT_AND_MITIGATE),
        run_id="sh3a_mitigate",
    )

    assert [(event.event_type, event.reason_code) for event in events] == [
        (EventType.REQUEST_RECEIVED, None),
        (EventType.DETECTION_EVALUATED, "session_user_matches"),
        (EventType.DETECTION_EVALUATED, "nonce_not_seen"),
        (EventType.TOOL_REQUESTED, None),
        (EventType.TOOL_COMPLETED, None),
        (EventType.REQUEST_RECEIVED, None),
        (EventType.DETECTION_EVALUATED, "session_user_matches"),
        (EventType.DETECTION_EVALUATED, "duplicate_nonce"),
        (EventType.MITIGATION_APPLIED, "replay_detected"),
    ]

    mitigation = events[-1]
    assert mitigation.mitigation_id == "replay_validator_v1"
    assert mitigation.action == "reject_request"
    assert mitigation.boundary == "request"

    assert result.attack_result is not None
    assert result.attack_result.outcome == AttackOutcome.BLOCKED
    assert result.attack_result.observed_signal_ids == []
    assert result.detection_outcome == DetectionOutcome.DETECTED
    assert result.mitigation_outcome == MitigationOutcome.APPLIED
    assert result.detection_latency_ms is not None
    assert result.mitigation_latency_ms is not None


def test_sh3a_two_distinct_requests_do_not_trigger_signal() -> None:
    for mode in (DefenseMode.NONE, DefenseMode.DETECT_AND_MITIGATE):
        result, events = run_sh3a(
            sh3a_scenario(mode),
            run_id=f"sh3a_control_{mode.value}",
            exact_copy=False,
        )

        assert event_types(events).count(EventType.TOOL_COMPLETED) == 2
        assert EventType.ATTACK_SIGNAL_OBSERVED not in event_types(events)
        assert EventType.MITIGATION_APPLIED not in event_types(events)

        assert result.attack_result is not None
        assert result.attack_result.outcome == AttackOutcome.NOT_TRIGGERED
        assert not any(verdict.detected for verdict in result.detection_verdicts)


def test_sh3a_events_do_not_contain_raw_session_id_nonce_or_notes() -> None:
    scenario = sh3a_scenario(DefenseMode.DETECT_AND_MITIGATE)
    result, events = run_sh3a(scenario, run_id="sh3a_sanitized")

    serialized = "\n".join(
        [event.model_dump_json() for event in events] + [result.model_dump_json()]
    )

    assert "session_sh3a_user" not in serialized
    assert scenario.nonce not in serialized

    for note in list_notes("user_1"):
        assert note["title"] not in serialized
        assert note["note_id"] not in serialized
