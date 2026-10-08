from typing import Any

import pytest
from pydantic import ValidationError

from contracts.events import EventType, ToolEvent
from contracts.results import (
    AttackOutcome,
    DetectionOutcome,
    ExecutionStatus,
    MitigationOutcome,
)
from contracts.scenario import (
    ActorIntent,
    Backend,
    DefenseMode,
    MaliciousInputSource,
)


def base_event_data() -> dict[str, Any]:
    return {
        "event_type": EventType.RUN_STARTED,
        "run_id": "run_001",
        "scenario_id": "AC-PI1a",
        "event_index": 0,
        "attack_id": "AC-PI1a",
        "attack_name": "Hidden Instructions in a Tool Result",
        "actor_intent": ActorIntent.INNOCENT,
        "actor_user_id": "user_1",
        "malicious_input_source": MaliciousInputSource.TOOL_RESULT,
        "defense_mode": DefenseMode.DETECT,
        "backend": Backend.FAKE,
        "seed": 0,
        "repetition": 1,
    }


def test_valid_run_started_event() -> None:
    event = ToolEvent(**base_event_data())

    assert event.event_type == EventType.RUN_STARTED
    assert event.run_id == "run_001"


def test_run_started_requires_required_fields() -> None:
    data = base_event_data()
    del data["actor_intent"]

    with pytest.raises(ValidationError):
        ToolEvent(**data)


def test_run_started_requires_attack_id_and_name_together() -> None:
    data = base_event_data()
    data["attack_name"] = None

    with pytest.raises(ValidationError):
        ToolEvent(**data)


def test_event_json_round_trip() -> None:
    event = ToolEvent(**base_event_data())

    encoded = event.model_dump_json()
    restored = ToolEvent.model_validate_json(encoded)

    assert restored == event


def test_unknown_field_rejected() -> None:
    data = base_event_data()
    data["raw_payload"] = "must not be accepted"

    with pytest.raises(ValidationError):
        ToolEvent(**data)


def test_event_index_cannot_be_negative() -> None:
    data = base_event_data()
    data["event_index"] = -1

    with pytest.raises(ValidationError):
        ToolEvent(**data)


def test_valid_request_received_event() -> None:
    event = ToolEvent(
        event_type=EventType.REQUEST_RECEIVED,
        run_id="run_001",
        scenario_id="AC-SH3a",
        event_index=1,
        actor_user_id="user_1",
        request_id="request_001",
        session_fingerprint="session_fp_001",
        nonce_fingerprint="nonce_fp_001",
    )

    assert event.actor_user_id == "user_1"


def test_request_received_requires_session_fingerprint() -> None:
    with pytest.raises(ValidationError):
        ToolEvent(
            event_type=EventType.REQUEST_RECEIVED,
            run_id="run_001",
            scenario_id="AC-SH3a",
            event_index=1,
            actor_user_id="user_1",
            request_id="request_001",
            nonce_fingerprint="nonce_fp_001",
        )


def test_valid_tool_requested_event() -> None:
    event = ToolEvent(
        event_type=EventType.TOOL_REQUESTED,
        run_id="run_001",
        scenario_id="AC-PI2a",
        event_index=2,
        tool_name="get_user_profile",
        operation="read",
        target_user_id="user_2",
    )

    assert event.tool_name == "get_user_profile"


def test_tool_requested_requires_tool_name() -> None:
    with pytest.raises(ValidationError):
        ToolEvent(
            event_type=EventType.TOOL_REQUESTED,
            run_id="run_001",
            scenario_id="AC-PI2a",
            event_index=2,
            operation="read",
        )


def test_valid_tool_completed_event() -> None:
    event = ToolEvent(
        event_type=EventType.TOOL_COMPLETED,
        run_id="run_001",
        scenario_id="AC-PI1a",
        event_index=3,
        tool_name="read_note",
        success=True,
        classification="untrusted",
        content_length=128,
        result_fingerprint="result_fp_001",
    )

    assert event.success is True


def test_tool_completed_requires_success() -> None:
    with pytest.raises(ValidationError):
        ToolEvent(
            event_type=EventType.TOOL_COMPLETED,
            run_id="run_001",
            scenario_id="AC-PI1a",
            event_index=3,
            tool_name="read_note",
        )


def test_valid_detection_evaluated_event() -> None:
    event = ToolEvent(
        event_type=EventType.DETECTION_EVALUATED,
        run_id="run_001",
        scenario_id="AC-PI1a",
        event_index=4,
        detector_id="prompt_injection_rules_v1",
        detector_version="v1",
        detected=False,
        reason_code="no_injection_detected",
        latency_ms=0.5,
    )

    assert event.detected is False


def test_detection_evaluated_requires_detector_fields() -> None:
    with pytest.raises(ValidationError):
        ToolEvent(
            event_type=EventType.DETECTION_EVALUATED,
            run_id="run_001",
            scenario_id="AC-PI1a",
            event_index=4,
            detected=True,
            reason_code="untrusted_content_requests_tool",
            latency_ms=1.2,
        )


def test_confidence_must_be_between_zero_and_one() -> None:
    with pytest.raises(ValidationError):
        ToolEvent(
            event_type=EventType.DETECTION_EVALUATED,
            run_id="run_001",
            scenario_id="AC-PI1a",
            event_index=4,
            detector_id="prompt_injection_rules_v1",
            detector_version="v1",
            detected=True,
            reason_code="untrusted_content_requests_tool",
            confidence=1.5,
            latency_ms=1.2,
        )


def test_valid_mitigation_applied_event() -> None:
    event = ToolEvent(
        event_type=EventType.MITIGATION_APPLIED,
        run_id="run_001",
        scenario_id="AC-PI2a",
        event_index=5,
        mitigation_id="tool_authorization_policy_v1",
        mitigation_version="v1",
        action="block_tool_call",
        reason_code="cross_user_access_denied",
        boundary="tool_execution",
        success=True,
        latency_ms=0.8,
    )

    assert event.action == "block_tool_call"


def test_mitigation_applied_requires_action() -> None:
    with pytest.raises(ValidationError):
        ToolEvent(
            event_type=EventType.MITIGATION_APPLIED,
            run_id="run_001",
            scenario_id="AC-PI2a",
            event_index=5,
            mitigation_id="tool_authorization_policy_v1",
            mitigation_version="v1",
            reason_code="cross_user_access_denied",
            boundary="tool_execution",
            success=True,
            latency_ms=0.8,
        )


def test_valid_attack_signal_observed_event() -> None:
    event = ToolEvent(
        event_type=EventType.ATTACK_SIGNAL_OBSERVED,
        run_id="run_001",
        scenario_id="AC-CL1a",
        event_index=6,
        attack_id="AC-CL1a",
        signal_id="raw_canary_crossed_boundary",
        boundary="final_answer",
        canary_fingerprint="canary_fp_001",
    )

    assert event.signal_id == "raw_canary_crossed_boundary"


def test_attack_signal_requires_signal_id() -> None:
    with pytest.raises(ValidationError):
        ToolEvent(
            event_type=EventType.ATTACK_SIGNAL_OBSERVED,
            run_id="run_001",
            scenario_id="AC-CL1a",
            event_index=6,
            attack_id="AC-CL1a",
        )


def test_valid_run_completed_event() -> None:
    event = ToolEvent(
        event_type=EventType.RUN_COMPLETED,
        run_id="run_001",
        scenario_id="AC-PI1a",
        event_index=7,
        execution_status=ExecutionStatus.COMPLETED,
        attack_outcome=AttackOutcome.BLOCKED,
        detection_outcome=DetectionOutcome.DETECTED,
        mitigation_outcome=MitigationOutcome.APPLIED,
        latency_ms=12.5,
    )

    assert event.execution_status == ExecutionStatus.COMPLETED
    assert event.attack_outcome == AttackOutcome.BLOCKED


def test_run_completed_requires_outcomes() -> None:
    with pytest.raises(ValidationError):
        ToolEvent(
            event_type=EventType.RUN_COMPLETED,
            run_id="run_001",
            scenario_id="AC-PI1a",
            event_index=7,
            execution_status=ExecutionStatus.COMPLETED,
            attack_outcome=AttackOutcome.BLOCKED,
            detection_outcome=DetectionOutcome.DETECTED,
            latency_ms=12.5,
        )


def test_latency_cannot_be_negative() -> None:
    with pytest.raises(ValidationError):
        ToolEvent(
            event_type=EventType.DETECTION_EVALUATED,
            run_id="run_001",
            scenario_id="AC-PI1a",
            event_index=4,
            detector_id="prompt_injection_rules_v1",
            detector_version="v1",
            detected=True,
            reason_code="untrusted_content_requests_tool",
            latency_ms=-1.0,
        )
