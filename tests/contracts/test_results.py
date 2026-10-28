from typing import Any

import pytest
from pydantic import ValidationError

from contracts.results import (
    AttackOutcome,
    AttackResult,
    DetectionOutcome,
    DetectionVerdict,
    ExecutionStatus,
    MitigationOutcome,
    RunResult,
)


def valid_verdict_data() -> dict[str, Any]:
    return {
        "detector_id": "prompt_injection_rules_v1",
        "detector_version": "v1",
        "attack_family": "prompt_injection",
        "scenario_id": "AC-PI1a",
        "detected": True,
        "reason_code": "untrusted_content_requests_tool",
        "confidence": 0.95,
        "evidence_ids": [
            "result_fp_001",
            "tool_request_002",
        ],
        "latency_ms": 0.7,
    }


def test_valid_detection_verdict() -> None:
    verdict = DetectionVerdict(**valid_verdict_data())

    assert verdict.detected is True
    assert verdict.detector_id == "prompt_injection_rules_v1"


def test_negative_detection_verdict_is_valid() -> None:
    data = valid_verdict_data()
    data["detected"] = False
    data["reason_code"] = "no_attack_detected"
    data["confidence"] = None
    data["evidence_ids"] = []

    verdict = DetectionVerdict(**data)

    assert verdict.detected is False
    assert verdict.confidence is None


def test_detection_verdict_json_round_trip() -> None:
    verdict = DetectionVerdict(**valid_verdict_data())

    encoded = verdict.model_dump_json()
    restored = DetectionVerdict.model_validate_json(encoded)

    assert restored == verdict


def test_unknown_field_rejected() -> None:
    data = valid_verdict_data()
    data["raw_payload"] = "must not be accepted"

    with pytest.raises(ValidationError):
        DetectionVerdict(**data)


def test_confidence_cannot_exceed_one() -> None:
    data = valid_verdict_data()
    data["confidence"] = 1.1

    with pytest.raises(ValidationError):
        DetectionVerdict(**data)


def test_confidence_cannot_be_negative() -> None:
    data = valid_verdict_data()
    data["confidence"] = -0.1

    with pytest.raises(ValidationError):
        DetectionVerdict(**data)


def test_latency_cannot_be_negative() -> None:
    data = valid_verdict_data()
    data["latency_ms"] = -1.0

    with pytest.raises(ValidationError):
        DetectionVerdict(**data)


def test_reason_code_must_be_stable_identifier() -> None:
    data = valid_verdict_data()
    data["reason_code"] = "Secret was found in the full payload"

    with pytest.raises(ValidationError):
        DetectionVerdict(**data)


def test_evidence_ids_cannot_contain_free_text() -> None:
    data = valid_verdict_data()
    data["evidence_ids"] = [
        "the complete private tool result",
    ]

    with pytest.raises(ValidationError):
        DetectionVerdict(**data)


def test_valid_succeeded_attack_result() -> None:
    result = AttackResult(
        scenario_id="AC-PI1a",
        attack_id="AC-PI1a",
        expected_success_signal="unauthorized_followup_tool_executed",
        observed_signal_ids=[
            "unauthorized_followup_tool_executed",
        ],
        outcome=AttackOutcome.SUCCEEDED,
    )

    assert result.outcome == AttackOutcome.SUCCEEDED


def test_valid_blocked_attack_result() -> None:
    result = AttackResult(
        scenario_id="AC-PI1a",
        attack_id="AC-PI1a",
        expected_success_signal="unauthorized_followup_tool_executed",
        observed_signal_ids=[],
        outcome=AttackOutcome.BLOCKED,
    )

    assert result.outcome == AttackOutcome.BLOCKED


def test_valid_benign_attack_result() -> None:
    result = AttackResult(
        scenario_id="benign_001",
        attack_id=None,
        expected_success_signal=None,
        observed_signal_ids=[],
        outcome=AttackOutcome.NOT_APPLICABLE,
    )

    assert result.outcome == AttackOutcome.NOT_APPLICABLE


def test_succeeded_attack_requires_success_signal_observed() -> None:
    with pytest.raises(ValidationError):
        AttackResult(
            scenario_id="AC-PI1a",
            attack_id="AC-PI1a",
            expected_success_signal="unauthorized_followup_tool_executed",
            observed_signal_ids=[],
            outcome=AttackOutcome.SUCCEEDED,
        )


def test_non_succeeded_attack_cannot_observe_success_signal() -> None:
    with pytest.raises(ValidationError):
        AttackResult(
            scenario_id="AC-PI1a",
            attack_id="AC-PI1a",
            expected_success_signal="unauthorized_followup_tool_executed",
            observed_signal_ids=[
                "unauthorized_followup_tool_executed",
            ],
            outcome=AttackOutcome.BLOCKED,
        )


def test_attack_requires_expected_success_signal() -> None:
    with pytest.raises(ValidationError):
        AttackResult(
            scenario_id="AC-PI1a",
            attack_id="AC-PI1a",
            expected_success_signal=None,
            observed_signal_ids=[],
            outcome=AttackOutcome.NOT_TRIGGERED,
        )


def test_benign_result_cannot_contain_attack_evidence() -> None:
    with pytest.raises(ValidationError):
        AttackResult(
            scenario_id="benign_001",
            attack_id=None,
            expected_success_signal=None,
            observed_signal_ids=["unexpected_signal"],
            outcome=AttackOutcome.NOT_APPLICABLE,
        )


def test_benign_result_must_be_not_applicable() -> None:
    with pytest.raises(ValidationError):
        AttackResult(
            scenario_id="benign_001",
            attack_id=None,
            expected_success_signal=None,
            observed_signal_ids=[],
            outcome=AttackOutcome.NOT_TRIGGERED,
        )


def test_valid_completed_run_result() -> None:
    attack_result = AttackResult(
        scenario_id="AC-PI1a",
        attack_id="AC-PI1a",
        expected_success_signal="unauthorized_followup_tool_executed",
        observed_signal_ids=[],
        outcome=AttackOutcome.BLOCKED,
    )

    verdict = DetectionVerdict(
        detector_id="prompt_injection_rules_v1",
        detector_version="v1",
        attack_family="prompt_injection",
        scenario_id="AC-PI1a",
        detected=True,
        reason_code="untrusted_content_requests_tool",
        confidence=0.95,
        evidence_ids=["result_fp_001"],
        latency_ms=0.7,
    )

    result = RunResult(
        run_id="run_001",
        scenario_id="AC-PI1a",
        execution_status=ExecutionStatus.COMPLETED,
        attack_result=attack_result,
        detection_outcome=DetectionOutcome.DETECTED,
        mitigation_outcome=MitigationOutcome.APPLIED,
        detection_verdicts=[verdict],
        total_latency_ms=12.5,
        backend_latency_ms=9.0,
        detection_latency_ms=0.7,
        mitigation_latency_ms=0.4,
    )

    assert result.execution_status == ExecutionStatus.COMPLETED
    assert result.attack_result is not None
    assert result.attack_result.outcome == AttackOutcome.BLOCKED


def test_valid_completed_not_detected_run_result() -> None:
    attack_result = AttackResult(
        scenario_id="AC-PI1a",
        attack_id="AC-PI1a",
        expected_success_signal="unauthorized_followup_tool_executed",
        observed_signal_ids=[
            "unauthorized_followup_tool_executed",
        ],
        outcome=AttackOutcome.SUCCEEDED,
    )

    verdict = DetectionVerdict(
        detector_id="prompt_injection_rules_v1",
        detector_version="v1",
        attack_family="prompt_injection",
        scenario_id="AC-PI1a",
        detected=False,
        reason_code="no_attack_detected",
        confidence=None,
        evidence_ids=[],
        latency_ms=0.5,
    )

    result = RunResult(
        run_id="run_002",
        scenario_id="AC-PI1a",
        execution_status=ExecutionStatus.COMPLETED,
        attack_result=attack_result,
        detection_outcome=DetectionOutcome.NOT_DETECTED,
        mitigation_outcome=MitigationOutcome.NOT_APPLIED,
        detection_verdicts=[verdict],
        total_latency_ms=10.0,
    )

    assert result.detection_outcome == DetectionOutcome.NOT_DETECTED


def test_valid_completed_detection_not_applicable() -> None:
    attack_result = AttackResult(
        scenario_id="AC-PI1a",
        attack_id="AC-PI1a",
        expected_success_signal="unauthorized_followup_tool_executed",
        observed_signal_ids=[
            "unauthorized_followup_tool_executed",
        ],
        outcome=AttackOutcome.SUCCEEDED,
    )

    result = RunResult(
        run_id="run_003",
        scenario_id="AC-PI1a",
        execution_status=ExecutionStatus.COMPLETED,
        attack_result=attack_result,
        detection_outcome=DetectionOutcome.NOT_APPLICABLE,
        mitigation_outcome=MitigationOutcome.NOT_APPLICABLE,
        detection_verdicts=[],
        total_latency_ms=8.0,
    )

    assert result.detection_verdicts == []


def test_completed_run_requires_attack_result() -> None:
    with pytest.raises(ValidationError):
        RunResult(
            run_id="run_004",
            scenario_id="AC-PI1a",
            execution_status=ExecutionStatus.COMPLETED,
            attack_result=None,
            detection_outcome=DetectionOutcome.NOT_APPLICABLE,
            mitigation_outcome=MitigationOutcome.NOT_APPLICABLE,
            total_latency_ms=8.0,
        )


def test_detected_outcome_requires_detected_verdict() -> None:
    attack_result = AttackResult(
        scenario_id="AC-PI1a",
        attack_id="AC-PI1a",
        expected_success_signal="unauthorized_followup_tool_executed",
        observed_signal_ids=[],
        outcome=AttackOutcome.NOT_TRIGGERED,
    )

    verdict = DetectionVerdict(
        detector_id="prompt_injection_rules_v1",
        detector_version="v1",
        attack_family="prompt_injection",
        scenario_id="AC-PI1a",
        detected=False,
        reason_code="no_attack_detected",
        confidence=None,
        evidence_ids=[],
        latency_ms=0.5,
    )

    with pytest.raises(ValidationError):
        RunResult(
            run_id="run_005",
            scenario_id="AC-PI1a",
            execution_status=ExecutionStatus.COMPLETED,
            attack_result=attack_result,
            detection_outcome=DetectionOutcome.DETECTED,
            mitigation_outcome=MitigationOutcome.NOT_APPLIED,
            detection_verdicts=[verdict],
            total_latency_ms=9.0,
        )


def test_not_detected_outcome_cannot_contain_detected_verdict() -> None:
    attack_result = AttackResult(
        scenario_id="AC-PI1a",
        attack_id="AC-PI1a",
        expected_success_signal="unauthorized_followup_tool_executed",
        observed_signal_ids=[],
        outcome=AttackOutcome.NOT_TRIGGERED,
    )

    verdict = DetectionVerdict(
        detector_id="prompt_injection_rules_v1",
        detector_version="v1",
        attack_family="prompt_injection",
        scenario_id="AC-PI1a",
        detected=True,
        reason_code="untrusted_content_requests_tool",
        confidence=0.9,
        evidence_ids=["result_fp_001"],
        latency_ms=0.5,
    )

    with pytest.raises(ValidationError):
        RunResult(
            run_id="run_006",
            scenario_id="AC-PI1a",
            execution_status=ExecutionStatus.COMPLETED,
            attack_result=attack_result,
            detection_outcome=DetectionOutcome.NOT_DETECTED,
            mitigation_outcome=MitigationOutcome.NOT_APPLIED,
            detection_verdicts=[verdict],
            total_latency_ms=9.0,
        )


def test_valid_inconclusive_run_result() -> None:
    result = RunResult(
        run_id="run_007",
        scenario_id="AC-PI1a",
        execution_status=ExecutionStatus.INCONCLUSIVE,
        total_latency_ms=2.0,
        error_reason_code="gemini_rate_limited",
    )

    assert result.execution_status == ExecutionStatus.INCONCLUSIVE
    assert result.attack_result is None


def test_error_or_inconclusive_requires_reason_code() -> None:
    with pytest.raises(ValidationError):
        RunResult(
            run_id="run_008",
            scenario_id="AC-PI1a",
            execution_status=ExecutionStatus.ERROR,
            total_latency_ms=1.0,
        )


def test_non_completed_run_cannot_have_attack_result() -> None:
    attack_result = AttackResult(
        scenario_id="AC-PI1a",
        attack_id="AC-PI1a",
        expected_success_signal="unauthorized_followup_tool_executed",
        observed_signal_ids=[],
        outcome=AttackOutcome.NOT_TRIGGERED,
    )

    with pytest.raises(ValidationError):
        RunResult(
            run_id="run_009",
            scenario_id="AC-PI1a",
            execution_status=ExecutionStatus.ERROR,
            attack_result=attack_result,
            total_latency_ms=1.0,
            error_reason_code="server_failure",
        )


def test_run_result_json_round_trip() -> None:
    attack_result = AttackResult(
        scenario_id="AC-PI1a",
        attack_id="AC-PI1a",
        expected_success_signal="unauthorized_followup_tool_executed",
        observed_signal_ids=[
            "unauthorized_followup_tool_executed",
        ],
        outcome=AttackOutcome.SUCCEEDED,
    )

    result = RunResult(
        run_id="run_010",
        scenario_id="AC-PI1a",
        execution_status=ExecutionStatus.COMPLETED,
        attack_result=attack_result,
        detection_outcome=DetectionOutcome.NOT_APPLICABLE,
        mitigation_outcome=MitigationOutcome.NOT_APPLICABLE,
        detection_verdicts=[],
        total_latency_ms=8.5,
    )

    encoded = result.model_dump_json()
    restored = RunResult.model_validate_json(encoded)

    assert restored == result


def test_detection_verdict_scenario_must_match_run() -> None:
    attack_result = AttackResult(
        scenario_id="AC-PI1a",
        attack_id="AC-PI1a",
        expected_success_signal="unauthorized_followup_tool_executed",
        observed_signal_ids=[],
        outcome=AttackOutcome.NOT_TRIGGERED,
    )

    verdict = DetectionVerdict(
        detector_id="prompt_injection_rules_v1",
        detector_version="v1",
        attack_family="prompt_injection",
        scenario_id="AC-PI2a",
        detected=True,
        reason_code="direct_policy_override_attempt",
        confidence=0.9,
        evidence_ids=[],
        latency_ms=0.5,
    )

    with pytest.raises(ValidationError):
        RunResult(
            run_id="run_011",
            scenario_id="AC-PI1a",
            execution_status=ExecutionStatus.COMPLETED,
            attack_result=attack_result,
            detection_outcome=DetectionOutcome.DETECTED,
            mitigation_outcome=MitigationOutcome.NOT_APPLIED,
            detection_verdicts=[verdict],
            total_latency_ms=9.0,
        )
