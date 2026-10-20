from dataclasses import dataclass
from pathlib import Path

import pytest

from attacks.session_hijack.sh1a import run_sh1a
from contracts.events import EventType
from contracts.results import (
    AttackOutcome,
    DetectionOutcome,
    MitigationOutcome,
)
from contracts.scenario import (
    ActorIntent,
    Backend,
    DefenseMode,
    MaliciousInputSource,
    Scenario,
)
from defenses.detection import session_validator
from defenses.mitigation.session_binding import SessionGateResult, admit_request
from harness.scenario_loader import load_scenario
from mcp_server.events import ToolEventRecorder
from mcp_server.session import RequestContext, SessionStore, SessionValidationMode

SH1A_SCENARIO = Path("scenarios/attacks/ac_sh1a.yaml")
SESSION_CONTROLS = [
    session_validator.BINDING_VALIDATOR_ID,
    session_validator.REPLAY_VALIDATOR_ID,
]
DEFENDED_MODES = [DefenseMode.DETECT, DefenseMode.DETECT_AND_MITIGATE]

# N3.2 threshold (DECISIONS 17): zero false positives on the innocent cases.
FPR_THRESHOLD = 0.0


def sh1a_scenario(mode: DefenseMode) -> Scenario:
    scenario = load_scenario(SH1A_SCENARIO)
    controls = [] if mode == DefenseMode.NONE else SESSION_CONTROLS
    return scenario.model_copy(
        update={"defense_mode": mode, "enabled_controls": controls}
    )


def session_scenario(scenario_id: str, mode: DefenseMode) -> Scenario:
    return Scenario(
        scenario_id=scenario_id,
        actor_intent=ActorIntent.INNOCENT,
        actor_user_id="user_1",
        malicious_input_source=MaliciousInputSource.NONE,
        user_prompt="List my notes.",
        allowed_tools=["list_notes"],
        allowed_operations=["list"],
        allowed_target_user_ids=["user_1"],
        defense_mode=mode,
        enabled_controls=SESSION_CONTROLS,
        backend=Backend.FAKE,
        seed=0,
        repetition=1,
        nonce=f"{scenario_id}_nonce",
    )


# --- Validators ----------------------------------------------------------------


def test_binding_validator_compares_request_user_with_session_owner() -> None:
    scenario = sh1a_scenario(DefenseMode.DETECT)
    store = SessionStore()
    session = store.create_session("user_1")

    def context_for(actor: str, nonce: str) -> RequestContext:
        return store.begin_request(
            actor_user_id=actor,
            session_id=session.session_id,
            nonce=nonce,
            validation_mode=SessionValidationMode.VULNERABLE,
        )

    mismatch = session_validator.inspect_session_binding(
        scenario, context_for("user_2", "nonce_a")
    )
    match = session_validator.inspect_session_binding(
        scenario, context_for("user_1", "nonce_b")
    )

    assert mismatch.detected is True
    assert mismatch.reason_code == "session_user_mismatch"
    assert mismatch.confidence == 1.0
    assert mismatch.evidence_ids == ["request_user_differs_from_session_owner"]
    assert mismatch.detector_id == "session_binding_validator_v1"
    assert mismatch.detector_version == "v1"
    assert mismatch.latency_ms >= 0.0

    assert match.detected is False
    assert match.reason_code == "session_user_matches"
    assert match.confidence == 0.0
    assert match.evidence_ids == []


def test_replay_validator_detects_a_reused_nonce() -> None:
    scenario = sh1a_scenario(DefenseMode.DETECT)
    store = SessionStore()
    session = store.create_session("user_1")
    context = store.begin_request(
        actor_user_id="user_1",
        session_id=session.session_id,
        nonce="nonce_a",
        validation_mode=SessionValidationMode.VULNERABLE,
    )

    duplicate = session_validator.inspect_replay(
        scenario, context, frozenset({"nonce_a"})
    )
    fresh = session_validator.inspect_replay(scenario, context, frozenset())

    assert duplicate.detected is True
    assert duplicate.reason_code == "duplicate_nonce"
    assert duplicate.detector_id == "replay_validator_v1"
    assert duplicate.evidence_ids == ["nonce_in_used_set"]
    assert fresh.detected is False
    assert fresh.reason_code == "nonce_not_seen"


def test_every_reason_code_has_an_explanation() -> None:
    assert set(session_validator.REASON_EXPLANATIONS) == {
        "session_user_mismatch",
        "session_user_matches",
        "duplicate_nonce",
        "nonce_not_seen",
    }
    assert all(session_validator.REASON_EXPLANATIONS.values())


def test_gate_rejects_unknown_controls() -> None:
    scenario = sh1a_scenario(DefenseMode.DETECT).model_copy(
        update={"enabled_controls": ["prompt_injection_rules_v1"]}
    )

    with pytest.raises(ValueError, match="Unknown session controls"):
        run_sh1a(scenario, run_id="sh1a_unknown_control")


# --- AC-SH1a under the three defense modes ------------------------------------


def test_sh1a_none_mode_is_unchanged() -> None:
    result, events = run_sh1a(sh1a_scenario(DefenseMode.NONE), run_id="sh_none")

    assert result.attack_result is not None
    assert result.attack_result.outcome == AttackOutcome.SUCCEEDED
    assert result.detection_outcome == DetectionOutcome.NOT_APPLICABLE
    assert result.mitigation_outcome == MitigationOutcome.NOT_APPLICABLE
    assert result.detection_verdicts == []
    assert result.detection_latency_ms is None
    assert result.mitigation_latency_ms is None
    assert EventType.DETECTION_EVALUATED not in [event.event_type for event in events]


def test_sh1a_detect_mode_records_mismatch_but_does_not_reject() -> None:
    result, events = run_sh1a(sh1a_scenario(DefenseMode.DETECT), run_id="sh_detect")

    assert result.attack_result is not None
    assert result.attack_result.outcome == AttackOutcome.SUCCEEDED
    assert result.detection_outcome == DetectionOutcome.DETECTED
    assert result.mitigation_outcome == MitigationOutcome.NOT_APPLIED
    assert [verdict.reason_code for verdict in result.detection_verdicts] == [
        "session_user_mismatch",
        "nonce_not_seen",
    ]

    event_types = [event.event_type for event in events]
    assert EventType.TOOL_COMPLETED in event_types
    assert EventType.MITIGATION_APPLIED not in event_types

    binding_event = events[1]
    assert binding_event.event_type == EventType.DETECTION_EVALUATED
    assert binding_event.actor_user_id == "user_2"
    assert binding_event.session_owner_user_id == "user_1"
    assert binding_event.session_fingerprint is not None
    assert result.detection_latency_ms is not None
    assert result.mitigation_latency_ms is None


def test_sh1a_detect_and_mitigate_rejects_before_any_tool() -> None:
    result, events = run_sh1a(
        sh1a_scenario(DefenseMode.DETECT_AND_MITIGATE),
        run_id="sh_mitigate",
    )

    assert result.attack_result is not None
    assert result.attack_result.outcome == AttackOutcome.BLOCKED
    assert result.attack_result.observed_signal_ids == []
    assert result.detection_outcome == DetectionOutcome.DETECTED
    assert result.mitigation_outcome == MitigationOutcome.APPLIED

    assert [(event.event_type, event.reason_code) for event in events] == [
        (EventType.REQUEST_RECEIVED, None),
        (EventType.DETECTION_EVALUATED, "session_user_mismatch"),
        (EventType.DETECTION_EVALUATED, "nonce_not_seen"),
        (EventType.MITIGATION_APPLIED, "session_binding_failed"),
    ]

    mitigation = events[-1]
    assert mitigation.mitigation_id == "session_binding_validator_v1"
    assert mitigation.mitigation_version == "v1"
    assert mitigation.action == "reject_request"
    assert mitigation.boundary == "request"
    assert mitigation.success is True
    assert mitigation.actor_user_id == "user_2"
    assert mitigation.session_owner_user_id == "user_1"
    assert result.mitigation_latency_ms is not None


def test_session_events_do_not_contain_raw_session_id_or_nonce() -> None:
    scenario = sh1a_scenario(DefenseMode.DETECT_AND_MITIGATE)
    result, events = run_sh1a(scenario, run_id="sh_sanitized")

    serialized = "\n".join(
        [event.model_dump_json() for event in events] + [result.model_dump_json()]
    )

    assert "session_sh1a_victim" not in serialized
    assert scenario.nonce not in serialized


# --- Replay -----------------------------------------------------------------


def send_twice(mode: DefenseMode) -> tuple[SessionGateResult, SessionGateResult]:
    scenario = session_scenario("replay_direct", mode)
    store = SessionStore()
    session = store.create_session("user_1")
    recorder = ToolEventRecorder(run_id="replay_run", scenario_id="replay_direct")

    def send(request_id: str) -> SessionGateResult:
        return admit_request(
            scenario,
            store,
            recorder,
            actor_user_id="user_1",
            session_id=session.session_id,
            nonce="copied_nonce",
            request_id=request_id,
        )

    return send("request_original"), send("request_copy")


def test_detect_mode_records_duplicate_nonce_but_admits_it() -> None:
    first, copy = send_twice(DefenseMode.DETECT)

    assert first.rejected is False
    assert copy.rejected is False
    assert [verdict.reason_code for verdict in copy.verdicts] == [
        "session_user_matches",
        "duplicate_nonce",
    ]


def test_detect_and_mitigate_rejects_the_copied_request() -> None:
    first, copy = send_twice(DefenseMode.DETECT_AND_MITIGATE)

    assert first.rejected is False
    assert not any(verdict.detected for verdict in first.verdicts)
    assert copy.rejected is True
    assert [verdict.reason_code for verdict in copy.verdicts if verdict.detected] == [
        "duplicate_nonce"
    ]


# --- Innocent cases and FPR -------------------------------------------------


@dataclass(frozen=True)
class BenignCase:
    case_id: str
    # Each request: (request user, session owner, nonce).
    requests: tuple[tuple[str, str, str], ...]


BENIGN_CASES = [
    BenignCase(
        "session_benign_owner_own_session",
        (("user_1", "user_1", "nonce_1"),),
    ),
    BenignCase(
        "session_benign_two_users_own_sessions",
        (("user_1", "user_1", "nonce_1"), ("user_2", "user_2", "nonce_2")),
    ),
    BenignCase(
        "session_benign_distinct_nonces",
        (("user_1", "user_1", "nonce_1"), ("user_1", "user_1", "nonce_2")),
    ),
    BenignCase(
        "session_benign_retry_with_new_nonce",
        (("user_1", "user_1", "nonce_1"), ("user_1", "user_1", "nonce_1_retry")),
    ),
]


def run_benign(case: BenignCase, mode: DefenseMode) -> list[SessionGateResult]:
    scenario = session_scenario(case.case_id, mode)
    store = SessionStore()
    sessions = {
        owner: store.create_session(owner).session_id
        for owner in sorted({owner for _, owner, _ in case.requests})
    }
    recorder = ToolEventRecorder(run_id=case.case_id, scenario_id=case.case_id)

    return [
        admit_request(
            scenario,
            store,
            recorder,
            actor_user_id=user,
            session_id=sessions[owner],
            nonce=nonce,
            request_id=f"request_{index}",
        )
        for index, (user, owner, nonce) in enumerate(case.requests)
    ]


@pytest.mark.parametrize("mode", DEFENDED_MODES, ids=lambda mode: mode.value)
@pytest.mark.parametrize("case", BENIGN_CASES, ids=lambda case: case.case_id)
def test_benign_case_is_admitted_without_detection(
    case: BenignCase,
    mode: DefenseMode,
) -> None:
    gates = run_benign(case, mode)

    assert len(gates) == len(case.requests)
    for gate in gates:
        assert gate.rejected is False
        assert len(gate.verdicts) == 2
        assert not any(verdict.detected for verdict in gate.verdicts)
        assert all(verdict.latency_ms >= 0.0 for verdict in gate.verdicts)


def test_benign_session_fpr_is_within_threshold() -> None:
    # FPR = innocent runs with any positive verdict / completed innocent runs.
    false_positives: list[str] = []
    completed = 0

    for mode in DEFENDED_MODES:
        for case in BENIGN_CASES:
            gates = run_benign(case, mode)
            completed += 1

            reasons = [
                verdict.reason_code
                for gate in gates
                for verdict in gate.verdicts
                if verdict.detected
            ]
            if reasons:
                false_positives.append(f"{case.case_id}:{mode.value}:{reasons}")

    fpr = len(false_positives) / completed

    assert completed == 8
    assert fpr <= FPR_THRESHOLD, false_positives
