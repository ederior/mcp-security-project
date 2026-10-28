from dataclasses import dataclass
from time import perf_counter

from contracts.results import DetectionVerdict
from contracts.scenario import DefenseMode, Scenario
from defenses.detection.session_validator import (
    BINDING_VALIDATOR_ID,
    REPLAY_VALIDATOR_ID,
    VALIDATOR_VERSION,
    inspect_replay,
    inspect_session_binding,
)
from mcp_server.events import ToolEventRecorder
from mcp_server.session import RequestContext, SessionStore, SessionValidationMode

REJECT_ACTION = "reject_request"
REJECT_BOUNDARY = "request"

REJECTION_REASONS: dict[str, str] = {
    BINDING_VALIDATOR_ID: "session_binding_failed",
    REPLAY_VALIDATOR_ID: "replay_detected",
}


@dataclass(frozen=True)
class SessionGateResult:
    context: RequestContext
    verdicts: tuple[DetectionVerdict, ...]
    rejected: bool
    detection_latency_ms: float | None
    mitigation_latency_ms: float | None


def resolve_session_controls(scenario: Scenario) -> tuple[frozenset[str], bool]:
    """Return the enabled session validators and whether they enforce."""
    controls = frozenset(scenario.enabled_controls)
    unknown = controls - set(REJECTION_REASONS)

    if unknown:
        raise ValueError(f"Unknown session controls: {', '.join(sorted(unknown))}")

    if scenario.defense_mode == DefenseMode.NONE:
        return frozenset(), False

    return controls, scenario.defense_mode == DefenseMode.DETECT_AND_MITIGATE


def admit_request(
    scenario: Scenario,
    store: SessionStore,
    recorder: ToolEventRecorder,
    *,
    actor_user_id: str,
    session_id: str,
    nonce: str,
    request_id: str,
) -> SessionGateResult:
    """Open one request and apply the enabled validators before any tool runs."""
    controls, enforce = resolve_session_controls(scenario)

    used_nonces_before = store.used_nonces(session_id)

    # The server only records the protocol facts; the validators below decide.
    context = store.begin_request(
        actor_user_id=actor_user_id,
        session_id=session_id,
        nonce=nonce,
        validation_mode=SessionValidationMode.VULNERABLE,
        request_id=request_id,
    )

    recorder.set_request_context(
        actor_user_id=context.actor_user_id,
        session_owner_user_id=context.session_owner_user_id,
        session_fingerprint=context.session_fingerprint,
    )
    recorder.record_request_received(
        request_id=context.request_id,
        nonce_fingerprint=context.nonce_fingerprint,
    )

    verdicts: list[DetectionVerdict] = []

    if BINDING_VALIDATOR_ID in controls:
        verdicts.append(inspect_session_binding(scenario, context))

    if REPLAY_VALIDATOR_ID in controls:
        verdicts.append(inspect_replay(scenario, context, used_nonces_before))

    for verdict in verdicts:
        recorder.record_detection_evaluated(verdict=verdict)

    rejected = False
    mitigation_latency_ms = 0.0

    if enforce:
        # Enforcement point: a rejected request never reaches a tool.
        for verdict in verdicts:
            if not verdict.detected:
                continue

            started = perf_counter()
            reason_code = REJECTION_REASONS[verdict.detector_id]
            latency_ms = (perf_counter() - started) * 1000.0

            recorder.record_mitigation_applied(
                mitigation_id=verdict.detector_id,
                mitigation_version=VALIDATOR_VERSION,
                action=REJECT_ACTION,
                reason_code=reason_code,
                boundary=REJECT_BOUNDARY,
                success=True,
                latency_ms=latency_ms,
            )

            rejected = True
            mitigation_latency_ms += latency_ms

    return SessionGateResult(
        context=context,
        verdicts=tuple(verdicts),
        rejected=rejected,
        detection_latency_ms=(
            sum(verdict.latency_ms for verdict in verdicts) if controls else None
        ),
        mitigation_latency_ms=mitigation_latency_ms if enforce else None,
    )
