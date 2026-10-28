from time import perf_counter

from contracts.results import DetectionVerdict
from contracts.scenario import Scenario
from mcp_server.session import RequestContext

BINDING_VALIDATOR_ID = "session_binding_validator_v1"
REPLAY_VALIDATOR_ID = "replay_validator_v1"
VALIDATOR_VERSION = "v1"
ATTACK_FAMILY = "session_hijacking"

SESSION_USER_MISMATCH = "session_user_mismatch"
SESSION_USER_MATCHES = "session_user_matches"
DUPLICATE_NONCE = "duplicate_nonce"
NONCE_NOT_SEEN = "nonce_not_seen"

REASON_EXPLANATIONS: dict[str, str] = {
    SESSION_USER_MISMATCH: (
        "The user who sent the request is not the user the session was " "created for."
    ),
    SESSION_USER_MATCHES: "The request user is the session owner.",
    DUPLICATE_NONCE: (
        "The request reuses a nonce that this session already accepted, "
        "so it is a copy of an earlier request."
    ),
    NONCE_NOT_SEEN: "The request nonce has not been used in this session.",
}


def _verdict(
    scenario: Scenario,
    *,
    detector_id: str,
    detected: bool,
    reason_code: str,
    evidence_id: str,
    started: float,
) -> DetectionVerdict:
    return DetectionVerdict(
        detector_id=detector_id,
        detector_version=VALIDATOR_VERSION,
        attack_family=ATTACK_FAMILY,
        scenario_id=scenario.scenario_id,
        detected=detected,
        reason_code=reason_code,
        confidence=1.0 if detected else 0.0,
        evidence_ids=[evidence_id] if detected else [],
        latency_ms=(perf_counter() - started) * 1000.0,
    )


def inspect_session_binding(
    scenario: Scenario,
    context: RequestContext,
) -> DetectionVerdict:
    """Compare the request user with the user bound to the session."""
    started = perf_counter()
    mismatch = context.actor_user_id != context.session_owner_user_id

    return _verdict(
        scenario,
        detector_id=BINDING_VALIDATOR_ID,
        detected=mismatch,
        reason_code=SESSION_USER_MISMATCH if mismatch else SESSION_USER_MATCHES,
        evidence_id="request_user_differs_from_session_owner",
        started=started,
    )


def inspect_replay(
    scenario: Scenario,
    context: RequestContext,
    used_nonces_before: frozenset[str],
) -> DetectionVerdict:
    """Check the request nonce against the nonces accepted before it."""
    started = perf_counter()
    duplicate = context.nonce in used_nonces_before

    return _verdict(
        scenario,
        detector_id=REPLAY_VALIDATOR_ID,
        detected=duplicate,
        reason_code=DUPLICATE_NONCE if duplicate else NONCE_NOT_SEEN,
        evidence_id="nonce_in_used_set",
        started=started,
    )
