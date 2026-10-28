"""Runner for normal-use session scenarios (Decision 23).

The session attacks have their own runners; an innocent session scenario
instead lists its requests in ``metadata.requests``. Every request passes
through ``admit_request``, the same gate the attacks use (Decision 17), so a
false positive here is a false positive of the real defense.
"""

from time import perf_counter

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter

from contracts.events import ToolEvent
from contracts.results import (
    AttackOutcome,
    AttackResult,
    DetectionOutcome,
    DetectionVerdict,
    ExecutionStatus,
    MitigationOutcome,
    RunResult,
)
from contracts.scenario import DefenseMode, Scenario
from defenses.mitigation.session_binding import admit_request
from mcp_server.events import ToolEventRecorder
from mcp_server.server import list_notes
from mcp_server.session import SessionStore

SESSION_TOOL_NAME = "list_notes"


class SessionRequest(BaseModel):
    """One request: who sends it, whose session it uses, and its nonce."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    user: str = Field(pattern=r"^user_[A-Za-z0-9_-]+$")
    session_owner: str = Field(pattern=r"^user_[A-Za-z0-9_-]+$")
    nonce: str = Field(min_length=1)


_REQUESTS = TypeAdapter(list[SessionRequest])


def run_session_requests(
    scenario: Scenario,
    *,
    run_id: str,
) -> tuple[RunResult, tuple[ToolEvent, ...]]:
    """Send the scenario's requests through the session gate, in order.

    An admitted request lists the requesting user's notes. A rejected request
    on a normal-use run is a mitigation false positive.
    """
    if scenario.attack_id is not None:
        raise ValueError("run_session_requests runs normal-use scenarios only")

    if SESSION_TOOL_NAME not in scenario.allowed_tools:
        raise ValueError(f"A session scenario needs {SESSION_TOOL_NAME} allowed")

    requests = _REQUESTS.validate_python(scenario.metadata.get("requests"))

    if not requests:
        raise ValueError("A session scenario needs at least one request")

    total_started = perf_counter()
    store = SessionStore()
    # Fixed session IDs keep runs reproducible; events store only fingerprints.
    sessions = {
        owner: store.create_session(owner, session_id=f"session_{owner}").session_id
        for owner in sorted({request.session_owner for request in requests})
    }
    recorder = ToolEventRecorder(run_id=run_id, scenario_id=scenario.scenario_id)

    verdicts: list[DetectionVerdict] = []
    rejected = False
    detection_latency_ms: float | None = None
    mitigation_latency_ms: float | None = None

    for index, request in enumerate(requests, start=1):
        gate = admit_request(
            scenario,
            store,
            recorder,
            actor_user_id=request.user,
            session_id=sessions[request.session_owner],
            nonce=request.nonce,
            request_id=f"{scenario.scenario_id}_request_{index}",
        )

        verdicts.extend(gate.verdicts)
        rejected = rejected or gate.rejected

        if gate.detection_latency_ms is not None:
            detection_latency_ms = (detection_latency_ms or 0.0) + (
                gate.detection_latency_ms
            )
        if gate.mitigation_latency_ms is not None:
            mitigation_latency_ms = (mitigation_latency_ms or 0.0) + (
                gate.mitigation_latency_ms
            )

        if gate.rejected:
            continue

        arguments = {"user_id": request.user}
        recorder.record_tool_requested(tool_name=SESSION_TOOL_NAME, arguments=arguments)

        tool_started = perf_counter()
        records = list_notes(**arguments)
        recorder.record_tool_completed(
            tool_name=SESSION_TOOL_NAME,
            result={"result": records, "is_error": False},
            latency_ms=(perf_counter() - tool_started) * 1000.0,
        )

    if scenario.defense_mode == DefenseMode.NONE:
        detection_outcome = DetectionOutcome.NOT_APPLICABLE
        mitigation_outcome = MitigationOutcome.NOT_APPLICABLE
    else:
        detection_outcome = (
            DetectionOutcome.DETECTED
            if any(verdict.detected for verdict in verdicts)
            else DetectionOutcome.NOT_DETECTED
        )
        mitigation_outcome = (
            MitigationOutcome.APPLIED if rejected else MitigationOutcome.NOT_APPLIED
        )

    result = RunResult(
        run_id=run_id,
        scenario_id=scenario.scenario_id,
        execution_status=ExecutionStatus.COMPLETED,
        attack_result=AttackResult(
            scenario_id=scenario.scenario_id,
            outcome=AttackOutcome.NOT_APPLICABLE,
        ),
        detection_outcome=detection_outcome,
        mitigation_outcome=mitigation_outcome,
        detection_verdicts=verdicts,
        total_latency_ms=(perf_counter() - total_started) * 1000.0,
        detection_latency_ms=detection_latency_ms,
        mitigation_latency_ms=mitigation_latency_ms,
    )

    return result, tuple(recorder.events)
