from enum import Enum
from typing import Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

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


class EventType(str, Enum):
    RUN_STARTED = "run_started"
    REQUEST_RECEIVED = "request_received"
    TOOL_REQUESTED = "tool_requested"
    TOOL_COMPLETED = "tool_completed"
    DETECTION_EVALUATED = "detection_evaluated"
    MITIGATION_APPLIED = "mitigation_applied"
    ATTACK_SIGNAL_OBSERVED = "attack_signal_observed"
    RUN_COMPLETED = "run_completed"


class ToolEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_type: EventType
    run_id: str = Field(min_length=1)
    scenario_id: str = Field(min_length=1)
    event_index: int = Field(ge=0)

    attack_id: str | None = None
    attack_name: str | None = None

    actor_intent: ActorIntent | None = None
    malicious_input_source: MaliciousInputSource | None = None

    defense_mode: DefenseMode | None = None
    backend: Backend | None = None

    seed: int | None = Field(default=None, ge=0)
    repetition: int | None = Field(default=None, ge=1)

    actor_user_id: str | None = None
    victim_user_id: str | None = None
    session_owner_user_id: str | None = None
    request_id: str | None = None

    session_fingerprint: str | None = None
    nonce_fingerprint: str | None = None

    tool_name: str | None = None
    operation: str | None = None
    target_user_id: str | None = None

    success: bool | None = None
    reason_code: str | None = None
    classification: str | None = None

    content_length: int | None = Field(default=None, ge=0)
    result_fingerprint: str | None = None
    canary_fingerprint: str | None = None

    detector_id: str | None = None
    detector_version: str | None = None
    detected: bool | None = None
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)

    mitigation_id: str | None = None
    mitigation_version: str | None = None
    action: str | None = None
    boundary: str | None = None

    signal_id: str | None = None

    execution_status: ExecutionStatus | None = None
    attack_outcome: AttackOutcome | None = None
    detection_outcome: DetectionOutcome | None = None
    mitigation_outcome: MitigationOutcome | None = None

    latency_ms: float | None = Field(default=None, ge=0.0)

    @model_validator(mode="after")
    def validate_event_fields(self) -> Self:
        required_fields: dict[EventType, tuple[str, ...]] = {
            EventType.RUN_STARTED: (
                "actor_intent",
                "actor_user_id",
                "malicious_input_source",
                "defense_mode",
                "backend",
                "seed",
                "repetition",
            ),
            EventType.REQUEST_RECEIVED: (
                "actor_user_id",
                "request_id",
                "session_fingerprint",
                "nonce_fingerprint",
            ),
            EventType.TOOL_REQUESTED: (
                "tool_name",
                "operation",
            ),
            EventType.TOOL_COMPLETED: (
                "tool_name",
                "success",
            ),
            EventType.DETECTION_EVALUATED: (
                "detector_id",
                "detector_version",
                "detected",
                "reason_code",
                "latency_ms",
            ),
            EventType.MITIGATION_APPLIED: (
                "mitigation_id",
                "mitigation_version",
                "action",
                "reason_code",
                "boundary",
                "success",
                "latency_ms",
            ),
            EventType.ATTACK_SIGNAL_OBSERVED: (
                "attack_id",
                "signal_id",
            ),
            EventType.RUN_COMPLETED: (
                "execution_status",
                "attack_outcome",
                "detection_outcome",
                "mitigation_outcome",
                "latency_ms",
            ),
        }

        required = required_fields.get(self.event_type, ())

        missing = [
            field_name for field_name in required if getattr(self, field_name) is None
        ]

        if missing:
            raise ValueError(
                f"{self.event_type.value} requires fields: " f"{', '.join(missing)}"
            )
        if self.event_type == EventType.RUN_STARTED and (self.attack_id is None) != (
            self.attack_name is None
        ):
            raise ValueError(
                "attack_id and attack_name must either both be set "
                "or both be None for run_started"
            )

        return self
