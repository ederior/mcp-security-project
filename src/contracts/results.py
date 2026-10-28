from enum import Enum
from typing import Annotated, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator


class ExecutionStatus(str, Enum):
    COMPLETED = "completed"
    ERROR = "error"
    INCONCLUSIVE = "inconclusive"


class AttackOutcome(str, Enum):
    SUCCEEDED = "succeeded"
    BLOCKED = "blocked"
    NOT_TRIGGERED = "not_triggered"
    NOT_APPLICABLE = "not_applicable"


class DetectionOutcome(str, Enum):
    DETECTED = "detected"
    NOT_DETECTED = "not_detected"
    NOT_APPLICABLE = "not_applicable"


class MitigationOutcome(str, Enum):
    APPLIED = "applied"
    NOT_APPLIED = "not_applied"
    NOT_APPLICABLE = "not_applicable"


StableIdentifier = Annotated[
    str,
    Field(
        min_length=1,
        pattern=r"^[A-Za-z0-9_.:-]+$",
    ),
]

ReasonCode = Annotated[
    str,
    Field(
        min_length=1,
        pattern=r"^[a-z0-9_]+$",
    ),
]


class DetectionVerdict(BaseModel):
    model_config = ConfigDict(extra="forbid")

    detector_id: StableIdentifier
    detector_version: StableIdentifier

    attack_family: StableIdentifier
    scenario_id: StableIdentifier

    detected: bool
    reason_code: ReasonCode

    confidence: float | None = Field(
        default=None,
        ge=0.0,
        le=1.0,
    )

    evidence_ids: list[StableIdentifier] = Field(default_factory=list)

    latency_ms: float = Field(ge=0.0)


class AttackResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scenario_id: StableIdentifier

    attack_id: StableIdentifier | None = None
    expected_success_signal: StableIdentifier | None = None

    observed_signal_ids: list[StableIdentifier] = Field(default_factory=list)

    outcome: AttackOutcome

    @model_validator(mode="after")
    def validate_consistency(self) -> Self:
        if self.attack_id is None:
            if self.expected_success_signal is not None:
                raise ValueError(
                    "expected_success_signal must be None " "when attack_id is None"
                )

            if self.observed_signal_ids:
                raise ValueError(
                    "observed_signal_ids must be empty " "when attack_id is None"
                )

            if self.outcome != AttackOutcome.NOT_APPLICABLE:
                raise ValueError(
                    "outcome must be 'not_applicable' " "when attack_id is None"
                )

            return self

        if self.expected_success_signal is None:
            raise ValueError(
                "expected_success_signal is required " "when attack_id is set"
            )

        if self.outcome == AttackOutcome.NOT_APPLICABLE:
            raise ValueError("attack scenarios cannot have " "outcome 'not_applicable'")

        success_observed = self.expected_success_signal in self.observed_signal_ids

        if self.outcome == AttackOutcome.SUCCEEDED:
            if not success_observed:
                raise ValueError(
                    "a succeeded attack must contain " "the expected success signal"
                )
        elif success_observed:
            raise ValueError(
                "the expected success signal cannot be observed "
                "unless the attack outcome is 'succeeded'"
            )

        return self


class RunResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    run_id: StableIdentifier
    scenario_id: StableIdentifier

    execution_status: ExecutionStatus

    attack_result: AttackResult | None = None
    detection_outcome: DetectionOutcome | None = None
    mitigation_outcome: MitigationOutcome | None = None

    detection_verdicts: list[DetectionVerdict] = Field(default_factory=list)

    total_latency_ms: float = Field(ge=0.0)
    backend_latency_ms: float | None = Field(
        default=None,
        ge=0.0,
    )
    detection_latency_ms: float | None = Field(
        default=None,
        ge=0.0,
    )
    mitigation_latency_ms: float | None = Field(
        default=None,
        ge=0.0,
    )

    error_reason_code: ReasonCode | None = None

    @model_validator(mode="after")
    def validate_run_result(self) -> Self:
        if self.execution_status == ExecutionStatus.COMPLETED:
            if self.attack_result is None:
                raise ValueError(
                    "attack_result is required " "when execution_status is 'completed'"
                )

            if self.detection_outcome is None:
                raise ValueError(
                    "detection_outcome is required "
                    "when execution_status is 'completed'"
                )

            if self.mitigation_outcome is None:
                raise ValueError(
                    "mitigation_outcome is required "
                    "when execution_status is 'completed'"
                )

            if self.error_reason_code is not None:
                raise ValueError(
                    "error_reason_code must be None "
                    "when execution_status is 'completed'"
                )

            if self.attack_result.scenario_id != self.scenario_id:
                raise ValueError(
                    "attack_result scenario_id must match " "RunResult scenario_id"
                )
            for verdict in self.detection_verdicts:
                if verdict.scenario_id != self.scenario_id:
                    raise ValueError(
                        "detection verdict scenario_id must match "
                        "RunResult scenario_id"
                    )

            if self.detection_outcome == DetectionOutcome.NOT_APPLICABLE:
                if self.detection_verdicts:
                    raise ValueError(
                        "detection_verdicts must be empty "
                        "when detection is not applicable"
                    )
            else:
                if not self.detection_verdicts:
                    raise ValueError(
                        "detection_verdicts are required "
                        "when detection is applicable"
                    )

                any_detected = any(
                    verdict.detected for verdict in self.detection_verdicts
                )

                if (
                    self.detection_outcome == DetectionOutcome.DETECTED
                    and not any_detected
                ):
                    raise ValueError(
                        "detected outcome requires at least " "one detected verdict"
                    )

                if (
                    self.detection_outcome == DetectionOutcome.NOT_DETECTED
                    and any_detected
                ):
                    raise ValueError(
                        "not_detected outcome cannot contain " "a detected verdict"
                    )

            return self

        if self.error_reason_code is None:
            raise ValueError(
                "error_reason_code is required for " "error or inconclusive runs"
            )

        if self.attack_result is not None:
            raise ValueError(
                "attack_result must be None for " "error or inconclusive runs"
            )

        if self.detection_outcome is not None:
            raise ValueError(
                "detection_outcome must be None for " "error or inconclusive runs"
            )

        if self.mitigation_outcome is not None:
            raise ValueError(
                "mitigation_outcome must be None for " "error or inconclusive runs"
            )

        if self.detection_verdicts:
            raise ValueError(
                "detection_verdicts must be empty for " "error or inconclusive runs"
            )

        return self
