from enum import Enum
from typing import Self

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    JsonValue,
    model_validator,
)


class ActorIntent(str, Enum):
    INNOCENT = "innocent"
    MALICIOUS = "malicious"


class MaliciousInputSource(str, Enum):
    USER_PROMPT = "user_prompt"
    TOOL_RESULT = "tool_result"
    REPLAYED_REQUEST = "replayed_request"
    PROTECTED_CONTEXT = "protected_context"
    NONE = "none"


class DefenseMode(str, Enum):
    NONE = "none"
    DETECT = "detect"
    DETECT_AND_MITIGATE = "detect_and_mitigate"


class Backend(str, Enum):
    FAKE = "fake"
    GEMINI = "gemini"

class Scenario(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scenario_id: str = Field(min_length=1)

    attack_id: str | None = None
    attack_name: str | None = None

    actor_intent: ActorIntent
    actor_user_id: str = Field(min_length=1)
    victim_user_id: str | None = None
    malicious_input_source: MaliciousInputSource

    user_prompt: str = Field(min_length=1)

    allowed_tools: list[str]
    allowed_operations: list[str]
    allowed_target_user_ids: list[str]

    success_signal: str | None = None

    defense_mode: DefenseMode
    enabled_controls: list[str]

    backend: Backend
    model_id: str | None = None
    seed: int = Field(ge=0)
    repetition: int = Field(ge=1)
    nonce: str = Field(min_length=1)

    sampling_config: dict[str, JsonValue] = Field(default_factory=dict)
    metadata: dict[str, JsonValue] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_consistency(self) -> Self:
        if self.attack_id is None:
            if self.attack_name is not None or self.success_signal is not None:
                raise ValueError(
                    "attack_name and success_signal must be None "
                    "when attack_id is None"
                )

            if self.malicious_input_source != MaliciousInputSource.NONE:
                raise ValueError(
                    "malicious_input_source must be 'none' "
                    "when attack_id is None"
                )
        else:
            if self.attack_name is None or self.success_signal is None:
                raise ValueError(
                    "attack_name and success_signal are required "
                    "when attack_id is set"
                )

        if self.backend == Backend.GEMINI and not self.model_id:
            raise ValueError(
                "model_id is required for the Gemini backend"
            )

        if self.defense_mode == DefenseMode.NONE:
            if self.enabled_controls:
                raise ValueError(
                    "enabled_controls must be empty "
                    "when defense_mode is 'none'"
                )
        elif not self.enabled_controls:
            raise ValueError(
                "enabled_controls must not be empty "
                "when defenses are enabled"
            )

        return self
