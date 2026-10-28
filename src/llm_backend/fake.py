import json
import re
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, JsonValue

from llm_backend.base import BackendResponse, LLMBackend, ToolCall, ToolResult

# A script writes this where the scripted model copies the run's synthetic
# canary. The value is taken from tool results the model has already read
# (Decision 22), so no script ever contains the raw canary.
CANARY_PLACEHOLDER = "{{SYNTHETIC_CANARY}}"

# The synthetic canary formats from Decisions 4 and 14.
_CANARY_FORMAT = re.compile(r"\b(?:FAKE_SECRET|CANARY)_[A-Za-z0-9_-]+")


class FakeScriptError(ValueError):
    """A Fake script is invalid or cannot be played in this run.

    Error messages never contain a canary value.
    """


class FakeBackend(LLMBackend):
    def __init__(
        self,
        script: Sequence[BackendResponse],
    ) -> None:
        if not script:
            raise ValueError("FakeBackend script must not be empty")

        if script[-1].final_text is None:
            raise ValueError("FakeBackend script must end with a final response")

        if any(response.final_text is not None for response in script[:-1]):
            raise ValueError(
                "Only the last FakeBackend response may contain final_text"
            )

        self._script = tuple(script)
        self._step_index: int | None = None
        self._prompt: str | None = None
        self._seed: int | None = None
        self._tool_result_history: list[tuple[ToolResult, ...]] = []

    @property
    def prompt(self) -> str | None:
        return self._prompt

    @property
    def seed(self) -> int | None:
        return self._seed

    @property
    def tool_result_history(
        self,
    ) -> tuple[tuple[ToolResult, ...], ...]:
        return tuple(self._tool_result_history)

    async def begin(
        self,
        prompt: str,
        *,
        seed: int,
    ) -> BackendResponse:
        if self._step_index is not None:
            raise RuntimeError("FakeBackend run has already started")

        if not prompt:
            raise ValueError("prompt must not be empty")

        if seed < 0:
            raise ValueError("seed must be non-negative")

        self._prompt = prompt
        self._seed = seed
        self._step_index = 0

        return self._resolve(self._script[0])

    async def continue_after_tools(
        self,
        tool_results: Sequence[ToolResult],
    ) -> BackendResponse:
        if self._step_index is None:
            raise RuntimeError("FakeBackend run has not started")

        current_response = self._script[self._step_index]

        if current_response.final_text is not None:
            raise RuntimeError("FakeBackend run has already completed")

        expected_names = tuple(
            tool_call.name for tool_call in current_response.tool_calls
        )
        actual_names = tuple(tool_result.name for tool_result in tool_results)

        if actual_names != expected_names:
            raise AssertionError(
                "Unexpected tool result order: "
                f"expected {expected_names}, got {actual_names}"
            )

        self._tool_result_history.append(tuple(tool_results))

        self._step_index += 1

        return self._resolve(self._script[self._step_index])

    def _resolve(self, response: BackendResponse) -> BackendResponse:
        """Fill the canary placeholder from the tool results received so far."""
        if not _mentions_placeholder(response):
            return response

        canary = self._received_canary()

        if response.final_text is not None:
            return BackendResponse(
                final_text=response.final_text.replace(CANARY_PLACEHOLDER, canary)
            )

        return BackendResponse(
            tool_calls=tuple(
                ToolCall(
                    name=tool_call.name,
                    arguments=_fill(tool_call.arguments, canary),
                )
                for tool_call in response.tool_calls
            )
        )

    def _received_canary(self) -> str:
        found: set[str] = {
            str(match)
            for tool_results in self._tool_result_history
            for tool_result in tool_results
            for match in _CANARY_FORMAT.findall(_serialize(tool_result.result))
        }

        if not found:
            raise FakeScriptError(
                "The script copies a synthetic canary, but no tool result "
                "received so far contained one"
            )

        if len(found) > 1:
            raise FakeScriptError(
                "The tool results contain more than one synthetic canary value"
            )

        return found.pop()


class FakeToolCallSpec(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(min_length=1)
    arguments: dict[str, JsonValue] = Field(default_factory=dict)


class FakeStepSpec(BaseModel):
    """One model turn: either tool calls or the final answer."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tool_calls: list[FakeToolCallSpec] = Field(default_factory=list)
    final_text: str | None = None


class FakeScript(BaseModel):
    """A scripted Fake model, stored as experiments/fake_scripts/<id>.yaml."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    script_id: str = Field(min_length=1, pattern=r"^[a-z0-9_]+$")
    scenario_id: str = Field(min_length=1)
    description: str = Field(min_length=1)
    steps: list[FakeStepSpec] = Field(min_length=1)

    def responses(self) -> tuple[BackendResponse, ...]:
        return tuple(
            BackendResponse(
                tool_calls=tuple(
                    ToolCall(name=call.name, arguments=dict(call.arguments))
                    for call in step.tool_calls
                ),
                final_text=step.final_text,
            )
            for step in self.steps
        )

    def make_backend(self) -> FakeBackend:
        """Return a new backend; a FakeBackend plays one run only."""
        return FakeBackend(self.responses())


def load_fake_script(path: str | Path) -> FakeScript:
    script_path = Path(path)

    if not script_path.is_file():
        raise FileNotFoundError(f"Fake script does not exist: {script_path}")

    with script_path.open("r", encoding="utf-8") as file:
        raw: Any = yaml.safe_load(file)

    if not isinstance(raw, dict):
        raise FakeScriptError("Fake script YAML must contain a top-level mapping")

    script = FakeScript.model_validate(raw)

    if script.script_id != script_path.stem:
        raise FakeScriptError(
            f"script_id {script.script_id!r} must match the file name "
            f"{script_path.stem!r}"
        )

    try:
        # Building a backend checks every step and the script shape.
        script.make_backend()
    except ValueError as error:
        raise FakeScriptError(f"Invalid Fake script {script_path}: {error}") from error

    return script


def _mentions_placeholder(response: BackendResponse) -> bool:
    if response.final_text is not None:
        return CANARY_PLACEHOLDER in response.final_text

    return any(
        CANARY_PLACEHOLDER in _serialize(tool_call.arguments)
        for tool_call in response.tool_calls
    )


def _fill(value: Any, canary: str) -> Any:
    if isinstance(value, str):
        return value.replace(CANARY_PLACEHOLDER, canary)

    if isinstance(value, dict):
        return {key: _fill(item, canary) for key, item in value.items()}

    if isinstance(value, list):
        return [_fill(item, canary) for item in value]

    return value


def _serialize(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, default=str)
