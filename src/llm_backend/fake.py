from collections.abc import Sequence

from llm_backend.base import BackendResponse, LLMBackend, ToolResult


class FakeBackend(LLMBackend):
    def __init__(
        self,
        script: Sequence[BackendResponse],
    ) -> None:
        if not script:
            raise ValueError("FakeBackend script must not be empty")

        if script[-1].final_text is None:
            raise ValueError(
                "FakeBackend script must end with a final response"
            )

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

        return self._script[0]

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
            tool_call.name
            for tool_call in current_response.tool_calls
        )
        actual_names = tuple(
            tool_result.name
            for tool_result in tool_results
        )

        if actual_names != expected_names:
            raise AssertionError(
                "Unexpected tool result order: "
                f"expected {expected_names}, got {actual_names}"
            )

        self._tool_result_history.append(tuple(tool_results))

        self._step_index += 1

        return self._script[self._step_index]
