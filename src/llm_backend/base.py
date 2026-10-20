from abc import ABC, abstractmethod
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class ToolCall:
    name: str
    arguments: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ToolResult:
    name: str
    result: Any
    is_error: bool = False


@dataclass(frozen=True)
class BackendResponse:
    tool_calls: tuple[ToolCall, ...] = ()
    final_text: str | None = None

    def __post_init__(self) -> None:
        has_tool_calls = bool(self.tool_calls)
        has_final_text = self.final_text is not None

        if has_tool_calls == has_final_text:
            raise ValueError(
                "BackendResponse must contain either tool_calls "
                "or final_text, but not both"
            )


class LLMBackend(ABC):
    @abstractmethod
    async def begin(
        self,
        prompt: str,
        *,
        seed: int,
    ) -> BackendResponse:
        """Start one model run."""

    @abstractmethod
    async def continue_after_tools(
        self,
        tool_results: Sequence[ToolResult],
    ) -> BackendResponse:
        """Continue the same run after tool execution."""
