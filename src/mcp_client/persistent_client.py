import json
from contextlib import AsyncExitStack
from secrets import token_urlsafe
from time import perf_counter
from types import TracebackType
from typing import Any, Self

from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

from mcp_server.events import ToolEventRecorder


def normalize_mcp_result(result: Any) -> dict[str, Any]:
    """
    Convert the MCP tool result into a simple JSON-like Python dict.
    """

    if hasattr(result, "model_dump"):
        raw = result.model_dump(mode="json", by_alias=True)
    else:
        raw = result

    if isinstance(raw, dict):
        if raw.get("structuredContent") is not None:
            return {
                "result": raw["structuredContent"],
                "is_error": raw.get("isError", False),
            }

        content_items = raw.get("content", [])
        text_parts = []

        for item in content_items:
            if isinstance(item, dict) and "text" in item:
                text_parts.append(item["text"])

        text = "\n".join(text_parts).strip()

        if text:
            try:
                return {
                    "result": json.loads(text),
                    "is_error": raw.get("isError", False),
                }
            except json.JSONDecodeError:
                return {
                    "result": text,
                    "is_error": raw.get("isError", False),
                }

        return {
            "result": raw,
            "is_error": raw.get("isError", False),
        }

    return {
        "result": str(raw),
        "is_error": False,
    }


class PersistentMCPClient:
    def __init__(
        self,
        url: str,
        *,
        run_id: str | None = None,
        scenario_id: str = "manual_demo",
        actor_user_id: str | None = None,
        session_owner_user_id: str | None = None,
        session_fingerprint: str | None = None,
    ) -> None:
        self.url = url
        self._exit_stack: AsyncExitStack | None = None
        self._session: ClientSession | None = None

        self.event_recorder = ToolEventRecorder(
            run_id=run_id or f"run_{token_urlsafe(8)}",
            scenario_id=scenario_id,
            actor_user_id=actor_user_id,
            session_owner_user_id=session_owner_user_id,
            session_fingerprint=session_fingerprint,
        )

    async def __aenter__(self) -> Self:
        self._exit_stack = AsyncExitStack()
        read_stream, write_stream, _ = await self._exit_stack.enter_async_context(
            streamable_http_client(self.url)
        )
        self._session = await self._exit_stack.enter_async_context(
            ClientSession(read_stream, write_stream)
        )
        await self._session.initialize()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        if self._exit_stack is not None:
            await self._exit_stack.aclose()

        self._exit_stack = None
        self._session = None

    async def call_tool(
        self,
        tool_name: str,
        args: dict[str, Any],
    ) -> dict[str, Any]:
        if self._session is None:
            raise RuntimeError("PersistentMCPClient is not connected")

        self.event_recorder.record_tool_requested(
            tool_name=tool_name,
            arguments=args,
            allowed=True,
        )

        started_at = perf_counter()

        result = await self._session.call_tool(
            tool_name,
            arguments=args,
        )

        latency_ms = (perf_counter() - started_at) * 1000.0
        normalized_result = normalize_mcp_result(result)

        self.event_recorder.record_tool_completed(
            tool_name=tool_name,
            result=normalized_result,
            latency_ms=latency_ms,
        )

        return normalized_result
