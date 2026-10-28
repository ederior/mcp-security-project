import asyncio

import pytest

from llm_backend.base import BackendResponse, ToolCall, ToolResult
from llm_backend.fake import FakeBackend


def make_script() -> tuple[BackendResponse, ...]:
    return (
        BackendResponse(
            tool_calls=(
                ToolCall(
                    name="read_note",
                    arguments={"note_id": "note_4"},
                ),
            )
        ),
        BackendResponse(
            tool_calls=(
                ToolCall(
                    name="get_user_profile",
                    arguments={"user_id": "user_2"},
                ),
            )
        ),
        BackendResponse(final_text="Deterministic final answer"),
    )


def test_fake_backend_supports_multiple_tool_rounds() -> None:
    async def run() -> None:
        backend = FakeBackend(make_script())

        first = await backend.begin(
            "Read the note",
            seed=42,
        )

        assert first.tool_calls[0].name == "read_note"

        second = await backend.continue_after_tools(
            [
                ToolResult(
                    name="read_note",
                    result={"note_id": "note_4"},
                )
            ]
        )

        assert second.tool_calls[0].name == "get_user_profile"

        final = await backend.continue_after_tools(
            [
                ToolResult(
                    name="get_user_profile",
                    result={"user_id": "user_2"},
                )
            ]
        )

        assert final.final_text == "Deterministic final answer"

    asyncio.run(run())


def test_fake_backend_records_prompt_seed_and_results() -> None:
    async def run() -> None:
        backend = FakeBackend(make_script())

        await backend.begin(
            "Read the note",
            seed=7,
        )

        result = ToolResult(
            name="read_note",
            result={"note_id": "note_4"},
        )

        await backend.continue_after_tools([result])

        assert backend.prompt == "Read the note"
        assert backend.seed == 7
        assert backend.tool_result_history == ((result,),)

    asyncio.run(run())


def test_fake_backend_rejects_wrong_tool_result_order() -> None:
    async def run() -> None:
        backend = FakeBackend(
            (
                BackendResponse(
                    tool_calls=(
                        ToolCall(name="read_note"),
                        ToolCall(name="search_notes"),
                    )
                ),
                BackendResponse(final_text="done"),
            )
        )

        await backend.begin("Run tools", seed=0)

        with pytest.raises(
            AssertionError,
            match="Unexpected tool result order",
        ):
            await backend.continue_after_tools(
                [
                    ToolResult(
                        name="search_notes",
                        result=[],
                    ),
                    ToolResult(
                        name="read_note",
                        result={},
                    ),
                ]
            )

    asyncio.run(run())


def test_fake_backend_is_deterministic_across_twenty_runs() -> None:
    async def run_once() -> tuple[str, str]:
        backend = FakeBackend(make_script())

        first = await backend.begin(
            "Read the note",
            seed=123,
        )

        second = await backend.continue_after_tools(
            [
                ToolResult(
                    name="read_note",
                    result={"note_id": "note_4"},
                )
            ]
        )

        return (
            first.tool_calls[0].name,
            second.tool_calls[0].name,
        )

    outputs = [asyncio.run(run_once()) for _ in range(20)]

    assert len(set(outputs)) == 1


def test_fake_backend_script_must_end_with_final_response() -> None:
    with pytest.raises(
        ValueError,
        match="must end with a final response",
    ):
        FakeBackend((BackendResponse(tool_calls=(ToolCall(name="read_note"),)),))


def test_fake_backend_cannot_continue_after_final_response() -> None:
    async def run() -> None:
        backend = FakeBackend(
            (
                BackendResponse(
                    final_text="done",
                ),
            )
        )

        response = await backend.begin(
            "Nothing else needed",
            seed=0,
        )

        assert response.final_text == "done"

        with pytest.raises(
            RuntimeError,
            match="already completed",
        ):
            await backend.continue_after_tools([])

    asyncio.run(run())
