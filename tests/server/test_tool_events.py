import asyncio
import json

from contracts.events import EventType
from mcp_client.ai_client import PersistentMCPClient
from mcp_server.events import (
    ToolEventRecorder,
    sanitize_tool_arguments,
    sanitize_tool_result,
)

FAKE_SECRET = "FAKE_SECRET_must_never_appear_in_events"


def test_tool_events_are_sanitized() -> None:
    recorder = ToolEventRecorder(
        run_id="run_001",
        scenario_id="AC-CL1a",
        actor_user_id="user_1",
        session_owner_user_id="user_1",
        session_fingerprint="sha256:session123456",
    )

    requested = recorder.record_tool_requested(
        tool_name="get_user_profile",
        arguments={
            "user_id": "user_2",
            "payload": FAKE_SECRET,
        },
    )

    completed = recorder.record_tool_completed(
        tool_name="get_user_profile",
        result={
            "result": {
                "user_id": "user_2",
                "secret": FAKE_SECRET,
            },
            "is_error": False,
        },
        latency_ms=1.25,
    )

    assert requested.event_type == EventType.TOOL_REQUESTED
    assert requested.tool_name == "get_user_profile"
    assert requested.operation == "read"
    assert requested.target_user_id == "user_2"
    assert requested.classification == "allowed"

    assert completed.event_type == EventType.TOOL_COMPLETED
    assert completed.success is True
    assert completed.content_length is not None
    assert completed.result_fingerprint is not None
    assert completed.latency_ms == 1.25

    serialized = recorder.to_jsonl()

    assert FAKE_SECRET not in serialized


def test_sanitized_metadata_does_not_copy_secret(capsys) -> None:
    argument_metadata = sanitize_tool_arguments(
        "search_notes",
        {"query": FAKE_SECRET},
    )

    result_metadata = sanitize_tool_result(
        {
            "result": {
                "content": FAKE_SECRET,
            },
            "is_error": False,
        }
    )

    print(json.dumps(argument_metadata))
    print(json.dumps(result_metadata))

    captured = capsys.readouterr()

    assert FAKE_SECRET not in captured.out


def test_unsafe_target_user_value_is_not_copied() -> None:
    metadata = sanitize_tool_arguments(
        "get_user_profile",
        {"user_id": FAKE_SECRET},
    )

    assert metadata["target_user_id"] is None
    assert FAKE_SECRET not in json.dumps(metadata)


def test_blocked_tool_request_records_decision() -> None:
    recorder = ToolEventRecorder(
        run_id="run_002",
        scenario_id="AC-PI2a",
        actor_user_id="user_1",
    )

    event = recorder.record_tool_requested(
        tool_name="get_user_profile",
        arguments={"user_id": "user_2"},
        allowed=False,
        reason_code="cross_user_access_denied",
    )

    assert event.classification == "blocked"
    assert event.reason_code == "cross_user_access_denied"


def test_persistent_client_emits_before_and_after_events() -> None:
    class FakeSession:
        async def call_tool(
            self,
            tool_name: str,
            arguments: dict,
        ) -> dict:
            return {
                "structuredContent": {
                    "value": FAKE_SECRET,
                },
                "isError": False,
            }

    client = PersistentMCPClient(
        "http://unused",
        run_id="run_003",
        scenario_id="AC-CL1a",
        actor_user_id="user_1",
        session_owner_user_id="user_1",
        session_fingerprint="sha256:session123456",
    )

    client._session = FakeSession()  # type: ignore[assignment]

    result = asyncio.run(
        client.call_tool(
            "read_note",
            {"note_id": "note_1"},
        )
    )

    assert result["is_error"] is False

    events = client.event_recorder.events

    assert len(events) == 2
    assert events[0].event_type == EventType.TOOL_REQUESTED
    assert events[1].event_type == EventType.TOOL_COMPLETED
    assert events[0].event_index == 0
    assert events[1].event_index == 1

    assert FAKE_SECRET not in client.event_recorder.to_jsonl()
