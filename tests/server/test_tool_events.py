import asyncio
import json
from typing import Any

import pytest

from contracts.events import EventType
from mcp_client.persistent_client import PersistentMCPClient
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


def test_sanitized_metadata_does_not_copy_secret(
    capsys: pytest.CaptureFixture[str],
) -> None:
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


def test_tool_request_can_be_marked_unauthorized() -> None:
    recorder = ToolEventRecorder(
        run_id="run_unauthorized",
        scenario_id="AC-PI1a",
        actor_user_id="user_1",
    )

    event = recorder.record_tool_requested(
        tool_name="get_user_profile",
        arguments={"user_id": "user_2"},
        classification="unauthorized",
        reason_code="followup_not_authorized_by_user_goal",
    )

    assert event.event_type == EventType.TOOL_REQUESTED
    assert event.classification == "unauthorized"
    assert event.reason_code == "followup_not_authorized_by_user_goal"
    assert event.target_user_id == "user_2"


def test_tool_result_can_be_marked_untrusted() -> None:
    recorder = ToolEventRecorder(
        run_id="run_untrusted",
        scenario_id="AC-PI1a",
        actor_user_id="user_1",
    )

    event = recorder.record_tool_completed(
        tool_name="read_note",
        result={
            "result": {
                "note_id": "note_4",
                "content": FAKE_SECRET,
            },
            "is_error": False,
        },
        latency_ms=1.0,
        classification="untrusted",
    )

    assert event.event_type == EventType.TOOL_COMPLETED
    assert event.classification == "untrusted"
    assert event.success is True
    assert event.result_fingerprint is not None

    assert FAKE_SECRET not in recorder.to_jsonl()


def test_persistent_client_emits_before_and_after_events() -> None:
    class FakeSession:
        async def call_tool(
            self,
            tool_name: str,
            arguments: dict[str, Any],
        ) -> dict[str, Any]:
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


def test_attack_signal_observed_event() -> None:
    recorder = ToolEventRecorder(
        run_id="run_signal",
        scenario_id="ac_pi1a_baseline",
        actor_user_id="user_1",
    )

    event = recorder.record_attack_signal_observed(
        attack_id="AC-PI1a",
        signal_id="unauthorized_followup_tool_executed",
    )

    assert event.event_type == EventType.ATTACK_SIGNAL_OBSERVED
    assert event.attack_id == "AC-PI1a"
    assert event.signal_id == "unauthorized_followup_tool_executed"
