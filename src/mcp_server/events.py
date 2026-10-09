import json
import re
from hashlib import sha256
from typing import Any

from contracts.events import EventType, ToolEvent

_SAFE_USER_ID = re.compile(r"^user_[A-Za-z0-9_-]{1,48}$")


def fingerprint(value: Any) -> str:
    serialized = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    )
    digest = sha256(serialized.encode("utf-8")).hexdigest()
    return f"sha256:{digest[:16]}"


def infer_operation(tool_name: str) -> str:
    operations = {
        "health_check": "check",
        "list_notes": "list",
        "read_note": "read",
        "search_notes": "search",
        "get_user_profile": "read",
        "local_exfiltration_sink": "write",
    }

    return operations.get(tool_name, "execute")


def sanitize_tool_arguments(
    tool_name: str,
    arguments: dict[str, Any],
) -> dict[str, Any]:
    target_user_id = arguments.get("user_id")

    if not (
        isinstance(target_user_id, str) and _SAFE_USER_ID.fullmatch(target_user_id)
    ):
        target_user_id = None

    return {
        "operation": infer_operation(tool_name),
        "target_user_id": target_user_id,
        "argument_count": len(arguments),
    }


def sanitize_tool_result(
    result: dict[str, Any],
) -> dict[str, Any]:
    payload = result.get("result")

    serialized = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    )

    if isinstance(payload, (dict, list)):
        classification = "structured"
    elif isinstance(payload, str):
        classification = "text"
    elif payload is None:
        classification = "empty"
    else:
        classification = "scalar"

    success = not bool(result.get("is_error", False))

    return {
        "success": success,
        "classification": classification,
        "content_length": len(serialized),
        "result_fingerprint": fingerprint(payload),
    }


class ToolEventRecorder:
    def __init__(
        self,
        *,
        run_id: str,
        scenario_id: str,
        actor_user_id: str | None = None,
        session_owner_user_id: str | None = None,
        session_fingerprint: str | None = None,
        start_index: int = 0,
    ) -> None:
        self.run_id = run_id
        self.scenario_id = scenario_id
        self.actor_user_id = actor_user_id
        self.session_owner_user_id = session_owner_user_id
        self.session_fingerprint = session_fingerprint
        self._next_index = start_index
        self.events: list[ToolEvent] = []

    def record_tool_requested(
        self,
        *,
        tool_name: str,
        arguments: dict[str, Any],
        allowed: bool = True,
        reason_code: str | None = None,
        classification: str | None = None,
    ) -> ToolEvent:
        metadata = sanitize_tool_arguments(tool_name, arguments)

        event = ToolEvent(
            event_type=EventType.TOOL_REQUESTED,
            run_id=self.run_id,
            scenario_id=self.scenario_id,
            event_index=self._next_index,
            actor_user_id=self.actor_user_id,
            session_owner_user_id=self.session_owner_user_id,
            session_fingerprint=self.session_fingerprint,
            tool_name=tool_name,
            operation=metadata["operation"],
            target_user_id=metadata["target_user_id"],
            classification=(
                classification
                if classification is not None
                else ("allowed" if allowed else "blocked")
            ),
            reason_code=reason_code,
        )

        self._append(event)
        return event

    def record_tool_completed(
        self,
        *,
        tool_name: str,
        result: dict[str, Any],
        latency_ms: float,
        classification: str | None = None,
    ) -> ToolEvent:
        metadata = sanitize_tool_result(result)

        event = ToolEvent(
            event_type=EventType.TOOL_COMPLETED,
            run_id=self.run_id,
            scenario_id=self.scenario_id,
            event_index=self._next_index,
            actor_user_id=self.actor_user_id,
            session_owner_user_id=self.session_owner_user_id,
            session_fingerprint=self.session_fingerprint,
            tool_name=tool_name,
            success=metadata["success"],
            classification=(
                classification
                if classification is not None
                else metadata["classification"]
            ),
            content_length=metadata["content_length"],
            result_fingerprint=metadata["result_fingerprint"],
            latency_ms=latency_ms,
        )

        self._append(event)
        return event

    def record_attack_signal_observed(
        self,
        *,
        attack_id: str,
        signal_id: str,
    ) -> ToolEvent:
        event = ToolEvent(
            event_type=EventType.ATTACK_SIGNAL_OBSERVED,
            run_id=self.run_id,
            scenario_id=self.scenario_id,
            event_index=self._next_index,
            actor_user_id=self.actor_user_id,
            attack_id=attack_id,
            signal_id=signal_id,
        )

        self._append(event)
        return event

    def to_jsonl(self) -> str:
        return "\n".join(event.model_dump_json() for event in self.events)

    def _append(self, event: ToolEvent) -> None:
        self.events.append(event)
        self._next_index += 1
