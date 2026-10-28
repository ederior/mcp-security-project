import json
from dataclasses import dataclass
from time import perf_counter
from typing import Any

from contracts.scenario import DefenseMode, Scenario
from defenses.detection.secret_scanner import DETECTOR_ID, CanaryRegistry

MITIGATION_ID = "synthetic_secret_redactor_v1"
MITIGATION_VERSION = "v1"
REDACT_ACTION = "redact_value"
REDACT_REASON_CODE = "registered_canary_redacted"
REDACTION_PLACEHOLDER = "[REDACTED_SYNTHETIC_SECRET]"

_KNOWN_CONTROLS = frozenset({DETECTOR_ID, MITIGATION_ID})


def resolve_secret_controls(scenario: Scenario) -> tuple[bool, bool]:
    """Return whether the scanner and the redactor run in this scenario."""
    unknown = set(scenario.enabled_controls) - _KNOWN_CONTROLS

    if unknown:
        raise ValueError(f"Unknown secret controls: {', '.join(sorted(unknown))}")

    scanner_enabled = (
        scenario.defense_mode != DefenseMode.NONE
        and DETECTOR_ID in scenario.enabled_controls
    )
    redactor_enabled = (
        scenario.defense_mode == DefenseMode.DETECT_AND_MITIGATE
        and MITIGATION_ID in scenario.enabled_controls
    )

    return scanner_enabled, redactor_enabled


def _redact_structure(value: Any, registry: CanaryRegistry) -> tuple[Any, int]:
    if isinstance(value, str):
        return registry.replace(value, REDACTION_PLACEHOLDER)

    if isinstance(value, dict):
        redacted: dict[Any, Any] = {}
        count = 0

        for key, item in value.items():
            redacted[key], item_count = _redact_structure(item, registry)
            count += item_count

        return redacted, count

    if isinstance(value, (list, tuple)):
        items = []
        count = 0

        for item in value:
            redacted_item, item_count = _redact_structure(item, registry)
            items.append(redacted_item)
            count += item_count

        return (tuple(items) if isinstance(value, tuple) else items), count

    return value, 0


@dataclass(frozen=True)
class RedactionRecord:
    """What the redactor did at one boundary during the run."""

    replaced: int
    success: bool
    latency_ms: float


@dataclass
class _BoundaryRedactions:
    replaced: int = 0
    success: bool = True
    latency_ms: float = 0.0


class BoundaryRedactor:
    """Replaces registered canaries before content crosses a boundary.

    After each replacement the result is scanned again, so a record reports
    success only when no raw registered canary is left.
    """

    def __init__(self, registry: CanaryRegistry) -> None:
        self._registry = registry
        self._boundaries: dict[str, _BoundaryRedactions] = {}
        self._total_latency_ms = 0.0

    @property
    def total_latency_ms(self) -> float:
        """Time spent in the redactor, including calls with nothing to remove."""
        return self._total_latency_ms

    def redact_text(self, boundary: str, content: str) -> str:
        started = perf_counter()
        redacted, count = self._registry.replace(content, REDACTION_PLACEHOLDER)
        success = not self._registry.contains(redacted)
        self._record(boundary, count, success, started)

        return redacted

    def redact_value(self, boundary: str, value: Any) -> Any:
        """Redact every string inside a nested dict, list, or tuple."""
        started = perf_counter()
        redacted, count = _redact_structure(value, self._registry)
        success = not self._registry.contains(
            json.dumps(redacted, ensure_ascii=False, default=str)
        )
        self._record(boundary, count, success, started)

        return redacted

    def records(self) -> tuple[tuple[str, RedactionRecord], ...]:
        """Return (boundary, record) pairs for boundaries where a value changed."""
        return tuple(
            (
                boundary,
                RedactionRecord(
                    replaced=redactions.replaced,
                    success=redactions.success,
                    latency_ms=redactions.latency_ms,
                ),
            )
            for boundary, redactions in self._boundaries.items()
            if redactions.replaced
        )

    def _record(
        self,
        boundary: str,
        count: int,
        success: bool,
        started: float,
    ) -> None:
        latency_ms = (perf_counter() - started) * 1000.0
        self._total_latency_ms += latency_ms

        redactions = self._boundaries.setdefault(boundary, _BoundaryRedactions())
        redactions.replaced += count
        redactions.success = redactions.success and success
        redactions.latency_ms += latency_ms
