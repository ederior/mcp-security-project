import json
import platform
from collections.abc import Sequence
from datetime import UTC, datetime
from importlib import metadata
from pathlib import Path
from typing import Any

from contracts.events import EventType, ToolEvent
from contracts.results import ExecutionStatus, RunResult
from contracts.scenario import Scenario
from harness.runner import HarnessRun

# Package versions recorded in environment.json (Decision 22).
RECORDED_PACKAGES = ("mcp", "pydantic", "google-genai")

_BRACKET_EVENT_TYPES = frozenset({EventType.RUN_STARTED, EventType.RUN_COMPLETED})


def make_run_id(scenario: Scenario) -> str:
    """Return the run identifier used for the run directory (Decision 22)."""
    return (
        f"{scenario.scenario_id}"
        f"__{scenario.defense_mode.value}"
        f"__seed{scenario.seed}"
        f"__rep{scenario.repetition}"
    )


def make_batch_id(started_at: datetime) -> str:
    """Return the batch identifier: the UTC start time, for example 20261028T153000Z."""
    return _as_utc(started_at).strftime("%Y%m%dT%H%M%SZ")


def bracket_events(
    scenario: Scenario,
    result: RunResult,
    events: Sequence[ToolEvent],
) -> tuple[ToolEvent, ...]:
    """Add run_started first and run_completed last, then renumber the events.

    Both events use only fields from the scenario and the final result. An
    error or inconclusive run gets no run_completed event, because the event
    contract requires the three outcomes that such a result must not have.
    """
    if result.scenario_id != scenario.scenario_id:
        raise ValueError("RunResult scenario_id does not match the scenario")

    if any(event.event_type in _BRACKET_EVENT_TYPES for event in events):
        raise ValueError("events already contain run_started or run_completed")

    started = ToolEvent(
        event_type=EventType.RUN_STARTED,
        run_id=result.run_id,
        scenario_id=scenario.scenario_id,
        event_index=0,
        attack_id=scenario.attack_id,
        attack_name=scenario.attack_name,
        actor_intent=scenario.actor_intent,
        malicious_input_source=scenario.malicious_input_source,
        defense_mode=scenario.defense_mode,
        backend=scenario.backend,
        seed=scenario.seed,
        repetition=scenario.repetition,
        actor_user_id=scenario.actor_user_id,
        victim_user_id=scenario.victim_user_id,
    )

    bracketed = [
        started,
        *(
            event.model_copy(update={"event_index": index})
            for index, event in enumerate(events, start=1)
        ),
    ]

    if result.execution_status == ExecutionStatus.COMPLETED:
        bracketed.append(_completed_event(scenario, result, len(bracketed)))

    return tuple(bracketed)


def _completed_event(
    scenario: Scenario,
    result: RunResult,
    event_index: int,
) -> ToolEvent:
    if (
        result.attack_result is None
        or result.detection_outcome is None
        or result.mitigation_outcome is None
    ):
        # RunResult validation already guarantees these for completed runs.
        raise ValueError("a completed RunResult must contain all outcomes")

    return ToolEvent(
        event_type=EventType.RUN_COMPLETED,
        run_id=result.run_id,
        scenario_id=scenario.scenario_id,
        event_index=event_index,
        attack_id=scenario.attack_id,
        defense_mode=scenario.defense_mode,
        execution_status=result.execution_status,
        attack_outcome=result.attack_result.outcome,
        detection_outcome=result.detection_outcome,
        mitigation_outcome=result.mitigation_outcome,
        latency_ms=result.total_latency_ms,
    )


def build_config(
    scenario: Scenario,
    *,
    run_id: str,
    fake_script_id: str | None = None,
) -> dict[str, Any]:
    """The non-secret run configuration from docs/experiment_plan.md §9.

    The user prompt, nonce, and scenario metadata are left out on purpose:
    they may hold attack payloads or fixture content (Decision 9).
    """
    return {
        "run_id": run_id,
        "scenario_id": scenario.scenario_id,
        "attack_id": scenario.attack_id,
        "attack_name": scenario.attack_name,
        "success_signal": scenario.success_signal,
        "actor_intent": scenario.actor_intent.value,
        "actor_user_id": scenario.actor_user_id,
        "victim_user_id": scenario.victim_user_id,
        "malicious_input_source": scenario.malicious_input_source.value,
        "defense_mode": scenario.defense_mode.value,
        "enabled_controls": list(scenario.enabled_controls),
        "backend": scenario.backend.value,
        "model_id": scenario.model_id,
        "seed": scenario.seed,
        "repetition": scenario.repetition,
        "sampling_config": scenario.sampling_config,
        "fake_script_id": fake_script_id,
    }


def build_environment(
    *,
    git_sha: str,
    started_at: datetime,
) -> dict[str, Any]:
    """Where and with what the run executed. The host name is not recorded."""
    return {
        "git_sha": git_sha,
        "python_version": platform.python_version(),
        "packages": {name: _package_version(name) for name in RECORDED_PACKAGES},
        "os": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
        },
        "started_at_utc": _as_utc(started_at).isoformat().replace("+00:00", "Z"),
    }


def write_run_artifacts(
    harness_run: HarnessRun,
    scenario: Scenario,
    *,
    output_dir: str | Path,
    git_sha: str,
    started_at: datetime | None = None,
    fake_script_id: str | None = None,
) -> Path:
    """Write the four run files below output_dir/<run_id>/.

    An existing run directory is never overwritten; writing to one raises
    FileExistsError. ``started_at`` defaults to the time of writing.
    """
    run_id = harness_run.result.run_id
    run_dir = Path(output_dir) / run_id

    events = bracket_events(scenario, harness_run.result, harness_run.events)

    run_dir.mkdir(parents=True, exist_ok=False)

    events_jsonl = "".join(event.model_dump_json() + "\n" for event in events)
    (run_dir / "events.jsonl").write_text(events_jsonl, encoding="utf-8")

    (run_dir / "result.json").write_text(
        harness_run.result.model_dump_json(indent=2) + "\n",
        encoding="utf-8",
    )

    write_run_metadata(
        run_dir,
        scenario,
        git_sha=git_sha,
        started_at=started_at or datetime.now(UTC),
        fake_script_id=fake_script_id,
    )

    return run_dir


def write_run_metadata(
    run_dir: Path,
    scenario: Scenario,
    *,
    git_sha: str,
    started_at: datetime,
    fake_script_id: str | None,
) -> None:
    """Write config.json and environment.json into an existing run directory.

    Both files depend only on the scenario and the run setup, never on what
    happened in the run. The experiment entry point calls this again after an
    attack module wrote its own artifacts, to add the Fake script identifier
    and the run's start time (Decision 22).
    """
    run_id = run_dir.name

    _write_json(
        run_dir / "config.json",
        build_config(scenario, run_id=run_id, fake_script_id=fake_script_id),
    )
    _write_json(
        run_dir / "environment.json",
        build_environment(git_sha=git_sha, started_at=started_at),
    )


def _write_json(path: Path, value: dict[str, Any]) -> None:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _package_version(name: str) -> str | None:
    try:
        return metadata.version(name)
    except metadata.PackageNotFoundError:
        return None


def _as_utc(moment: datetime) -> datetime:
    if moment.tzinfo is None:
        raise ValueError("timestamps must be timezone-aware")

    return moment.astimezone(UTC)
