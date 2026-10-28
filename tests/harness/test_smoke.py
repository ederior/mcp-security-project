import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path

from contracts.events import EventType, ToolEvent
from contracts.results import ExecutionStatus, RunResult
from harness.smoke import execute_smoke

STARTED_AT = datetime(2026, 10, 28, 15, 30, 0, tzinfo=UTC)


def test_execute_smoke_creates_complete_run(
    tmp_path: Path,
) -> None:
    run_dir = asyncio.run(
        execute_smoke(
            tmp_path,
            git_sha="test_git_sha",
            started_at=STARTED_AT,
        )
    )

    assert run_dir == tmp_path / "20261028T153000Z" / "runs" / (
        "benign_smoke__none__seed0__rep1"
    )

    result = RunResult.model_validate_json(
        (run_dir / "result.json").read_text(encoding="utf-8")
    )

    assert result.execution_status == ExecutionStatus.COMPLETED
    assert result.scenario_id == "benign_smoke"

    events = [
        ToolEvent.model_validate_json(line)
        for line in (run_dir / "events.jsonl").read_text(encoding="utf-8").splitlines()
    ]

    assert events[0].event_type == EventType.RUN_STARTED
    assert events[-1].event_type == EventType.RUN_COMPLETED
    assert len(events) == 4

    config = json.loads((run_dir / "config.json").read_text(encoding="utf-8"))

    assert config["backend"] == "fake"
    assert config["seed"] == 0
    assert config["repetition"] == 1

    environment = json.loads((run_dir / "environment.json").read_text(encoding="utf-8"))

    assert environment["git_sha"] == "test_git_sha"
