import asyncio
import json
from pathlib import Path

from contracts.results import ExecutionStatus, RunResult
from harness.smoke import execute_smoke


def test_execute_smoke_creates_complete_run(
    tmp_path: Path,
) -> None:
    run_dir = asyncio.run(
        execute_smoke(
            tmp_path,
            git_sha="test_git_sha",
        )
    )

    assert run_dir.name == "benign_smoke_seed0_rep1"

    events_path = run_dir / "events.jsonl"
    result_path = run_dir / "result.json"
    config_path = run_dir / "config.json"

    assert events_path.is_file()
    assert result_path.is_file()
    assert config_path.is_file()

    result = RunResult.model_validate_json(
        result_path.read_text(encoding="utf-8")
    )

    assert result.execution_status == ExecutionStatus.COMPLETED
    assert result.scenario_id == "benign_smoke"

    event_lines = events_path.read_text(
        encoding="utf-8"
    ).splitlines()

    assert len(event_lines) == 2

    config = json.loads(
        config_path.read_text(encoding="utf-8")
    )

    assert config["backend"] == "fake"
    assert config["seed"] == 0
    assert config["repetition"] == 1
    assert config["git_sha"] == "test_git_sha"
