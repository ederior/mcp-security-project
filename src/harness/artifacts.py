import json
from pathlib import Path

from contracts.scenario import Scenario
from harness.runner import HarnessRun


def write_run_artifacts(
    harness_run: HarnessRun,
    scenario: Scenario,
    *,
    output_dir: str | Path,
    git_sha: str,
) -> Path:
    run_dir = Path(output_dir) / harness_run.result.run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    events_path = run_dir / "events.jsonl"
    result_path = run_dir / "result.json"
    config_path = run_dir / "config.json"

    events_jsonl = "\n".join(
        event.model_dump_json()
        for event in harness_run.events
    )

    if events_jsonl:
        events_jsonl += "\n"

    events_path.write_text(
        events_jsonl,
        encoding="utf-8",
    )

    result_path.write_text(
        harness_run.result.model_dump_json(indent=2) + "\n",
        encoding="utf-8",
    )

    safe_config = {
        "run_id": harness_run.result.run_id,
        "scenario_id": scenario.scenario_id,
        "backend": scenario.backend.value,
        "seed": scenario.seed,
        "repetition": scenario.repetition,
        "git_sha": git_sha,
    }

    config_path.write_text(
        json.dumps(
            safe_config,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    return run_dir
