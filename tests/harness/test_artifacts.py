import asyncio
import json
from pathlib import Path

from contracts.events import ToolEvent
from contracts.results import RunResult
from harness.artifacts import write_run_artifacts
from harness.runner import run_scenario
from harness.scenario_loader import load_scenario
from llm_backend.base import BackendResponse, ToolCall
from llm_backend.fake import FakeBackend

SMOKE_SCENARIO = Path("scenarios/benign/smoke.yaml")


def make_smoke_backend() -> FakeBackend:
    return FakeBackend(
        (
            BackendResponse(
                tool_calls=(
                    ToolCall(
                        name="health_check",
                        arguments={},
                    ),
                )
            ),
            BackendResponse(
                final_text="Server is healthy"
            ),
        )
    )


def test_write_run_artifacts(
    tmp_path: Path,
) -> None:
    async def run() -> None:
        scenario = load_scenario(SMOKE_SCENARIO)

        harness_run = await run_scenario(
            scenario,
            make_smoke_backend(),
            run_id="smoke_artifact_run",
        )

        run_dir = write_run_artifacts(
            harness_run,
            scenario,
            output_dir=tmp_path,
            git_sha="abc123",
        )

        assert run_dir == tmp_path / "smoke_artifact_run"

        events_path = run_dir / "events.jsonl"
        result_path = run_dir / "result.json"
        config_path = run_dir / "config.json"

        assert events_path.is_file()
        assert result_path.is_file()
        assert config_path.is_file()

        result = RunResult.model_validate_json(
            result_path.read_text(encoding="utf-8")
        )

        assert result.run_id == "smoke_artifact_run"

        event_lines = events_path.read_text(
            encoding="utf-8"
        ).splitlines()

        assert len(event_lines) == 2

        events = [
            ToolEvent.model_validate_json(line)
            for line in event_lines
        ]

        assert events[0].event_index == 0
        assert events[1].event_index == 1

        config = json.loads(
            config_path.read_text(encoding="utf-8")
        )

        assert config == {
            "backend": "fake",
            "git_sha": "abc123",
            "repetition": 1,
            "run_id": "smoke_artifact_run",
            "scenario_id": "benign_smoke",
            "seed": 0,
        }

    asyncio.run(run())


def test_artifacts_do_not_store_sensitive_scenario_fields(
    tmp_path: Path,
) -> None:
    async def run() -> None:
        scenario = load_scenario(SMOKE_SCENARIO)

        harness_run = await run_scenario(
            scenario,
            make_smoke_backend(),
            run_id="smoke_safe_artifacts",
        )

        run_dir = write_run_artifacts(
            harness_run,
            scenario,
            output_dir=tmp_path,
            git_sha="abc123",
        )

        combined = "\n".join(
            path.read_text(encoding="utf-8")
            for path in (
                run_dir / "events.jsonl",
                run_dir / "result.json",
                run_dir / "config.json",
            )
        )

        assert scenario.user_prompt not in combined
        assert scenario.nonce not in combined

    asyncio.run(run())
