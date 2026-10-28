import asyncio
import subprocess
from datetime import UTC, datetime
from pathlib import Path

from harness.artifacts import make_batch_id, make_run_id, write_run_artifacts
from harness.runner import run_scenario
from harness.scenario_loader import load_scenario
from llm_backend.base import BackendResponse, ToolCall
from llm_backend.fake import FakeBackend

SMOKE_SCENARIO = Path("scenarios/benign/smoke.yaml")
DEFAULT_OUTPUT_DIR = Path("results")


def current_git_sha() -> str:
    completed = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    )

    return completed.stdout.strip()


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
            BackendResponse(final_text="Server is healthy"),
        )
    )


async def execute_smoke(
    output_dir: str | Path = DEFAULT_OUTPUT_DIR,
    *,
    git_sha: str | None = None,
    started_at: datetime | None = None,
) -> Path:
    """Run the smoke scenario into output_dir/<batch_id>/runs/<run_id>/."""
    scenario = load_scenario(SMOKE_SCENARIO)
    started_at = started_at or datetime.now(UTC)

    harness_run = await run_scenario(
        scenario,
        make_smoke_backend(),
        run_id=make_run_id(scenario),
    )

    return write_run_artifacts(
        harness_run,
        scenario,
        output_dir=Path(output_dir) / make_batch_id(started_at) / "runs",
        git_sha=git_sha or current_git_sha(),
        started_at=started_at,
    )


def main() -> None:
    run_dir = asyncio.run(execute_smoke())

    print(f"Smoke run completed: {run_dir}")


if __name__ == "__main__":
    main()
