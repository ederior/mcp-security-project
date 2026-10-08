import asyncio
import subprocess
from pathlib import Path

from harness.artifacts import write_run_artifacts
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
) -> Path:
    scenario = load_scenario(SMOKE_SCENARIO)

    run_id = (
        f"{scenario.scenario_id}" f"_seed{scenario.seed}" f"_rep{scenario.repetition}"
    )

    harness_run = await run_scenario(
        scenario,
        make_smoke_backend(),
        run_id=run_id,
    )

    return write_run_artifacts(
        harness_run,
        scenario,
        output_dir=output_dir,
        git_sha=git_sha or current_git_sha(),
    )


def main() -> None:
    run_dir = asyncio.run(execute_smoke())

    print(f"Smoke run completed: {run_dir}")


if __name__ == "__main__":
    main()
