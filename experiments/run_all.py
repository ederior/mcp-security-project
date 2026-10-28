"""Run an experiment matrix and write one batch below results/.

From the repository root:

    uv run python -m experiments.run_all
    uv run python -m experiments.run_all --matrix experiments/matrix_fake.yaml \\
        --output-dir results

The command exits with status 1 when any run is an error (Decision 22).
"""

import argparse
import asyncio
import sys
from pathlib import Path

# src/ is not an installed package. pytest finds it through its pythonpath
# setting; this command adds it here so python -m works from the root.
_SRC = Path(__file__).resolve().parents[1] / "src"

if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from harness.experiment import git_state, load_matrix, run_batch
from harness.plots import draw_batch_plots

DEFAULT_MATRIX = Path("experiments/matrix_fake.yaml")
DEFAULT_OUTPUT_DIR = Path("results")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run an experiment matrix and write a batch of results."
    )
    parser.add_argument("--matrix", type=Path, default=DEFAULT_MATRIX)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    args = parser.parse_args(argv)

    matrix = load_matrix(args.matrix)
    git_sha, git_dirty = git_state()

    outcome = asyncio.run(
        run_batch(
            matrix,
            matrix_file=args.matrix,
            output_root=args.output_dir,
            git_sha=git_sha,
            git_dirty=git_dirty,
            progress=print,
        )
    )

    counts = outcome.status_counts
    print(
        f"Batch {outcome.batch_id}: {outcome.run_count} runs, "
        f"{counts['completed']} completed, {counts['error']} error, "
        f"{counts['inconclusive']} inconclusive"
    )
    print(f"Results: {outcome.batch_dir}")

    plots = draw_batch_plots(outcome.batch_dir)
    print(f"Plots: {len(plots)} written to {outcome.batch_dir / 'plots'}")

    if git_dirty:
        print("Note: tracked files had uncommitted changes (git_dirty in batch.json)")

    return 1 if outcome.has_errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
