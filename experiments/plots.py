"""Redraw the plots of an existing batch, without running it again.

From the repository root:

    uv run python -m experiments.plots results/<batch_id>

run_all draws the plots itself; use this after changing a chart.
"""

import argparse
import sys
from pathlib import Path

# src/ is not an installed package; see experiments/run_all.py.
_SRC = Path(__file__).resolve().parents[1] / "src"

if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from harness.plots import draw_batch_plots


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Redraw the plots of a batch.")
    parser.add_argument("batch_dir", type=Path)
    args = parser.parse_args(argv)

    for path in draw_batch_plots(args.batch_dir):
        print(f"Plot: {path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
