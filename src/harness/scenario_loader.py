from pathlib import Path
from typing import Any

import yaml

from contracts.scenario import Scenario


def load_scenario(path: str | Path) -> Scenario:
    scenario_path = Path(path)

    if not scenario_path.is_file():
        raise FileNotFoundError(
            f"Scenario file does not exist: {scenario_path}"
        )

    with scenario_path.open(
        "r",
        encoding="utf-8",
    ) as file:
        raw: Any = yaml.safe_load(file)

    if not isinstance(raw, dict):
        raise TypeError(
            "Scenario YAML must contain a top-level mapping"
        )

    return Scenario.model_validate(raw)
