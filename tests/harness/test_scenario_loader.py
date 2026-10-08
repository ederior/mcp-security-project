from pathlib import Path

import pytest
from pydantic import ValidationError

from contracts.scenario import (
    ActorIntent,
    Backend,
    DefenseMode,
    MaliciousInputSource,
)
from harness.scenario_loader import load_scenario

SMOKE_SCENARIO = Path("scenarios/benign/smoke.yaml")


def test_load_smoke_scenario() -> None:
    scenario = load_scenario(SMOKE_SCENARIO)

    assert scenario.scenario_id == "benign_smoke"
    assert scenario.actor_intent == ActorIntent.INNOCENT
    assert scenario.actor_user_id == "user_1"
    assert scenario.malicious_input_source == MaliciousInputSource.NONE
    assert scenario.allowed_tools == ["health_check"]
    assert scenario.defense_mode == DefenseMode.NONE
    assert scenario.backend == Backend.FAKE
    assert scenario.seed == 0


def test_missing_scenario_file_is_rejected() -> None:
    with pytest.raises(FileNotFoundError):
        load_scenario("scenarios/benign/does_not_exist.yaml")


def test_non_mapping_yaml_is_rejected(
    tmp_path: Path,
) -> None:
    path = tmp_path / "invalid.yaml"
    path.write_text(
        "- one\n- two\n",
        encoding="utf-8",
    )

    with pytest.raises(
        TypeError,
        match="top-level mapping",
    ):
        load_scenario(path)


def test_invalid_scenario_contract_is_rejected(
    tmp_path: Path,
) -> None:
    path = tmp_path / "invalid.yaml"

    path.write_text(
        """
scenario_id: broken
actor_intent: innocent
""",
        encoding="utf-8",
    )

    with pytest.raises(ValidationError):
        load_scenario(path)
