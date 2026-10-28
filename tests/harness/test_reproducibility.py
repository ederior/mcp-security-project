"""The same scenario and seed give identical normalized results (§7.1).

Twenty repetitions of one scenario are a stability check, not twenty
independent observations. Normalizing removes only the values that must
differ between runs: the run ID and measured latencies.
"""

import asyncio
from pathlib import Path
from typing import Any

import pytest

from contracts.scenario import DefenseMode, Scenario
from harness.dispatch import fake_script_factory, run_one, with_defense_mode
from harness.runner import HarnessRun
from harness.scenario_loader import load_scenario
from llm_backend.base import BackendResponse, LLMBackend, ToolCall
from llm_backend.fake import FakeBackend

REPETITIONS = 20
FAKE_SCRIPTS = fake_script_factory(Path("experiments/fake_scripts"))
VOLATILE_KEYS = frozenset(
    {
        "run_id",
        "latency_ms",
        "total_latency_ms",
        "backend_latency_ms",
        "detection_latency_ms",
        "mitigation_latency_ms",
    }
)


def smoke_backend(scenario: Scenario) -> tuple[LLMBackend, str | None]:
    return (
        FakeBackend(
            (
                BackendResponse(tool_calls=(ToolCall(name="health_check"),)),
                BackendResponse(final_text="Server is healthy"),
            )
        ),
        None,
    )


def normalize(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: normalize(item)
            for key, item in value.items()
            if key not in VOLATILE_KEYS
        }

    if isinstance(value, list):
        return [normalize(item) for item in value]

    return value


def normalized(harness_run: HarnessRun) -> Any:
    return normalize(
        {
            "result": harness_run.result.model_dump(mode="json"),
            "events": [event.model_dump(mode="json") for event in harness_run.events],
            "final_text": harness_run.final_text,
        }
    )


CASES = {
    "smoke": (
        load_scenario(Path("scenarios/benign/smoke.yaml")),
        smoke_backend,
    ),
    "pi1a_detect_and_mitigate": (
        with_defense_mode(
            load_scenario(Path("scenarios/attacks/ac_pi1a.yaml")),
            DefenseMode.DETECT_AND_MITIGATE,
            ["prompt_injection_rules_v1", "tool_authorization_policy_v1"],
        ),
        FAKE_SCRIPTS,
    ),
    "sh3a_detect_and_mitigate": (
        with_defense_mode(
            load_scenario(Path("scenarios/attacks/ac_sh3a.yaml")),
            DefenseMode.DETECT_AND_MITIGATE,
            ["session_binding_validator_v1", "replay_validator_v1"],
        ),
        FAKE_SCRIPTS,
    ),
}


@pytest.mark.parametrize("case_id", list(CASES))
def test_twenty_repetitions_give_identical_normalized_results(case_id: str) -> None:
    scenario, factory = CASES[case_id]

    results = [
        normalized(
            asyncio.run(
                run_one(scenario, run_id=f"{case_id}_{index}", backend_factory=factory)
            )
        )
        for index in range(REPETITIONS)
    ]

    assert all(result == results[0] for result in results)
    assert results[0]["result"]["execution_status"] == "completed"
