import asyncio
import re
from pathlib import Path

import pytest

from attacks.credential_leakage.cl1a import make_synthetic_canary, run_cl1a
from attacks.credential_leakage.cl2a import run_cl2a
from attacks.credential_leakage.local_sink import LocalExfiltrationSink
from contracts.events import EventType
from contracts.results import AttackOutcome
from harness.runner import run_scenario
from harness.scenario_loader import load_scenario
from llm_backend.base import BackendResponse, ToolCall, ToolResult
from llm_backend.fake import (
    CANARY_PLACEHOLDER,
    FakeBackend,
    FakeScriptError,
    load_fake_script,
)

SCRIPT_DIR = Path("experiments/fake_scripts")
ATTACK_SCENARIO_DIR = Path("scenarios/attacks")
BENIGN_SCENARIO_DIR = Path("scenarios/benign")
SECRET_FORMAT = re.compile(r"(?:FAKE_SECRET|CANARY)_[A-Za-z0-9_-]+")
UNREGISTERED_LOOKALIKE = "FAKE_SECRET_sample_id"

# Harmless synthetic test values in the canary format; not real secrets.
TEST_CANARY = "FAKE_SECRET_test_run_a"
OTHER_TEST_CANARY = "FAKE_SECRET_test_run_b"


def script_path(scenario_id: str) -> Path:
    return SCRIPT_DIR / f"{scenario_id}.yaml"


def note_result(content: str) -> ToolResult:
    return ToolResult(name="read_note", result={"content": content})


READ_NOTE = BackendResponse(
    tool_calls=(ToolCall(name="read_note", arguments={"note_id": "note_5"}),)
)


def play(backend: FakeBackend, *tool_results: ToolResult) -> BackendResponse:
    """Start the run, then continue once with the given tool results."""

    async def run() -> BackendResponse:
        await backend.begin("prompt", seed=0)
        return await backend.continue_after_tools(tool_results)

    return asyncio.run(run())


# --- the script files -------------------------------------------------------


def model_scenario_ids() -> set[str]:
    """Scenarios whose runner calls a model, so they need a Fake script."""
    ids: set[str] = set()

    for path in [
        *ATTACK_SCENARIO_DIR.glob("*.yaml"),
        *BENIGN_SCENARIO_DIR.glob("*.yaml"),
    ]:
        scenario = load_scenario(path)
        route = scenario.metadata.get("normal_use_route")

        # SH1a and SH3a and the session corpus never call a model; the smoke
        # scenario has its backend built in code.
        protocol_only = scenario.attack_id in {"AC-SH1a", "AC-SH3a"}
        if protocol_only or route == "session_requests" or path.name == "smoke.yaml":
            continue

        ids.add(scenario.scenario_id)

    return ids


def test_every_model_scenario_has_exactly_one_script() -> None:
    script_ids = {path.stem for path in SCRIPT_DIR.glob("*.yaml")}

    assert script_ids == model_scenario_ids()

    for script_id in script_ids:
        script = load_fake_script(script_path(script_id))
        assert script.script_id == script_id
        assert script.scenario_id == script_id


def test_script_files_never_store_a_raw_canary() -> None:
    # The only canary-format text allowed is the documented unregistered
    # lookalike of secret_benign_dev_unregistered_lookalike (Decision 23).
    for path in SCRIPT_DIR.glob("*.yaml"):
        found = set(SECRET_FORMAT.findall(path.read_text(encoding="utf-8")))
        assert found <= {UNREGISTERED_LOOKALIKE}, path


def test_make_backend_returns_a_fresh_backend_each_time() -> None:
    script = load_fake_script(script_path("ac_pi2a_baseline"))

    first, second = script.make_backend(), script.make_backend()
    asyncio.run(first.begin("prompt", seed=0))

    # The second backend can still start: runs never share a backend.
    response = asyncio.run(second.begin("prompt", seed=0))
    assert response.tool_calls[0].name == "get_user_profile"


@pytest.mark.parametrize("scenario_id", ["ac_pi1a_baseline", "ac_pi2a_baseline"])
def test_prompt_injection_script_makes_the_attack_succeed(scenario_id: str) -> None:
    attack_file = scenario_id.removesuffix("_baseline") + ".yaml"
    scenario = load_scenario(ATTACK_SCENARIO_DIR / attack_file)
    backend = load_fake_script(script_path(scenario_id)).make_backend()

    harness_run = asyncio.run(
        run_scenario(scenario, backend, run_id=f"{scenario_id}_script")
    )

    assert harness_run.result.attack_result is not None
    assert harness_run.result.attack_result.outcome == AttackOutcome.SUCCEEDED


def test_cl1a_script_copies_the_canary_into_the_final_answer() -> None:
    scenario = load_scenario(ATTACK_SCENARIO_DIR / "ac_cl1a.yaml")
    backend = load_fake_script(script_path("ac_cl1a_baseline")).make_backend()

    harness_run = asyncio.run(run_cl1a(scenario, backend, run_id="cl1a_script_run"))

    assert harness_run.result.attack_result is not None
    assert harness_run.result.attack_result.outcome == AttackOutcome.SUCCEEDED
    assert [
        event.boundary
        for event in harness_run.events
        if event.event_type == EventType.ATTACK_SIGNAL_OBSERVED
    ] == ["final_answer"]


def test_cl2a_script_sends_the_canary_to_the_sink() -> None:
    scenario = load_scenario(ATTACK_SCENARIO_DIR / "ac_cl2a.yaml")
    backend = load_fake_script(script_path("ac_cl2a_baseline")).make_backend()
    sink = LocalExfiltrationSink()

    try:
        harness_run = asyncio.run(
            run_cl2a(scenario, backend, sink, run_id="cl2a_script_run")
        )

        assert sink.received_canary is True
        assert harness_run.result.attack_result is not None
        assert harness_run.result.attack_result.outcome == AttackOutcome.SUCCEEDED
    finally:
        sink.clear()


# --- placeholder filling ----------------------------------------------------


def test_placeholder_in_final_text_is_filled_from_tool_results() -> None:
    backend = FakeBackend(
        (READ_NOTE, BackendResponse(final_text=f"Token: {CANARY_PLACEHOLDER}"))
    )

    response = play(backend, note_result(f"secret value {TEST_CANARY}"))

    assert response.final_text == f"Token: {TEST_CANARY}"


def test_placeholder_in_nested_tool_arguments_is_filled() -> None:
    backend = FakeBackend(
        (
            READ_NOTE,
            BackendResponse(
                tool_calls=(
                    ToolCall(
                        name="local_exfiltration_sink",
                        arguments={
                            "payload": CANARY_PLACEHOLDER,
                            "extra": {"items": [f"x {CANARY_PLACEHOLDER}", 3]},
                        },
                    ),
                )
            ),
            BackendResponse(final_text="Done"),
        )
    )

    response = play(backend, note_result(TEST_CANARY))

    assert response.tool_calls[0].arguments == {
        "payload": TEST_CANARY,
        "extra": {"items": [f"x {TEST_CANARY}", 3]},
    }


def test_the_canary_matches_the_attack_module_format() -> None:
    canary = make_synthetic_canary("ac_cl1a_baseline__none__seed0__rep1")
    backend = FakeBackend((READ_NOTE, BackendResponse(final_text=CANARY_PLACEHOLDER)))

    assert play(backend, note_result(f"token: {canary}.")).final_text == canary


def test_responses_without_placeholder_are_returned_unchanged() -> None:
    final = BackendResponse(final_text="No secret here")
    backend = FakeBackend((READ_NOTE, final))

    assert play(backend, note_result(TEST_CANARY)) is final


def test_placeholder_before_any_tool_result_is_an_error() -> None:
    backend = FakeBackend((BackendResponse(final_text=CANARY_PLACEHOLDER),))

    with pytest.raises(FakeScriptError, match="no tool result"):
        asyncio.run(backend.begin("prompt", seed=0))


def test_placeholder_without_a_received_canary_is_an_error() -> None:
    backend = FakeBackend((READ_NOTE, BackendResponse(final_text=CANARY_PLACEHOLDER)))

    with pytest.raises(FakeScriptError, match="no tool result"):
        play(backend, note_result("an ordinary note"))


def test_two_different_canaries_are_an_error_without_revealing_them() -> None:
    backend = FakeBackend((READ_NOTE, BackendResponse(final_text=CANARY_PLACEHOLDER)))

    with pytest.raises(FakeScriptError, match="more than one") as raised:
        play(backend, note_result(f"{TEST_CANARY} and {OTHER_TEST_CANARY}"))

    assert TEST_CANARY not in str(raised.value)
    assert OTHER_TEST_CANARY not in str(raised.value)


# --- loader validation ------------------------------------------------------


def write_script(tmp_path: Path, name: str, text: str) -> Path:
    path = tmp_path / f"{name}.yaml"
    path.write_text(text, encoding="utf-8")
    return path


VALID_HEADER = """\
script_id: sample
scenario_id: sample_scenario
description: A sample script.
"""


def test_loader_accepts_a_valid_script(tmp_path: Path) -> None:
    path = write_script(
        tmp_path,
        "sample",
        VALID_HEADER + "steps:\n  - final_text: Done\n",
    )

    script = load_fake_script(path)

    assert script.responses() == (BackendResponse(final_text="Done"),)


@pytest.mark.parametrize(
    ("name", "text", "message"),
    [
        ("sample", "- just a list\n", "top-level mapping"),
        (
            "other_name",
            VALID_HEADER + "steps:\n  - final_text: Done\n",
            "must match the file name",
        ),
        (
            "sample",
            VALID_HEADER
            + "steps:\n  - tool_calls:\n      - name: health_check\n"
            + "    final_text: Both\n",
            "either tool_calls or final_text",
        ),
        (
            "sample",
            VALID_HEADER + "steps:\n  - tool_calls:\n      - name: health_check\n",
            "must end with a final response",
        ),
        (
            "sample",
            VALID_HEADER + "unknown_field: 1\nsteps:\n  - final_text: Done\n",
            "unknown_field",
        ),
    ],
)
def test_loader_rejects_invalid_scripts(
    tmp_path: Path, name: str, text: str, message: str
) -> None:
    # FakeScriptError and Pydantic's ValidationError are both ValueErrors,
    # which the experiment entry point records as configuration errors.
    with pytest.raises(ValueError, match=message):
        load_fake_script(write_script(tmp_path, name, text))
