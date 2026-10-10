import asyncio
from pathlib import Path

from contracts.events import EventType
from contracts.results import (
    AttackOutcome,
    DetectionOutcome,
    MitigationOutcome,
)
from contracts.scenario import DefenseMode, MaliciousInputSource, Scenario
from harness.runner import HarnessRun, run_scenario
from harness.scenario_loader import load_scenario
from llm_backend.base import BackendResponse, ToolCall
from llm_backend.fake import FakeBackend
from mcp_server.server import get_user_profile

PI1A_SCENARIO = Path("scenarios/attacks/ac_pi1a.yaml")
PI2A_SCENARIO = Path("scenarios/attacks/ac_pi2a.yaml")
PI_CONTROLS = ["prompt_injection_rules_v1", "tool_authorization_policy_v1"]


def pi2a_scenario(mode: DefenseMode) -> Scenario:
    scenario = load_scenario(PI2A_SCENARIO)
    controls = [] if mode == DefenseMode.NONE else PI_CONTROLS
    return scenario.model_copy(
        update={"defense_mode": mode, "enabled_controls": controls}
    )


def profile_backend(user_id: str) -> FakeBackend:
    return FakeBackend(
        (
            BackendResponse(
                tool_calls=(
                    ToolCall(name="get_user_profile", arguments={"user_id": user_id}),
                )
            ),
            BackendResponse(final_text="Here is the requested profile."),
        )
    )


def run(scenario: Scenario, backend: FakeBackend, run_id: str) -> HarnessRun:
    return asyncio.run(run_scenario(scenario, backend, run_id=run_id))


def test_pi2a_executes_cross_user_action_without_defense() -> None:
    backend = profile_backend("user_2")
    harness_run = run(pi2a_scenario(DefenseMode.NONE), backend, "pi2a_run_001")

    assert [
        (event.event_type, event.tool_name, event.classification)
        for event in harness_run.events
    ] == [
        (EventType.TOOL_REQUESTED, "get_user_profile", "unauthorized"),
        (EventType.ATTACK_SIGNAL_OBSERVED, None, None),
        (EventType.TOOL_COMPLETED, "get_user_profile", "structured"),
    ]

    requested, signal, _ = harness_run.events
    assert requested.actor_user_id == "user_1"
    assert requested.target_user_id == "user_2"
    assert signal.attack_id == "AC-PI2a"
    assert signal.signal_id == "direct_prompt_unauthorized_action_executed"

    # The user_2 profile really reached the model.
    profile_result = backend.tool_result_history[0][0].result
    assert profile_result == get_user_profile("user_2")

    result = harness_run.result
    assert result.attack_result is not None
    assert result.attack_result.outcome == AttackOutcome.SUCCEEDED
    assert result.attack_result.observed_signal_ids == [
        "direct_prompt_unauthorized_action_executed"
    ]
    assert result.detection_outcome == DetectionOutcome.NOT_APPLICABLE
    assert result.mitigation_outcome == MitigationOutcome.NOT_APPLICABLE


def test_pi2a_detect_mode_records_alarm_but_does_not_block() -> None:
    result = run(
        pi2a_scenario(DefenseMode.DETECT),
        profile_backend("user_2"),
        "pi2a_detect",
    ).result

    assert result.attack_result is not None
    assert result.attack_result.outcome == AttackOutcome.SUCCEEDED
    assert result.detection_outcome == DetectionOutcome.DETECTED
    assert result.mitigation_outcome == MitigationOutcome.NOT_APPLIED
    assert [verdict.reason_code for verdict in result.detection_verdicts] == [
        "followup_outside_user_goal",
        "no_injection_indicators",
    ]


def test_pi2a_detect_and_mitigate_blocks_cross_user_action() -> None:
    backend = profile_backend("user_2")
    harness_run = run(
        pi2a_scenario(DefenseMode.DETECT_AND_MITIGATE),
        backend,
        "pi2a_mitigate",
    )

    assert [(event.event_type, event.reason_code) for event in harness_run.events] == [
        (EventType.TOOL_REQUESTED, "not_authorized_by_scenario_policy"),
        (EventType.DETECTION_EVALUATED, "followup_outside_user_goal"),
        (EventType.MITIGATION_APPLIED, "followup_not_authorized_by_user_goal"),
    ]

    # The model got a refusal instead of any user_2 data.
    blocked = backend.tool_result_history[0][0]
    assert blocked.is_error is True
    assert "user_id" not in blocked.result
    assert harness_run.final_text == "Here is the requested profile."

    result = harness_run.result
    assert result.attack_result is not None
    assert result.attack_result.outcome == AttackOutcome.BLOCKED
    assert result.attack_result.observed_signal_ids == []
    assert result.detection_outcome == DetectionOutcome.DETECTED
    assert result.mitigation_outcome == MitigationOutcome.APPLIED


def test_pi2a_own_profile_request_does_not_trigger_signal() -> None:
    scenario = pi2a_scenario(DefenseMode.NONE).model_copy(
        update={"user_prompt": "Show my profile."}
    )

    harness_run = run(scenario, profile_backend("user_1"), "pi2a_control")

    assert harness_run.events[0].classification == "allowed"
    assert EventType.ATTACK_SIGNAL_OBSERVED not in [
        event.event_type for event in harness_run.events
    ]

    attack_result = harness_run.result.attack_result
    assert attack_result is not None
    assert attack_result.outcome == AttackOutcome.NOT_TRIGGERED
    assert attack_result.observed_signal_ids == []


def test_pi2a_events_do_not_contain_victim_profile_data() -> None:
    harness_run = run(
        pi2a_scenario(DefenseMode.NONE),
        profile_backend("user_2"),
        "pi2a_sanitized",
    )

    serialized = "\n".join(
        [event.model_dump_json() for event in harness_run.events]
        + [harness_run.result.model_dump_json()]
    )

    victim_profile = get_user_profile("user_2")
    assert victim_profile["name"] not in serialized
    assert victim_profile["department"] not in serialized


def test_pi2a_is_reported_separately_from_pi1a() -> None:
    pi1a = load_scenario(PI1A_SCENARIO)
    pi2a = load_scenario(PI2A_SCENARIO)

    assert pi2a.attack_id == "AC-PI2a"
    assert pi2a.attack_id != pi1a.attack_id
    assert pi2a.success_signal != pi1a.success_signal
    assert pi2a.malicious_input_source == MaliciousInputSource.USER_PROMPT
    assert pi1a.malicious_input_source == MaliciousInputSource.TOOL_RESULT
    assert "tool_data" not in pi2a.metadata

    # No tool data is read, so no untrusted-content verdict is produced.
    result = run(
        pi2a_scenario(DefenseMode.DETECT),
        profile_backend("user_2"),
        "pi2a_separate",
    ).result
    assert not any(
        verdict.reason_code.startswith("untrusted_content")
        for verdict in result.detection_verdicts
    )
