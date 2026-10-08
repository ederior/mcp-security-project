import pytest
import yaml
from pydantic import ValidationError

from contracts.scenario import (
    ActorIntent,
    Backend,
    DefenseMode,
    MaliciousInputSource,
    Scenario,
)


def make_attack_scenario(**overrides: object) -> Scenario:
    data: dict[str, object] = {
        "scenario_id": "ac_pi1a_baseline",
        "attack_id": "AC-PI1a",
        "attack_name": "Hidden Instructions in a Tool Result",
        "actor_intent": ActorIntent.INNOCENT,
        "actor_user_id": "user_1",
        "victim_user_id": "user_2",
        "malicious_input_source": MaliciousInputSource.TOOL_RESULT,
        "user_prompt": "Read and summarize note_4",
        "allowed_tools": ["read_note"],
        "allowed_operations": ["read"],
        "allowed_target_user_ids": ["user_1"],
        "success_signal": "unauthorized_followup_tool_executed",
        "defense_mode": DefenseMode.NONE,
        "enabled_controls": [],
        "backend": Backend.FAKE,
        "model_id": None,
        "seed": 0,
        "repetition": 1,
        "nonce": "nonce-001",
        "sampling_config": {},
        "metadata": {"note_id": "note_4"},
    }
    data.update(overrides)
    return Scenario.model_validate(data)


def test_valid_attack_scenario() -> None:
    scenario = make_attack_scenario()

    assert scenario.attack_id == "AC-PI1a"
    assert scenario.actor_user_id == "user_1"
    assert scenario.defense_mode == DefenseMode.NONE
    assert scenario.backend == Backend.FAKE


def test_json_round_trip() -> None:
    original = make_attack_scenario()

    serialized = original.model_dump_json()
    restored = Scenario.model_validate_json(serialized)

    assert restored == original


def test_yaml_round_trip() -> None:
    original = make_attack_scenario()

    serialized = yaml.safe_dump(
        original.model_dump(mode="json"),
        sort_keys=True,
    )
    loaded = yaml.safe_load(serialized)
    restored = Scenario.model_validate(loaded)

    assert restored == original


def test_valid_benign_scenario() -> None:
    scenario = Scenario(
        scenario_id="benign_read_note",
        attack_id=None,
        attack_name=None,
        actor_intent=ActorIntent.INNOCENT,
        actor_user_id="user_1",
        victim_user_id=None,
        malicious_input_source=MaliciousInputSource.NONE,
        user_prompt="Read my note",
        allowed_tools=["read_note"],
        allowed_operations=["read"],
        allowed_target_user_ids=["user_1"],
        success_signal=None,
        defense_mode=DefenseMode.DETECT,
        enabled_controls=["prompt_injection_rules_v1"],
        backend=Backend.FAKE,
        model_id=None,
        seed=0,
        repetition=1,
        nonce="nonce-benign-001",
    )

    assert scenario.attack_id is None
    assert scenario.success_signal is None


def test_unknown_field_is_rejected() -> None:
    with pytest.raises(ValidationError):
        make_attack_scenario(unknown_field=True)


def test_attack_requires_name_and_success_signal() -> None:
    with pytest.raises(ValidationError):
        make_attack_scenario(attack_name=None)


def test_benign_scenario_cannot_have_malicious_source() -> None:
    with pytest.raises(ValidationError):
        Scenario(
            scenario_id="invalid_benign",
            attack_id=None,
            attack_name=None,
            actor_intent=ActorIntent.INNOCENT,
            actor_user_id="user_1",
            victim_user_id=None,
            malicious_input_source=MaliciousInputSource.TOOL_RESULT,
            user_prompt="Read my note",
            allowed_tools=["read_note"],
            allowed_operations=["read"],
            allowed_target_user_ids=["user_1"],
            success_signal=None,
            defense_mode=DefenseMode.NONE,
            enabled_controls=[],
            backend=Backend.FAKE,
            seed=0,
            repetition=1,
            nonce="nonce-invalid",
        )


def test_gemini_requires_model_id() -> None:
    with pytest.raises(ValidationError):
        make_attack_scenario(
            backend=Backend.GEMINI,
            model_id=None,
        )


def test_none_mode_cannot_enable_controls() -> None:
    with pytest.raises(ValidationError):
        make_attack_scenario(
            defense_mode=DefenseMode.NONE,
            enabled_controls=["prompt_injection_rules_v1"],
        )


def test_detect_mode_requires_enabled_control() -> None:
    with pytest.raises(ValidationError):
        make_attack_scenario(
            defense_mode=DefenseMode.DETECT,
            enabled_controls=[],
        )


@pytest.mark.parametrize(
    "required_field",
    [
        "allowed_tools",
        "allowed_operations",
        "allowed_target_user_ids",
        "nonce",
    ],
)
def test_required_security_fields_cannot_be_omitted(
    required_field: str,
) -> None:
    scenario = make_attack_scenario()
    data = scenario.model_dump()
    data.pop(required_field)

    with pytest.raises(ValidationError):
        Scenario.model_validate(data)
