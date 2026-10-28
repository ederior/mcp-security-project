"""One entry point that runs any attack scenario in any defense mode.

``run_one`` routes on ``attack_id`` to the existing attack runner, turns any
failure into an ``error`` or ``inconclusive`` RunResult instead of raising,
and writes the run artifacts (Decision 22).
"""

from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from time import perf_counter

from attacks.credential_leakage.cl1a import run_cl1a
from attacks.credential_leakage.cl2a import run_cl2a
from attacks.credential_leakage.local_sink import LocalExfiltrationSink
from attacks.session_hijack.sh1a import run_sh1a
from attacks.session_hijack.sh3a import run_sh3a
from contracts.results import ExecutionStatus, RunResult
from contracts.scenario import DefenseMode, Scenario
from harness.artifacts import write_run_artifacts, write_run_metadata
from harness.runner import HarnessRun, ToolRoundLimitExceeded, run_scenario
from llm_backend.base import BackendUnavailable, LLMBackend
from llm_backend.fake import FakeScriptError, load_fake_script

# Returns the backend for one run and the identifier of the script it plays,
# or None for a backend without a script. Called once per run.
BackendFactory = Callable[[Scenario], tuple[LLMBackend, str | None]]

# Protocol attacks: their runners never call a model (Decision 22).
MODEL_FREE_ATTACKS = frozenset({"AC-SH1a", "AC-SH3a"})

# Attack modules that write their own artifacts, because AC-CL1a scans the
# artifact boundary before writing (Decision 20).
SELF_WRITING_ATTACKS = frozenset({"AC-CL1a", "AC-CL2a"})

PROMPT_INJECTION_ATTACKS = frozenset({"AC-PI1a", "AC-PI2a"})

# Reason codes for runs that did not complete (Decision 22).
CONFIGURATION_ERROR = "configuration_error"
TOOL_ROUND_LIMIT_EXCEEDED = "tool_round_limit_exceeded"
UNEXPECTED_ERROR = "unexpected_error"
BACKEND_UNAVAILABLE = "backend_unavailable"


def fake_script_factory(script_dir: Path) -> BackendFactory:
    """Backend factory that plays ``script_dir/<scenario_id>.yaml``."""

    def factory(scenario: Scenario) -> tuple[LLMBackend, str | None]:
        path = script_dir / f"{scenario.scenario_id}.yaml"

        if not path.is_file():
            # A missing script is a setup mistake: a configuration error.
            raise FakeScriptError(f"No Fake script for {scenario.scenario_id}")

        script = load_fake_script(path)

        if script.scenario_id != scenario.scenario_id:
            raise FakeScriptError(
                f"Fake script {script.script_id} is for another scenario"
            )

        return script.make_backend(), script.script_id

    return factory


def with_defense_mode(
    scenario: Scenario,
    mode: DefenseMode,
    controls: Sequence[str],
    *,
    seed: int | None = None,
    repetition: int | None = None,
) -> Scenario:
    """Copy a scenario into another defense mode and validate the copy again.

    ``controls`` are the attack family's controls; the ``none`` mode always
    gets an empty list. The existing runners decide what each mode enforces.
    """
    updates: dict[str, object] = {
        "defense_mode": mode,
        "enabled_controls": [] if mode == DefenseMode.NONE else list(controls),
    }

    if seed is not None:
        updates["seed"] = seed

    if repetition is not None:
        updates["repetition"] = repetition

    # model_copy would skip the Scenario checks; model_validate runs them.
    return Scenario.model_validate({**scenario.model_dump(), **updates})


def classify_failure(error: Exception) -> tuple[ExecutionStatus, str]:
    """Map an exception to an execution status and a stable reason code."""
    if isinstance(error, BackendUnavailable):
        return ExecutionStatus.INCONCLUSIVE, BACKEND_UNAVAILABLE

    if isinstance(error, ToolRoundLimitExceeded):
        return ExecutionStatus.ERROR, TOOL_ROUND_LIMIT_EXCEEDED

    # Pydantic validation errors and FakeScriptError are ValueErrors too.
    if isinstance(error, (ValueError, TypeError)):
        return ExecutionStatus.ERROR, CONFIGURATION_ERROR

    return ExecutionStatus.ERROR, UNEXPECTED_ERROR


async def run_one(
    scenario: Scenario,
    *,
    run_id: str,
    backend_factory: BackendFactory,
    artifact_dir: Path | None = None,
    git_sha: str | None = None,
    started_at: datetime | None = None,
) -> HarnessRun:
    """Run one scenario and return its result; never raises for a failed run.

    With ``artifact_dir`` the four run files are written below
    ``artifact_dir/<run_id>/``. A run directory that already exists raises
    FileExistsError before anything runs, because it is a batch setup mistake,
    not a run failure. Exception messages are never stored or printed.
    """
    if artifact_dir is not None and git_sha is None:
        raise ValueError("git_sha is required when artifact_dir is set")

    if artifact_dir is not None and (artifact_dir / run_id).exists():
        raise FileExistsError(f"Run directory already exists: {artifact_dir / run_id}")

    started_at = started_at or datetime.now(UTC)
    total_started = perf_counter()
    fake_script_id: str | None = None

    try:
        backend: LLMBackend | None = None

        if scenario.attack_id not in MODEL_FREE_ATTACKS:
            backend, fake_script_id = backend_factory(scenario)

        harness_run = await _execute(
            scenario,
            backend,
            run_id=run_id,
            artifact_dir=artifact_dir,
            git_sha=git_sha,
        )
    except Exception as error:  # noqa: BLE001 - every failure becomes a result
        status, reason_code = classify_failure(error)
        harness_run = HarnessRun(
            result=RunResult(
                run_id=run_id,
                scenario_id=scenario.scenario_id,
                execution_status=status,
                total_latency_ms=(perf_counter() - total_started) * 1000.0,
                error_reason_code=reason_code,
            ),
            events=(),
            final_text="",
        )

    if artifact_dir is not None:
        assert git_sha is not None
        run_dir = artifact_dir / run_id

        if scenario.attack_id in SELF_WRITING_ATTACKS and run_dir.exists():
            # The attack module already wrote the run; add the setup fields
            # it does not know about.
            write_run_metadata(
                run_dir,
                scenario,
                git_sha=git_sha,
                started_at=started_at,
                fake_script_id=fake_script_id,
            )
        else:
            write_run_artifacts(
                harness_run,
                scenario,
                output_dir=artifact_dir,
                git_sha=git_sha,
                started_at=started_at,
                fake_script_id=fake_script_id,
            )

    return harness_run


async def _execute(
    scenario: Scenario,
    backend: LLMBackend | None,
    *,
    run_id: str,
    artifact_dir: Path | None,
    git_sha: str | None,
) -> HarnessRun:
    """Route one scenario to the runner of its attack."""
    attack_id = scenario.attack_id

    if attack_id == "AC-SH1a":
        result, events = run_sh1a(scenario, run_id=run_id)
        return HarnessRun(result=result, events=events, final_text="")

    if attack_id == "AC-SH3a":
        result, events = run_sh3a(scenario, run_id=run_id)
        return HarnessRun(result=result, events=events, final_text="")

    if backend is None:
        raise ValueError(f"Attack {attack_id} needs a model backend")

    if attack_id == "AC-CL1a":
        return await run_cl1a(
            scenario,
            backend,
            run_id=run_id,
            artifact_dir=artifact_dir,
            git_sha=git_sha,
        )

    if attack_id == "AC-CL2a":
        sink = LocalExfiltrationSink()

        try:
            return await run_cl2a(
                scenario,
                backend,
                sink,
                run_id=run_id,
                artifact_dir=artifact_dir,
                git_sha=git_sha,
            )
        finally:
            sink.clear()

    # Normal-use scenarios have no attack_id; only the prompt-injection
    # family supports them so far (Decision 22, scope limits).
    if attack_id is None or attack_id in PROMPT_INJECTION_ATTACKS:
        return await run_scenario(scenario, backend, run_id=run_id)

    raise ValueError(f"No runner for attack_id {attack_id}")
