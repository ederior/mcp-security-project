# MCP Attack & Defense Simulator

## Project Purpose

This repository is a defensive research simulator for attacks against a local
Model Context Protocol system. It implements six harmless attack scenarios,
detectors and mitigations, and a reproducible experiment harness that compares
security outcomes under three defense modes.

The core deliverables are:

- a local instrumented MCP server and client;
- six attack scenarios across prompt injection, session hijacking, and synthetic
  credential leakage;
- deterministic detectors and mitigations;
- a Fake LLM backend for automated testing;
- manual Gemini experiment runs for model-dependent content scenarios;
- sanitized JSON/CSV artifacts, metrics, plots, and report evidence.

## Authoritative Project Documents

Read these before designing or implementing related work:

- `DECISIONS.md` — approved architectural and experimental choices;
- `docs/threat_model.md` — actors, assets, trust boundaries, and allowed attacker
  capabilities;
- `docs/experiment_plan.md` — scenarios, success signals, outcomes, sample sizes,
  metrics, events, and artifacts;
- `docs/defense_catalog.md` — detector inputs, mitigation points, reason codes,
  normal-use comparisons, and the Or-to-Noam event handoff;
- `references/README.md` and `references/primary/` — locally saved source
  summaries used during design and implementation.

Do not invent capabilities outside the threat model or silently change a success
signal, defense mode, outcome name, sample size, or event contract.

## Pinned Environment

- Python: 3.11
- Package and environment manager: `uv`
- MCP SDK: version pinned in `pyproject.toml`
- Real model backend: Gemini through `google-genai`
- Automated-test backend: deterministic Fake backend
- Tests: pytest
- Quality checks: Ruff, Black, and mypy
- Async model: `asyncio`; do not introduce threads without an approved decision

Gemini is used only for manual experiments and demonstrations. Automated tests
must not call Gemini, require an API key, or depend on network access.

## Required Commands

Use the repository environment for every command:

```text
uv sync --locked
uv run pytest
uv run ruff check .
uv run black --check .
uv run mypy src
```

After every edit, run `uv run pytest` and `uv run ruff check .`. If either fails,
stop and report the failure before making another unrelated fix. Do not hide or
silently baseline a failing quality gate.

Before merging an implementation PR, also run Black and mypy. A clean clone must
eventually pass all four gates without credentials or network access.

## Ownership and Non-Overlapping Work

### Or — target system and attacks

- `src/mcp_server/**`
- `src/mcp_client/**`
- `src/attacks/**`
- `scenarios/attacks/**`
- `tests/server/**`
- `tests/attacks/**`
- `examples/**`

Or implements persistent sessions, sanitized server/client events, the six attack
scenarios, unsafe-baseline success tests, and manual Gemini demonstrations.

### Noam — experiment laboratory and defenses

- `src/llm_backend/**`
- `src/defenses/**`
- `src/harness/**`
- `scenarios/benign/**`
- `experiments/**`
- `tests/defenses/**`
- `tests/harness/**`
- `tests/integration/**`

Noam implements the Fake backend, scenario loader, harness, detectors,
mitigations, normal-use corpus, metrics, experiments, and result analysis.

### Shared files

- `src/contracts/**`
- `tests/contracts/**`
- `DECISIONS.md`
- `docs/**`
- `README.md`
- repository configuration and CI

For shared files, use one editor and one reviewer. Do not have both partners
independently edit the same contract or shared document at the same time.

## Branch and Review Workflow

1. Work on a task-specific branch; never push directly to `main`.
2. Keep one task and one owner per branch.
3. Use a Pull Request into `main`.
4. Request the other partner's review.
5. Do not merge until the task's documented completion gate is satisfied.
6. Keep unrelated local changes out of the commit; do not use `git add .` when
   the working tree contains unrelated files.
7. Never commit, push, merge, delete a branch, or rewrite Git history
   automatically. The user performs Git mutations after reviewing the files and
   commands.

## Required Design Workflow

Before implementing a new attack or defense:

1. Confirm that it is inside `docs/threat_model.md`.
2. Add or update a `DECISIONS.md` entry explaining the threat, technique,
   motivating primary source, and measurement.
3. Present the decision to the user and wait for approval.
4. For work spanning multiple modules, write a file-level plan and expected
   behavior before editing.
5. Implement the smallest complete vertical slice.
6. Add deterministic Fake-backend tests.
7. Run the required checks before continuing.

Every new attack must include:

- a stable attack ID and readable name;
- a Scenario YAML file;
- an unsafe-baseline success test;
- a machine-readable attack-success signal;
- sanitized events required by its detector;
- an approved defense handoff.

Every new defense must include:

- a stable detector or mitigation ID and version;
- a `DetectionVerdict` with a stable reason code;
- a test proving detection or mitigation of the matching attack;
- normal-use tests and a false-positive measurement plan;
- an explicit enforcement point;
- measured latency.

## Shared Contracts Must Be Frozen First

Do not implement dependent attack, defense, or harness modules until the J2.1
contract PR defines and tests:

- `Scenario`;
- sanitized `ToolEvent`;
- `AttackResult`;
- `DetectionVerdict`;
- `RunResult`.

Contract changes require a small dedicated PR reviewed by both partners.

## Defense Modes

Use only these stable identifiers:

- `none` — no attack-specific detector or mitigation;
- `detect` — detector runs, but the original flow is not changed;
- `detect_and_mitigate` — detector runs and the relevant security control is
  enforced.

Detection does not imply blocking. A valid detection-only result may be:

```text
execution: completed
attack: succeeded
detection: detected
mitigation: not_applied
```

Do not replace the four outcome dimensions with one ambiguous `PASS` or `FAIL`.

## Approved Defense Rules

- Replay defense uses unique per-request nonces and a per-session used-nonce set.
- Scenario policy explicitly lists allowed tools, operations, and target users.
- Security events serialize only allowlisted safe evidence.
- Exact registered-canary matches may block or redact; pattern-only matches warn
  in version 1.
- Detector rules freeze before final holdout evaluation.
- The LLM judge is advisory and never the sole security boundary.
- Session impersonation and replay use deterministic protocol validators, not an
  LLM judge.

See `DECISIONS.md` and `docs/defense_catalog.md` for the full reasoning and
measurement definitions.

## Structured Events and Sanitization

Experiment outcomes must come from structured events, not by parsing prose.
Required event families include:

- `run_started`;
- `request_received`;
- `tool_requested`;
- `tool_completed`;
- `detection_evaluated`;
- `mitigation_applied`;
- `attack_signal_observed`;
- `run_completed`.

Never store raw canaries, API keys, `.env` contents, full session tokens, real
credentials, PII, or complete sensitive payloads in stdout or artifacts. Use
stable classifications, reason codes, lengths, and non-reversible fingerprints.

Every experiment run writes its full non-secret configuration, Git SHA, seed,
environment, sanitized event stream, result, and latency below
`results/<run_id>/`. Preserve `error` and `inconclusive` runs instead of retrying
until a desired result appears.

## Security and Ethics

- All attacks target only the local server in this repository.
- Payloads are harmless, clearly labeled, and based on synthetic canaries.
- Exfiltration uses only an inert local test sink.
- Never target an external service in an attack example or test.
- Never use real credentials, real PII, or real session tokens.
- Do not call Gemini from pytest.
- Do not treat quota or service failure as evidence that a defense worked.

## Do Not Touch

- `.env` and `secrets/` — user-managed credentials;
- `docs/report/` — final report text is user-managed unless the user explicitly
  asks for an edit;
- `references/snapshots/` — raw archived source copies;
- generated `results/` artifacts unless a reporting task explicitly selects a
  sanitized summary.

## Teaching Requirement

When introducing an unfamiliar Python feature such as async/await, dataclasses,
Pydantic models, context managers, generators, or pytest fixtures, explain it in
plain language before or alongside the implementation. The project should remain
understandable to both partners, not only executable.
