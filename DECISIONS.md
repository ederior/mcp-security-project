# Project Decisions

## 1. Core Attack Variants

The six core attack variants used throughout the project are:

- PI1a
- PI2a
- SH1a
- SH3a
- CL1a
- CL2a

These variants will be used as the fixed baseline for implementation,
experiments, testing, and evaluation.

## 2. LLM Backend Strategy

Gemini will remain the real LLM backend used for manual demonstrations
and experiments.

Automated tests must not depend on Gemini or any external LLM API.

Instead, automated tests will use a deterministic Fake backend.

Reasons:
- reproducible tests
- no API quota dependency
- no network dependency
- deterministic CI behavior
- faster tests

## 3. Request / Session Metadata

The system will explicitly track:

- user_id
- session_id
- sequence number / nonce

These fields will later be used to test isolation and cross-session
security properties.

## 4. Canary Format

A synthetic canary value will be used when testing whether sensitive
information is leaked.

The canary must:
- contain no real secret
- be unique enough to detect leakage
- be easy to identify in logs and test results

Example format:

CANARY_<session_id>_<random-token>

## 5. Defense Modes

The project will support three defense configurations:

1. Unsafe / Baseline
2. Partial Defense
3. Secure / Full Defense

The exact controls enabled in each mode will be documented as the
implementation evolves.

## 6. Threat Count

The threat model contains 15 threats.

Any previous documentation referring to 14 threats should be updated
to 15.

## 7. Replay Protection Uses Per-Session Nonces

**Decision:** Every protected request carries a unique nonce. The server keeps a
used-nonce set for each session and treats reuse of the same nonce as a replay.
Monotonic sequence numbers may be evaluated later but are not required for the
core AC-SH3a scenario.

**Threat and technique:** AC-SH3a copies a previously accepted request. The
`replay_validator_v1` detector checks whether its nonce was already accepted, and
full defense rejects a duplicate before tool execution.

**Primary source:** MCP Security Best Practices, session hijacking guidance.

**Measurement:** duplicate detection rate, replay block rate, false-positive rate
on distinct legitimate nonces, and validator latency.

## 8. Scenario Files Contain Explicit Authorization Policy

**Decision:** `Scenario` contains explicit `allowed_tools`,
`allowed_operations`, and `allowed_target_user_ids`. Security controls read these
fields rather than asking an LLM to infer permissions from natural-language
prompts.

**Threat and technique:** AC-PI1a and AC-PI2a attempt to create an unauthorized
tool action. `tool_authorization_policy_v1` compares each proposed tool call and
target with the frozen scenario policy immediately before execution.

**Primary source:** OWASP Prompt Injection guidance on separating instructions
from untrusted data and applying guardrails; MCP Security Best Practices on
explicit server-side verification.

**Measurement:** unauthorized-tool block rate, attack success rate by defense
mode, false-positive rate on authorized tools, and policy-check latency.

## 9. Security Events Use a Safe Evidence Whitelist

**Decision:** Structured events store only approved fields such as stable IDs,
classifications, tool names, reason codes, lengths, and non-reversible
fingerprints. They never store a raw canary, full session identifier, complete
sensitive prompt, `.env` value, or private tool result.

**Threat and technique:** Credential-leakage scenarios must remain observable
without causing a second leak through logs. `ToolEvent` and `DetectionVerdict`
therefore use an allowlisted serialization contract.

**Primary source:** MCP Security Best Practices, scope-minimization and leakage
guidance.

**Measurement:** serialization tests scan stdout and artifacts for raw synthetic
secrets while confirming that every run still contains enough evidence to derive
its verdict.

## 10. Exact Canary Matches Block; Pattern-Only Matches Warn

**Decision:** An exact match against the run's registered synthetic canary is
high-confidence evidence and may trigger redaction or blocking. A general
secret-like pattern produces a detection verdict but does not block in version 1.

**Threat and technique:** AC-CL1a and AC-CL2a place a known fake secret at a
protected boundary. `synthetic_secret_scanner_v1` distinguishes exact registered
matches from weak pattern matches so innocent identifiers are not automatically
blocked.

**Primary source:** MCP Security Best Practices on credential exposure and scope
minimization.

**Measurement:** exact-canary detection and block rate, pattern-only
false-positive rate, leak rate, and scanning/redaction latency.

## 11. Detector Rules Freeze Before Final Evaluation

**Decision:** Detector rules are tuned only with development fixtures. Final FPR
and detection fixtures are held out. `prompt_injection_rules_v1` is frozen before
the final holdout is opened; later logic changes require a new version.

**Threat and technique:** Prompt-injection wording varies, so deterministic rules
must be evaluated without being tuned on the same examples used for the final
result.

**Primary source:** OWASP Prompt Injection provides the direct/indirect taxonomy
and defensive principles. The train/holdout separation is an experiment-control
decision for this project.

**Measurement:** per-version detection rate, FNR, FPR, attack success rate, and
latency on development and final-holdout sets reported separately.

## 12. The LLM Judge Is Advisory in Version 1

**Decision:** `content_llm_judge_v1` is a separate secondary detector for content
attacks. It never acts as the only blocker and is never authoritative for session
binding, replay, tool authorization, or exact secret boundaries. Unit tests use a
Fake judge; Gemini judge runs are manual experiments.

**Threat and technique:** An LLM judge may recognize wording missed by simple
rules, but its output can vary or become unavailable. Deterministic policies
remain the safety boundary while judge quality is measured independently.

**Primary source:** OWASP Prompt Injection motivates content-oriented guardrails;
this project's backend and reproducibility decisions require deterministic core
controls.

**Measurement:** judge detection rate, FNR, FPR, latency, inconclusive rate, and
agreement with `prompt_injection_rules_v1`.
