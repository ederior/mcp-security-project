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
