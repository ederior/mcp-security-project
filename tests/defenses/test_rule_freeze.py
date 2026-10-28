"""The detector rules are frozen (Decisions 11 and 23).

Each detector version has a recorded fingerprint of everything that decides
its verdicts: identifiers, versions, patterns, reason codes, confidence
values, and the detection code itself. If any of that changes while the
version stays the same, this test fails. To change a rule on purpose, bump
the detector's version and record the new fingerprint as a new entry;
results from the old and new versions are then never mixed.

The fingerprint ignores what cannot change a verdict: comments, formatting,
docstrings, and the plain-language REASON_EXPLANATIONS. It is computed from
Python's own parse of the code (ast), re-printed in one standard form.
"""

import ast
import hashlib
import inspect
import textwrap
from collections.abc import Callable, Sequence
from types import ModuleType

import pytest

from defenses.detection import prompt_injection, secret_scanner, session_validator
from defenses.mitigation import tool_policy
from harness.experiment import DETECTOR_IDS
from mcp_server import events

# A module, or a function whose code decides verdicts.
RuleSource = ModuleType | Callable[..., object]

# What decides each detector's verdicts. The prompt-injection policy check
# calls tool_policy.evaluate_tool_call, which uses events.infer_operation.
RULE_SOURCES: dict[tuple[str, str], Sequence[RuleSource]] = {
    (prompt_injection.DETECTOR_ID, prompt_injection.DETECTOR_VERSION): (
        prompt_injection,
        tool_policy.evaluate_tool_call,
        events.infer_operation,
    ),
    (secret_scanner.DETECTOR_ID, secret_scanner.DETECTOR_VERSION): (secret_scanner,),
    (
        session_validator.BINDING_VALIDATOR_ID,
        session_validator.VALIDATOR_VERSION,
    ): (session_validator,),
    (
        session_validator.REPLAY_VALIDATOR_ID,
        session_validator.VALIDATOR_VERSION,
    ): (session_validator,),
}

# Recorded on 28 October 2026, after the development corpus passed with zero
# false positives (Decision 23). Add an entry for a new version; never edit
# an existing one. Both session validators share one module and one version,
# so they share one fingerprint.
FROZEN: dict[tuple[str, str], str] = {
    ("prompt_injection_rules_v1", "v1"): "sha256:63f703c7683e920f",
    ("synthetic_secret_scanner_v1", "v1"): "sha256:bf692209c7fbe0e5",
    ("session_binding_validator_v1", "v1"): "sha256:3e30e55bf38a60d0",
    ("replay_validator_v1", "v1"): "sha256:3e30e55bf38a60d0",
}

_DOCUMENTED_NODES = (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)


def normalize(source: str) -> str:
    """Code in one standard form, without docstrings or reason explanations."""
    tree = ast.parse(textwrap.dedent(source))
    tree.body = [node for node in tree.body if not _is_explanations(node)]

    for node in ast.walk(tree):
        if isinstance(node, _DOCUMENTED_NODES) and _starts_with_docstring(node.body):
            node.body = node.body[1:] or [ast.Pass()]

    return ast.unparse(tree)


def rule_fingerprint(sources: Sequence[RuleSource]) -> str:
    text = "\n\n".join(normalize(inspect.getsource(source)) for source in sources)
    return f"sha256:{hashlib.sha256(text.encode('utf-8')).hexdigest()[:16]}"


def _is_explanations(node: ast.stmt) -> bool:
    targets = (
        node.targets
        if isinstance(node, ast.Assign)
        else [node.target] if isinstance(node, ast.AnnAssign) else []
    )
    return any(
        isinstance(target, ast.Name) and target.id == "REASON_EXPLANATIONS"
        for target in targets
    )


def _starts_with_docstring(body: list[ast.stmt]) -> bool:
    return bool(
        body
        and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
        and isinstance(body[0].value.value, str)
    )


# --- the freeze -------------------------------------------------------------


def test_every_detector_has_a_frozen_version() -> None:
    assert {detector_id for detector_id, _ in RULE_SOURCES} == DETECTOR_IDS
    assert set(RULE_SOURCES) <= set(FROZEN), (
        "A detector version has no recorded fingerprint. If you bumped a "
        "version on purpose, record its fingerprint in FROZEN."
    )


@pytest.mark.parametrize(
    "key", list(RULE_SOURCES), ids=lambda key: f"{key[0]}@{key[1]}"
)
def test_frozen_rules_are_unchanged(key: tuple[str, str]) -> None:
    detector_id, version = key

    assert rule_fingerprint(RULE_SOURCES[key]) == FROZEN[key], (
        f"The rules of {detector_id} changed while its version stayed {version}. "
        "Revert the change, or bump the version and record a new fingerprint "
        "(Decisions 11 and 23)."
    )


# --- the fingerprint itself -------------------------------------------------

RULE = '''
"""A detector module."""

REASON_EXPLANATIONS = {"code": "Plain-language text."}
_PATTERN = r"ignore (all )?instructions"


def inspect_text(text):
    """Return whether the text matches."""
    return _PATTERN in text
'''


def test_fingerprint_ignores_comments_docstrings_and_explanations() -> None:
    reworded = (
        RULE.replace('"""A detector module."""', '"""Reworded docstring."""')
        .replace("Plain-language text.", "Better wording.")
        .replace("    return _PATTERN", "    # A comment.\n    return  _PATTERN")
    )

    assert normalize(reworded) == normalize(RULE)


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ("(all )?instructions", "(all )?rules"),  # a pattern
        ("return _PATTERN in text", "return _PATTERN not in text"),  # the logic
    ],
)
def test_fingerprint_catches_a_rule_change(old: str, new: str) -> None:
    assert normalize(RULE.replace(old, new)) != normalize(RULE)
