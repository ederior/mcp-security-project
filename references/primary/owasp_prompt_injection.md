# OWASP Prompt Injection

- **Original source:** https://owasp.org/www-community/attacks/PromptInjection
- **Classification:** Primary security reference
- **Project snapshot summarized:** 2026-06-24

## Relevant Guidance

OWASP distinguishes direct prompt injection, where the user supplies the
malicious instruction, from indirect prompt injection, where the instruction is
embedded in external content such as a document, webpage, or tool result. The
underlying problem is that trusted instructions and untrusted natural-language
data can look similar to a model.

Relevant defenses include separating instructions from data, delimiting and
sanitizing untrusted input, applying guardrails and output checks, and keeping
important instructions from being silently replaced by lower-authority content.

## Use in This Project

- Grounds AC-PI1a as indirect injection from a tool result.
- Grounds AC-PI2a as direct injection from a malicious user.
- Motivates `prompt_injection_rules_v1` and untrusted-content framing.
- Supports output filtering and deterministic tool authorization as layered
  protection.

## Limits

The detector is an educational, measurable implementation. It is not claimed to
identify every natural-language injection or protect every external model.
