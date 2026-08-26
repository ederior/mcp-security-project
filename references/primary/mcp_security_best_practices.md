# MCP Security Best Practices

- **Original source:** https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices
- **Classification:** Primary, official MCP guidance
- **Project snapshot summarized:** 2026-06-24

## Relevant Guidance

The official guidance describes session-hijacking risks in which an attacker
reuses or obtains a session identifier and the server treats the attacker as the
original user. Recommended controls include unpredictable session identifiers,
binding each session to a user, and verifying that binding on every inbound
request. A session identifier must not be treated as authentication by itself.

The guidance also discusses credential exposure, token misuse, SSRF-related
credential access, and scope minimization. Broadly available credentials create
a larger impact when data reaches logs, memory, local interception points, or an
unauthorized downstream destination.

## Use in This Project

- Grounds AC-SH1a session-owner validation.
- Grounds AC-SH3a replay detection and rejection.
- Grounds AC-CL1a and AC-CL2a boundary scanning and scope minimization.
- Supports sanitized security events that do not create a second secret leak.

## Limits

The project implements simplified local controls around fake identities and
synthetic secrets. It does not claim production OAuth, token, or deployment
hardening.
