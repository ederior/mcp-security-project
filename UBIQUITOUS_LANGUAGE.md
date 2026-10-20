# Ubiquitous Language

This glossary defines the words Noam and Or use in project discussions, pull
requests, event data, experiments, and reports. Human-facing text should use the
plain-language attack name together with the stable attack ID on first mention.

## Attack variants

| Canonical term | Stable ID | Definition | Aliases to avoid |
| --- | --- | --- | --- |
| **Hidden Instructions in a Tool Result** | AC-PI1a | Untrusted data returned by a tool contains instructions that try to cause an unauthorized follow-up action. | PI1a by itself, indirect PI |
| **User Prompt Tries to Bypass Security Rules** | AC-PI2a | A user's direct prompt asks the system to ignore policy or perform an action outside that user's authority. | PI2a by itself, direct PI |
| **One User Reuses Another User's Session** | AC-SH1a | A request claims one user identity while presenting a session bound to a different user. | SH1a by itself, impersonation |
| **The Same Request Is Accepted Twice** | AC-SH3a | A previously processed request is submitted again with the same nonce or sequence number and is processed again. | SH3a by itself, replay |
| **A Synthetic Secret Appears Where It Should Not** | AC-CL1a | A synthetic canary crosses into an output, argument, log, or artifact where it is not authorized to appear. | CL1a by itself, leak |
| **Injection Sends a Synthetic Secret to a Test Destination** | AC-CL2a | An injected instruction causes a synthetic canary to be transferred to a local inert test destination. | CL2a by itself, exfiltration |

## Actors and intent

| Term | Definition | Aliases to avoid |
| --- | --- | --- |
| **Test identity** | A neutral account identifier such as `user_1` or `user_2` whose intent is assigned separately by each scenario. | Good user, bad user |
| **Innocent user** | A person making a normal authorized request without intending to cross a security boundary. | Safe identity, good account |
| **Malicious user** | A person intentionally submitting input or metadata designed to cross a security boundary. | Bad identity, attacker account |
| **Victim user** | A person whose session or protected data is targeted by another actor or exposed by a system failure. | Innocent user when victim status matters |
| **Malicious content source** | An attacker-controlled note, document, or tool result that carries malicious instructions into an otherwise innocent user flow. | Malicious user |
| **Normal-use comparison** | A scenario in which both the human behavior and input are legitimate, used to measure false positives and accidental blocking. | Negative scenario, harmless test |

## Experiment design

| Term | Definition | Aliases to avoid |
| --- | --- | --- |
| **Scenario** | One defined security test containing its setup, trigger, defense mode, backend, and expected evidence. | Test when the full scenario is meant |
| **Experiment cell** | One unique combination of attack, defense mode, and applicable backend. | Scenario, run |
| **Run** | One execution of an experiment cell, whether completed, errored, or inconclusive. | Attempt |
| **Completed run** | A run that reached a valid security verdict. | Successful run |
| **Backend** | The component that supplies agent decisions, either the Deterministic Fake or Gemini. | Model when referring to the Fake backend |
| **Unsafe mode** | The `none` configuration in which attack-specific detection and mitigation are disabled. | No security |
| **Detection-only mode** | The `detect` configuration in which a detector records a verdict but does not block behavior. | Partial defense without qualification |
| **Full-defense mode** | The `detect_and_mitigate` configuration in which detection and the relevant prevention control are enabled. | Secure without qualification |
| **Detector** | A component that decides whether observed activity matches an attack. | Defense when only recognition occurs |
| **Mitigation** | A control that blocks, rejects, binds, or redacts to prevent a security violation. | Detection |
| **Attack-success signal** | The machine-readable event proving that the attack's defined security violation occurred. | PASS |
| **Synthetic canary** | A unique fake secret used to detect boundary crossing without exposing a real credential. | Real secret, credential |
| **Artifact** | A structured file saved as evidence of an experiment run. | Log when referring to all result files |

## Outcome vocabulary

| Term | Definition | Aliases to avoid |
| --- | --- | --- |
| **Execution status** | Whether a run completed, failed locally, or was inconclusive because of an external condition. | PASS/FAIL |
| **Attack outcome** | Whether the defined attack succeeded, was blocked, was not triggered, or did not apply. | Test result |
| **Detection outcome** | Whether the enabled detector recognized the attack. | Defense outcome |
| **Mitigation outcome** | Whether the prevention control was applied. | Detection outcome |
| **Inconclusive run** | A run that cannot produce a security verdict because of an external condition such as Gemini quota or availability. | Failed defense, blocked attack |

## Relationships

- One **experiment cell** contains multiple **runs**.
- One **scenario** belongs to one attack variant and defines one
  **attack-success signal**.
- One **scenario** assigns intent to a neutral **test identity**; the same test
  identity may be an **innocent user** in one scenario and a **malicious user** in
  another.
- An **innocent user** may participate in an attack scenario when the malicious
  input comes from a **malicious content source**.
- A **normal-use comparison** contains neither malicious user intent nor malicious
  content.
- A **completed run** has an **execution status**, **attack outcome**,
  **detection outcome**, and **mitigation outcome**.
- A **detector** can recognize an attack without a **mitigation** preventing it.
- A **normal-use comparison** is evaluated by the same detector as its matching
  attack scenario.
- A **synthetic canary** may be inspected during a run but must not be copied
  into normal artifacts.

## Example dialogue

> **Noam:** "For AC-PI1a — **Hidden Instructions in a Tool Result**, is the
> person reading `note_4` a **malicious user**?"

> **Or:** "No. The person is an **innocent user**. The attack comes from the
> **malicious content source** inside `note_4`."

> **Noam:** "So the matching **normal-use comparison** uses an innocent user and a note
> that contains no malicious instruction?"

> **Or:** "Exactly. That difference lets us test protection of innocent users
> while also measuring false positives."

## Flagged ambiguities

- `PASS` previously meant either a completed experiment, a successful attack,
  or a successful defense; use the four separate outcome fields instead.
- `run` and `attempt` were used for the same execution; use **run** for one
  execution and **experiment cell** for the repeated configuration.
- `partial defense` did not state whether it blocks; use **detection-only mode**
  when the detector records a verdict but behavior continues.
- `secret`, `fake secret`, and `canary` referred to the same safe test value; use
  **synthetic canary** in technical text.
- `prompt injection` alone does not identify whether the malicious instruction
  came from a user or tool data; use the full plain-language attack name.
- `user_1` and `user_2` were easy to misread as permanent good and bad roles;
  treat them as neutral **test identities** and record intent per scenario.
- `innocent user scenario` could mean either an innocent victim exposed to
  malicious content or a fully normal control; use **innocent user** for the
  person and reserve **normal-use comparison** for runs containing no malicious
  user intent and no malicious content.
