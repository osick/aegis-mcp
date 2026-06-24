# ADR 002: Explicit transition graph for profile switching (no privilege tiers)

- Status: Accepted (supersedes an earlier tier-based draft)
- Date: 2026-06-16
- Cycle: 1

## Context

A profile switch (`aegis.set_profile`) must not let a prompt-injected agent grant itself
more capability. An initial design used integer **privilege tiers**: agent switches
lateral/down were autonomous, up required approval.

Tiers have a hole: two *disjoint* profiles at the same tier (e.g. `frontend-dev` with
GitHub/Jira and `db-analytics` with prod-DB read) are "lateral", so a compromised
`frontend-dev` agent could autonomously switch to `db-analytics` and exfiltrate data —
**horizontal privilege spread**, undetectable by tiers.

## Decision

Drop tiers. Each profile declares an explicit `allowed_transitions` list — the **switch
authorization graph**. An agent-initiated switch is autonomous **only** along a
pre-declared edge; every other agent switch is routed to human approval. A human
(CLI/control) may switch anywhere. Non-existent targets are denied.

## Consequences

- Defeats both vertical escalation and lateral spread: a switch is autonomous only on an
  edge the operator explicitly drew.
- One mechanism instead of two overlapping ones — less ambiguity.
- Operators must enumerate safe transitions; "unlisted ⇒ requires human approval" is the
  safe default. A future hard-`deny` edge (never even prompt) is noted in the spec's open
  questions.
- See [ADR 003](ADR_003_non_blocking_hitl.md) for how the approval itself is delivered.
