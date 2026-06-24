# ADR 003: Non-blocking human-in-the-loop approval

- Status: Accepted
- Date: 2026-06-16
- Cycle: 1

## Context

When an agent requests a profile switch that isn't a pre-declared edge ([ADR 002](ADR_002_transition_graph_not_tiers.md)),
a human must approve it. A blocking design would hold the `set_profile` JSON-RPC call
open until the human responds — but if the developer is away, the host/agent framework
(LangGraph, etc.) hits its own timeout, risking cascading failures, broken idempotency,
or deadlock.

## Decision

Approval is **non-blocking**. On a switch needing approval, Aegis returns immediately with
the structured error `AEGIS_PENDING_APPROVAL` plus an `approval_id`, and notifies the human
out-of-band (terminal channel in Cycle 1; pluggable interface for Slack/etc. later). The
agent framework preserves state and later re-issues `set_profile` (idempotent) or polls
`aegis.approval_status(approval_id)`.

Approvals are **single-use** and **bound to the originating profile**: a granted ticket is
consumed on application and only applies if the active profile still matches the one it was
requested from — so a stale approval cannot be replayed to re-elevate later, nor applied in
a different context.

## Consequences

- No held connections, no host/framework deadlock.
- The agent can never satisfy its own escalation; the human decision happens out-of-band.
- The approval store tracks `pending → approved/denied → applied` and never lets the agent
  mark its own request approved.
- A timed-expiry default remains an open question (spec §10); single-use + context-binding
  already prevent the replay risk that expiry would address.
