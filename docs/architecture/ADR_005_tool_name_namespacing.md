# ADR 005: Tool-name namespacing to prevent shadowing

- Status: Accepted
- Date: 2026-06-16
- Cycle: 1

## Context

In a 1:N aggregator ([ADR 001](ADR_001_aggregating_proxy_topology.md)), two downstream
servers can expose the same tool name (`search`), and a malicious/compromised server can
deliberately register a legitimate tool's name to redirect the agent (tool shadowing /
poisoning). Passing downstream names through 1:1 makes the host unable to tell which
server a tool belongs to.

## Decision

Aegis never surfaces downstream tool names 1:1. Each tool is presented upward under a
namespaced wire name `"<server>__<tool>"` (e.g. `github__search`) and mapped back to
`server.tool` internally on `tools/call`.

- Separator is `__` (double underscore); `.` is invalid in MCP tool names
  (`^[a-zA-Z0-9_-]+$`), so `server.tool` stays an internal-only identifier.
- Registration detects collisions: a duplicate `(server,tool)` **and** two distinct pairs
  that produce the same wire string (e.g. `("a","b__c")` vs `("a__b","c")`) are startup
  errors, never silently merged.

To avoid stranding a model that expects canonical names, the friction is mitigated:
server `instructions` (returned at `initialize`) explain the `__` convention, and each
tool's original description is preserved and annotated with its origin. The downstream
tool's `InputSchema` is forwarded so namespaced tools remain callable.

## Consequences

- Every tool's origin is explicit and unspoofable from the host's view.
- Collision detection prevents an ambiguous reverse mapping (itself a shadowing vector).
- The model is told the convention via the auto-surfaced `instructions` field rather than
  the user-invoked `prompts/*`.
