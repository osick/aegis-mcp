# ADR 001: Aggregating proxy topology (1:N), not a 1:1 wrapper

- Status: Accepted
- Date: 2026-06-15
- Cycle: 1

## Context

Aegis-MCP sits between an AI host (Claude Desktop, Cursor) and downstream MCP servers.
Two topologies are possible: a 1:1 wrapper (one Aegis per downstream server) or a 1:N
aggregating proxy (one Aegis fronting all downstream servers, presenting a single MCP
endpoint to the host).

The defining requirement is **context-aware tool filtering** — e.g. "show filesystem +
git, hide SonarQube unless in `code-review`". That is inherently a *cross-server*
decision.

## Decision

Aegis is a **single aggregating proxy (1:N)**. The host is configured to talk to exactly
one MCP server (Aegis); Aegis connects to all downstream servers and presents a single,
filtered, namespaced tool/resource surface upward.

## Consequences

- A component that sees all downstream servers at once can rewrite the unified
  `tools/list` per active profile — a 1:1 wrapper cannot express "hide server B entirely
  in this context" from one policy.
- Aegis becomes the single audit/enforcement chokepoint Zero-Trust wants.
- Trade-off: a single point of latency/failure and more internal complexity. Accepted,
  because that chokepoint is exactly where enforcement and audit belong.
- Tool-name collisions across servers must be handled (see [ADR 005](ADR_005_tool_name_namespacing.md)).
