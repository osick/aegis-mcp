# ADR 007: Audit records must not share stdout with the MCP protocol

- Status: Accepted
- Date: 2026-08-27
- Cycle: 1

## Context

The gateway serves MCP over stdio: stdout carries newline-delimited JSON-RPC
messages to the host. The original wiring (`audit.New(os.Stdout)`) wrote audit
records to the same stream. Verified against a live downstream, this interleaves
non-protocol JSON lines between JSON-RPC responses — hosts see invalid protocol
messages on every audited decision, and concurrent writes could even split a
frame. In a security tool, corrupting the very channel it protects is
unacceptable.

## Decision

Audit records never go to stdout. `audit.OpenSink` resolves the destination:

- default: **stderr** (line-based diagnostics, already used for logs and
  approval prompts);
- `AEGIS_AUDIT_LOG=<path>`: an **append-only file**, created owner-only (0600).

Opening the sink is **fail-closed**: if the configured audit file cannot be
opened, the gateway refuses to start — running without an audit trail is worse
than not running.

## Consequences

- stdout is protocol-pure; verified end-to-end (zero non-JSON-RPC lines).
- Deployments wanting durable, machine-readable audit set `AEGIS_AUDIT_LOG`;
  interactive use gets audit visibility on stderr for free.
- stderr mixes audit records with human-facing prompts/logs; anyone consuming
  audit programmatically should use the file sink.
- Log rotation is left to the operator (append-only open per run); a size/rotate
  policy is future work alongside the central control plane.
