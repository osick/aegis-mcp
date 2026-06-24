# ADR 006: Go + official MCP SDK; pure-core / I/O-shell split

- Status: Accepted
- Date: 2026-06-15
- Cycle: 1

## Context

Aegis is a security gateway: its decision logic must be exhaustively testable and free of
I/O surprises, while still speaking real MCP over stdio to hosts and downstream servers.

## Decision

- **Language:** Go, single binary, userland only (no kernel features in Cycle 1).
- **Protocol:** build on the official `github.com/modelcontextprotocol/go-sdk` (v1.2.0)
  rather than hand-rolling JSON-RPC.
- **Architecture:** a strict split:
  - **Pure core** (`config`, `policy`, `naming`, `approval`, `profilestate`, `aegiserr`,
    `enforcer`, `audit`) — no network, no SDK. Security-critical; unit-tested to 82–100%.
  - **I/O shell** (`gateway`) — adapts the SDK to the core. A `DownstreamClient` interface
    is the seam, so the core and routing are tested with an in-memory fake, and the real
    SDK adapter is tested over the SDK's in-memory transport plus a real stdio subprocess.
- Enforcement is installed as a single **receiving middleware** on the Aegis MCP server,
  intercepting `tools/list|call` and `resources/list|read`; `aegis.*` meta-tools are
  registered tools delegated to via the middleware's pass-through.

## Consequences

- The SDK is isolated behind one interface; the security core has zero SDK dependency and
  can be reasoned about and tested in isolation.
- The middleware is the protocol-boundary chokepoint: nothing reaches a downstream client
  without passing core authorization.
- SDK version is pinned; the seam means a future SDK change or swap touches only `gateway`.
- Kernel sandboxing (Cycle 2) and the OAuth broker + control plane (Cycle 3) are out of
  scope here by design.
