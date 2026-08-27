# ADR 009: Posture toward the MCP 2026-07-28 specification; SDK upgrade to v1.7.0

- Status: Accepted
- Date: 2026-08-27
- Cycle: 1

## Context

The 2026-07-28 MCP specification restructures the protocol: a stateless core
(`initialize` handshake replaced by per-request `_meta` + `server/discover`,
SEP-2575), list results that must not vary per connection and carry cache hints
(`ttlMs`/`cacheScope`, SEP-2549/2567), Multi Round-Trip Requests replacing
server-initiated requests (SEP-2322), a formal extensions framework, deprecation
of Roots/Sampling/Logging, and authorization hardening (Client ID Metadata
Documents over Dynamic Client Registration). Aegis was built against SDK v1.2.0
(pre-2025-11-25 era) and pins its behavior to the classic stateful handshake.

Two Aegis design points are in tension with the new spec's direction:

- **Profile-filtered `tools/list`** is per-session server state — exactly what
  SEP-2567 removes for Streamable HTTP. On stdio this is benign (one client per
  process; per-connection == per-process), but clients that cache lists must be
  able to trust `tools/list_changed`, which Aegis already emits on every switch.
- **Active profile** is cross-call state. The new spec's pattern for that is a
  server-minted handle passed as a tool argument.

Other changes *validate* existing decisions: the deprecation of MCP Logging
recommends stderr — where ADR 007 already sends diagnostics; MRTR's
`input_required`-then-retry shape is structurally the same non-blocking pattern
ADR 003 chose for approvals.

## Decision

1. **Upgrade the SDK to v1.7.0 now.** It negotiates the highest mutually
   supported protocol version per connection, so classic hosts (2025-06-18 /
   2025-11-25 handshake) keep working unchanged — verified: full suite green,
   legacy `initialize` smoke-tested. No Aegis code changes were needed.
2. **Stay on the classic stdio session model for Cycle 1.** The SDK does not
   yet expose `server/discover`/stateless serving over stdio, and every current
   host still initializes. Profile state stays session-scoped.
3. **Adopt-when-hosts-do:** when host adoption of the stateless core begins,
   revisit in this order — (a) advertise conservative cache hints
   (`ttlMs` small, `cacheScope: "private"`) on filtered lists, (b) express the
   approval wait as an MRTR `input_required` result instead of the
   `AEGIS_PENDING_APPROVAL` error string, (c) evaluate carrying the active
   profile as a server-minted handle for the future HTTP transport (Cycle 2/3).
4. **Roadmap wording:** the Cycle 3 token broker targets OAuth 2.1 + PKCE with
   **Client ID Metadata Documents** (DCR is deprecated).

## Consequences

- Dependency freshness: v1.2.0 → v1.7.0 (with jsonschema-go v0.4.3,
  oauth2 v0.35.0); minimum Go remains satisfied by the pinned 1.26 toolchain.
- Aegis can front both old- and new-spec downstream servers as the SDK client
  negotiates per downstream — a gateway selling point, not a liability.
- The `aegis.set_profile` / `aegis.approval_status` meta-tools are candidates
  for a declared MCP *extension* once the extensions registry stabilizes.
- Risk accepted: if a host ships stateless-only stdio before the SDK serves it,
  Aegis would not connect; tracked as a watch item, considered unlikely inside
  the spec's 12-month deprecation windows.
