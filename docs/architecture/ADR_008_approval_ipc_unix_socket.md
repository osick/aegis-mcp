# ADR 008: Approval decisions reach the gateway over a per-user unix socket

- Status: Accepted
- Date: 2026-08-27
- Cycle: 1

## Context

ADR 003 made approval non-blocking: the human decides out-of-band via
`aegis approve <id>`. But the approval store lives in the running gateway's
memory, and the CLI runs as a separate process — the decision needs a transport
between them. Candidates:

- **File drop-box** (CLI writes a token file, gateway polls/watches): works
  everywhere, but polling latency, cleanup races, and no reply channel.
- **TCP on localhost**: reachable by any local process and, misconfigured, the
  network; needs its own authentication story.
- **Unix domain socket**: kernel-enforced filesystem permissions give per-user
  access control for free, connection-oriented (the CLI gets an immediate
  reply), supported by Go's `net` package on Linux, macOS, and modern Windows.

## Decision

The gateway listens on a **unix domain socket**; `aegis approve <id>` /
`aegis deny <id>` connect, send one line (`approve <id>`), and print the one-line
reply (`ok`, `unknown or already resolved id`, `bad request`).

Socket placement (`approvalipc.SocketPath`, shared by gateway and CLI):
`$AEGIS_APPROVAL_SOCKET` if set, else `$XDG_RUNTIME_DIR/aegis/approval.sock`,
else `<tmp>/aegis-<uid>/approval.sock`. The parent directory is created `0700`,
so only the same user can approve. A stale socket file from a crashed run is
replaced on startup. Binding the socket is **fail-closed**: if the HITL channel
cannot be established, the gateway refuses to start rather than run with
unapprovable escalations.

The IPC layer only calls `approval.Store.Resolve` — the single-use and
context-binding guarantees of ADR 003 (`Consume`, from-profile check) stay in
the pure core, untouched by the transport.

## Consequences

- The documented `aegis approve` flow works end-to-end (verified: escalate →
  approve from a second process → `aegis.approval_status` applies the switch,
  audited as `switch`/`human`).
- Same-user processes can approve: the trust boundary is the OS user, matching
  the Cycle 1 local-sidecar threat model. Remote/multi-party approval channels
  (Slack, control plane) remain future work behind the same `Resolver` seam.
- Unix socket paths are length-limited (~104 bytes); the default locations are
  short, and `AEGIS_APPROVAL_SOCKET` overrides for unusual environments.
- One socket per user by default: two gateways under the same user must set
  distinct `AEGIS_APPROVAL_SOCKET` paths.
