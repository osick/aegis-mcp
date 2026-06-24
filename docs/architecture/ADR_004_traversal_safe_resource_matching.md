# ADR 004: Traversal-safe, host-aware resource URI matching

- Status: Accepted
- Date: 2026-06-16 (hardened 2026-06-17 after security review)
- Cycle: 1

## Context

The spec extends profile filtering to `resources/*` in Cycle 1. Unlike tools (discrete
`server.tool` names), MCP resources use dynamic URI templates
(`file:///repo/{path}`, `github://repo/pulls/{id}`). Naive glob matching is both
insufficient and dangerous: an allow pattern can be bypassed by path traversal, and the
URI **authority/host** carries scoping that must not be ignored.

## Decision

The `policy` module matches resource allow-lists with URI-template/glob patterns over a
**canonicalized** URI:

- Parse the URI; percent-decoding is applied to the path.
- Normalize the path (`path.Clean`) and **reject** anything that escapes its root
  (`../`, encoded variants) before matching — never match the raw attacker string.
- **Retain the host/authority** in the canonical form (`scheme://host + cleanedPath`).

## Consequences

- `file:///var/log/app/../../etc/passwd` and `…/%2e%2e/%2e%2e/…` are denied (traversal).
- A pattern scoped to one repo/host cannot be bypassed by another:
  `github://my-repo/pulls/**` does **not** match `github://attacker-repo/pulls/5`, and
  `file:///repo/**` does **not** match `file://evil-host/repo/x`. (The original
  implementation dropped the host — caught and fixed in security review; regression test
  `TestResourceHostScopingNotBypassable`.)
- This is *surface reduction* (which resources are reachable), **not** content-injection
  defense; inspecting resource payloads remains a deferred control.
