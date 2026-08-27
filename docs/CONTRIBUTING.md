# Contributing to Aegis-MCP

Thanks for considering a contribution!

## Ground rules

- **TDD**: every behavior change starts with a failing test. The security-critical
  packages (`policy`, `enforcer`, `profilestate`, `approval`, `naming`, `aegiserr`,
  `audit`) are pure (no I/O) and are expected to stay at or near 100% coverage.
- **Fail-closed**: when in doubt, deny — and audit the denial.
- **Small dependency footprint**: the only runtime dependencies are the official
  MCP Go SDK and `gopkg.in/yaml.v3`. New dependencies need a strong justification.
- **ADRs**: architectural decisions are recorded in `docs/architecture/ADR_xxx.md`.
  If your change alters a recorded decision, add a new ADR that supersedes it.

## Workflow

1. Fork and branch.
2. `make test` and `go test -race ./...` must pass; `go vet ./...` must be clean.
3. Open a PR describing the behavior change and which tests cover it.

For security-relevant findings, see [SECURITY.md](SECURITY.md) — please report
privately first.
