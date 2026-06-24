# Development Plan: contextmcp - Task 5: internal/naming package

*Generated on 2026-06-17 by Vibe Feature MCP*
*Workflow: [tdd](https://mrsimpson.github.io/responsible-vibe-mcp/workflows/tdd)*

## Goal
Implement the `internal/naming` package for Aegis-MCP gateway (Task 5).
This package maps internal `server.tool` identifiers to unspoofable wire names (`server__tool`)
to prevent tool shadowing. Stdlib only.

## Key Decisions
- Wire name format: `server__tool` (double underscore separator)
- Duplicate (server, tool) registration is a startup error
- `AnnotateDescription` appends `[origin: <server>]` to tool descriptions

## Notes
- Go module: `github.com/aegis-mcp/aegis`
- Files only in `internal/naming/`
- No modifications to go.mod, go.sum, or other packages
- Go binary: `$HOME/.local/go/bin/go`

## Explore
### Tasks
- [x] Verify project structure and module name
- [x] Check existing internal packages

### Phase Entrance Criteria
- [x] Requirements are fully specified (provided in task prompt)
- [x] Module name confirmed

### Completed
- [x] Created development plan file
- [x] Verified module is `github.com/aegis-mcp/aegis`
- [x] Confirmed `internal/naming/` directory does not yet exist

## Red
### Phase Entrance Criteria
- [x] Explore phase complete — structure and requirements understood

### Tasks
- [ ] Create `internal/naming/` directory
- [ ] Write `internal/naming/naming_test.go` with the provided test code
- [ ] Confirm tests FAIL (Red state)

### Completed
*None yet*

## Green
### Phase Entrance Criteria
- [ ] Tests written and confirmed failing (Red)

### Tasks
- [ ] Write `internal/naming/naming.go` implementation
- [ ] Run tests and confirm all PASS
- [ ] Check coverage

### Completed
*None yet*

## Refactor
### Phase Entrance Criteria
- [ ] All tests passing (Green)

### Tasks
- [ ] Review implementation for clarity and correctness
- [ ] Ensure no unnecessary code

### Completed
*None yet*

---
*This plan is maintained by the LLM. Tool responses provide guidance on which section to focus on and what tasks to work on.*
