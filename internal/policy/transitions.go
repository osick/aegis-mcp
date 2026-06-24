package policy

// ProfileExists reports whether a profile is defined.
func (p *Policy) ProfileExists(name string) bool {
	_, ok := p.profiles[name]
	return ok
}

// IsTransitionAllowed reports whether switching from->to is a pre-declared autonomous
// edge. Anything not declared is NOT allowed (caller routes to HITL).
func (p *Policy) IsTransitionAllowed(from, to string) bool {
	cp, ok := p.profiles[from]
	if !ok {
		return false
	}
	return cp.transitions[to]
}
