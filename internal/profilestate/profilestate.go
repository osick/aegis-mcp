// Package profilestate holds the active profile and authorizes switches.
package profilestate

import (
	"sync"

	"github.com/aegis-mcp/aegis/internal/approval"
	"github.com/aegis-mcp/aegis/internal/policy"
)

type Source int

const (
	SourceAgent Source = iota // via aegis.set_profile — subject to the transition graph
	SourceHuman               // via CLI/control — trusted
)

type Outcome int

const (
	OutcomeSwitched Outcome = iota
	OutcomePending
	OutcomeDenied
)

type Result struct {
	Outcome    Outcome
	ApprovalID string // set when OutcomePending
	Active     string
}

type State struct {
	mu     sync.Mutex
	pol    *policy.Policy
	ap     *approval.Store
	active string
}

func New(pol *policy.Policy, ap *approval.Store, initial string) *State {
	return &State{pol: pol, ap: ap, active: initial}
}

func (s *State) Active() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.active
}

// RequestSwitch authorizes a switch to target from the given source.
func (s *State) RequestSwitch(target string, src Source) Result {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.pol.ProfileExists(target) {
		return Result{Outcome: OutcomeDenied, Active: s.active}
	}
	if src == SourceHuman || s.pol.IsTransitionAllowed(s.active, target) {
		s.active = target
		return Result{Outcome: OutcomeSwitched, Active: s.active}
	}
	id := s.ap.Request(s.active, target)
	return Result{Outcome: OutcomePending, ApprovalID: id, Active: s.active}
}

// ApplyIfApproved completes a previously-pending switch if the human approved it.
// The approval is single-use (Consume), and is only applied when the active profile
// still matches the one the approval was granted from — so a stale approved ticket
// cannot be replayed, and an approval granted in one context cannot be applied in a
// different one.
func (s *State) ApplyIfApproved(approvalID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Peek without consuming so a wrong-context approval is left intact (not burned).
	req, ok := s.ap.Pending(approvalID)
	if !ok || req.FromProf != s.active {
		return false
	}
	if _, ok := s.ap.Consume(approvalID); !ok {
		return false // not approved, or already applied
	}
	s.active = req.ToProf
	return true
}
