// Package approval is a non-blocking pending-request store for HITL profile switches.
package approval

import (
	"fmt"
	"sync"
)

type Status string

const (
	StatusUnknown  Status = "unknown"
	StatusPending  Status = "pending"
	StatusApproved Status = "approved"
	StatusDenied   Status = "denied"
	StatusApplied  Status = "applied" // approved AND already consumed (single-use)
)

// Request is an escalation awaiting a human decision.
type Request struct {
	ID       string
	FromProf string
	ToProf   string
}

// Channel delivers approval requests to a human out-of-band (terminal, Slack, ...).
type Channel interface {
	Notify(Request)
}

type Store struct {
	mu     sync.Mutex
	ch     Channel
	seq    int
	status map[string]Status
	reqs   map[string]Request
}

func New(ch Channel) *Store {
	return &Store{ch: ch, status: map[string]Status{}, reqs: map[string]Request{}}
}

// Request registers a pending escalation, notifies the human, and returns immediately.
func (s *Store) Request(from, to string) string {
	s.mu.Lock()
	s.seq++
	id := fmt.Sprintf("apr_%d", s.seq)
	req := Request{ID: id, FromProf: from, ToProf: to}
	s.status[id] = StatusPending
	s.reqs[id] = req
	s.mu.Unlock()

	s.ch.Notify(req) // out-of-band; never blocks the caller's RPC
	return id
}

// Resolve records a human decision. Returns false if id is unknown or already resolved.
func (s *Store) Resolve(id string, approve bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.status[id] != StatusPending {
		return false
	}
	if approve {
		s.status[id] = StatusApproved
	} else {
		s.status[id] = StatusDenied
	}
	return true
}

func (s *Store) Status(id string) Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.status[id]
	if !ok {
		return StatusUnknown
	}
	return st
}

// Pending returns the original request for an id, if known.
func (s *Store) Pending(id string) (Request, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.reqs[id]
	return r, ok
}

// Consume atomically transitions an Approved request to Applied and returns it.
// It returns ok=false if the request is not currently Approved (unknown, pending,
// denied, or already applied). This makes an approval single-use: a stale approved
// ticket cannot be replayed to re-elevate later.
func (s *Store) Consume(id string) (Request, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.status[id] != StatusApproved {
		return Request{}, false
	}
	s.status[id] = StatusApplied
	return s.reqs[id], true
}
