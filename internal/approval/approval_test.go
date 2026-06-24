package approval

import "testing"

// recordingChannel captures requests instead of prompting a human.
type recordingChannel struct{ requests []Request }

func (r *recordingChannel) Notify(req Request) { r.requests = append(r.requests, req) }

func TestRequestApproveDenyExpire(t *testing.T) {
	ch := &recordingChannel{}
	s := New(ch)

	id := s.Request("default", "deploy")
	if id == "" {
		t.Fatal("expected non-empty approval_id")
	}
	if s.Status(id) != StatusPending {
		t.Fatalf("new request must be pending, got %v", s.Status(id))
	}
	if len(ch.requests) != 1 || ch.requests[0].ID != id {
		t.Fatalf("human channel was not notified")
	}

	if ok := s.Resolve(id, true); !ok {
		t.Fatal("resolve approve failed")
	}
	if s.Status(id) != StatusApproved {
		t.Fatalf("status should be approved")
	}
	if s.Resolve(id, false) {
		t.Error("a resolved request must not be re-resolvable")
	}

	id2 := s.Request("default", "deploy")
	s.Resolve(id2, false)
	if s.Status(id2) != StatusDenied {
		t.Error("status should be denied")
	}

	if s.Status("missing") != StatusUnknown {
		t.Error("unknown id must be StatusUnknown")
	}
}

func TestConsumeIsSingleUse(t *testing.T) {
	s := New(&recordingChannel{})

	// Cannot consume a pending (not-yet-approved) request.
	id := s.Request("default", "deploy")
	if _, ok := s.Consume(id); ok {
		t.Fatal("must not consume a pending request")
	}

	// After approval, first consume succeeds and returns the request.
	s.Resolve(id, true)
	req, ok := s.Consume(id)
	if !ok || req.ToProf != "deploy" || req.FromProf != "default" {
		t.Fatalf("first consume should return the request, got %+v ok=%v", req, ok)
	}
	if s.Status(id) != StatusApplied {
		t.Errorf("status after consume should be applied, got %v", s.Status(id))
	}

	// Second consume fails (single-use).
	if _, ok := s.Consume(id); ok {
		t.Fatal("a consumed approval must not be consumable again")
	}

	// Unknown id cannot be consumed.
	if _, ok := s.Consume("missing"); ok {
		t.Fatal("unknown id must not be consumable")
	}

	// Pending() still returns the original request record (for audit/inspection).
	if _, ok := s.Pending(id); !ok {
		t.Error("Pending should still know the request")
	}
}
