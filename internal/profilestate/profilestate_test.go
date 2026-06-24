package profilestate

import (
	"testing"

	"github.com/aegis-mcp/aegis/internal/approval"
	"github.com/aegis-mcp/aegis/internal/config"
	"github.com/aegis-mcp/aegis/internal/policy"
)

type nopChannel struct{}

func (nopChannel) Notify(approval.Request) {}

func build(t *testing.T) (*State, *approval.Store) {
	t.Helper()
	c := &config.Config{
		Profiles: map[string]config.Profile{
			"default":     {AllowedTransitions: []string{"code-review"}},
			"code-review": {AllowedTransitions: []string{"default"}},
			"deploy":      {AllowedTransitions: []string{}},
		},
		Activation: config.Activation{DefaultProfile: "default"},
	}
	pol, err := policy.Compile(c)
	if err != nil {
		t.Fatal(err)
	}
	ap := approval.New(nopChannel{})
	return New(pol, ap, "default"), ap
}

func TestAutonomousEdgeSwitch(t *testing.T) {
	s, _ := build(t)
	res := s.RequestSwitch("code-review", SourceAgent)
	if res.Outcome != OutcomeSwitched || s.Active() != "code-review" {
		t.Fatalf("expected autonomous switch, got %+v active=%s", res, s.Active())
	}
}

func TestNonEdgeSwitchRoutesToPending(t *testing.T) {
	s, _ := build(t)
	res := s.RequestSwitch("deploy", SourceAgent)
	if res.Outcome != OutcomePending || res.ApprovalID == "" {
		t.Fatalf("non-edge agent switch must be pending, got %+v", res)
	}
	if s.Active() != "default" {
		t.Fatal("profile must NOT change while pending")
	}
}

func TestLateralSpreadBlocked(t *testing.T) {
	s, _ := build(t)
	s.RequestSwitch("code-review", SourceAgent)
	res := s.RequestSwitch("deploy", SourceAgent)
	if res.Outcome != OutcomePending {
		t.Fatalf("lateral spread must require HITL, got %+v", res)
	}
}

func TestNonExistentTargetDenied(t *testing.T) {
	s, _ := build(t)
	res := s.RequestSwitch("ghost", SourceAgent)
	if res.Outcome != OutcomeDenied {
		t.Fatalf("unknown target must be denied, got %+v", res)
	}
}

func TestHumanCanSwitchAnywhere(t *testing.T) {
	s, _ := build(t)
	res := s.RequestSwitch("deploy", SourceHuman)
	if res.Outcome != OutcomeSwitched || s.Active() != "deploy" {
		t.Fatalf("human switch must be allowed, got %+v", res)
	}
}

func TestApplyApprovedCompletesSwitch(t *testing.T) {
	s, ap := build(t)
	res := s.RequestSwitch("deploy", SourceAgent)
	ap.Resolve(res.ApprovalID, true)
	if !s.ApplyIfApproved(res.ApprovalID) || s.Active() != "deploy" {
		t.Fatal("approved escalation must complete the switch")
	}
}

// An approved ticket must be single-use: it cannot be replayed to re-elevate later.
func TestApprovedSwitchIsSingleUse(t *testing.T) {
	s, ap := build(t)
	res := s.RequestSwitch("deploy", SourceAgent)
	ap.Resolve(res.ApprovalID, true)
	if !s.ApplyIfApproved(res.ApprovalID) {
		t.Fatal("first apply must succeed")
	}
	// Move back to a profile from which the same ticket could re-trigger if replayable.
	s.RequestSwitch("default", SourceHuman)
	if s.ApplyIfApproved(res.ApprovalID) {
		t.Fatal("a consumed approval must not be replayable")
	}
	if s.Active() != "default" {
		t.Fatal("replay must not change the active profile")
	}
}

// An approval is bound to the profile it was requested from; if the active profile
// has moved on, the approval must not silently apply in the new context.
func TestApprovalBoundToOriginatingProfile(t *testing.T) {
	s, ap := build(t)
	res := s.RequestSwitch("deploy", SourceAgent) // requested from "default"
	ap.Resolve(res.ApprovalID, true)
	s.RequestSwitch("code-review", SourceHuman) // active moves away from "default"
	if s.ApplyIfApproved(res.ApprovalID) {
		t.Fatal("approval from 'default' must not apply once active is 'code-review'")
	}
	if s.Active() != "code-review" {
		t.Fatal("active profile must be unchanged by the rejected apply")
	}
}
