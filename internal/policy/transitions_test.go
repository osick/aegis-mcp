package policy

import (
	"testing"

	"github.com/osick/aegis-mcp/internal/config"
)

func TestTransitions(t *testing.T) {
	p := compile(t, &config.Config{
		Profiles: map[string]config.Profile{
			"default":     {AllowedTransitions: []string{"code-review"}},
			"code-review": {AllowedTransitions: []string{"default"}},
			"deploy":      {AllowedTransitions: []string{}},
		},
		Activation: config.Activation{DefaultProfile: "default"},
	})
	if !p.ProfileExists("deploy") || p.ProfileExists("ghost") {
		t.Fatal("ProfileExists wrong")
	}
	if !p.IsTransitionAllowed("default", "code-review") {
		t.Error("default->code-review should be an autonomous edge")
	}
	if p.IsTransitionAllowed("default", "deploy") {
		t.Error("default->deploy is NOT an edge (must route to HITL)")
	}
	if p.IsTransitionAllowed("code-review", "deploy") {
		t.Error("lateral spread code-review->deploy must NOT be autonomous")
	}
}
