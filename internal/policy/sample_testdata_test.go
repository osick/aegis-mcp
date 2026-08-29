package policy

import (
	"testing"

	"github.com/osick/aegis-mcp/internal/config"
)

// TestCompileSampleTestdata ensures the shipped sample config compiles into a
// usable policy (catches wildcard / transition-graph issues end to end).
func TestCompileSampleTestdata(t *testing.T) {
	c, err := config.Load("../../testdata/aegis.yaml")
	if err != nil {
		t.Fatalf("load sample config: %v", err)
	}
	pol, err := Compile(c)
	if err != nil {
		t.Fatalf("sample config must compile: %v", err)
	}
	if !pol.ProfileExists("deploy") {
		t.Errorf("compiled policy missing deploy profile")
	}
	// deploy extends code-review extends default, so it should allow read_file.
	if !pol.IsToolAllowed("deploy", "filesystem.read_file") {
		t.Errorf("deploy must inherit filesystem.read_file via extends chain")
	}
}
