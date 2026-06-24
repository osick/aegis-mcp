package policy

import (
	"testing"

	"github.com/aegis-mcp/aegis/internal/config"
)

func compile(t *testing.T, c *config.Config) *Policy {
	t.Helper()
	p, err := Compile(c)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return p
}

func TestCompileRejectsCyclicExtends(t *testing.T) {
	c := &config.Config{
		Profiles: map[string]config.Profile{
			"a": {Extends: "b"},
			"b": {Extends: "a"},
		},
		Activation: config.Activation{DefaultProfile: "a"},
	}
	if _, err := Compile(c); err == nil {
		t.Fatal("cyclic extends must fail compilation (fail-closed)")
	}
}

func TestToolAllowGlobAndExtends(t *testing.T) {
	c := &config.Config{
		Profiles: map[string]config.Profile{
			"default":     {Allow: []string{"filesystem.read_file", "github.search_*"}},
			"code-review": {Extends: "default", Allow: []string{"sonarqube.*"}},
		},
		Activation: config.Activation{DefaultProfile: "default"},
	}
	p := compile(t, c)

	cases := []struct {
		profile, cap string
		want         bool
	}{
		{"default", "filesystem.read_file", true},
		{"default", "filesystem.write_file", false},
		{"default", "github.search_code", true},
		{"default", "sonarqube.scan", false},
		{"code-review", "sonarqube.scan", true},
		{"code-review", "filesystem.read_file", true},
	}
	for _, tc := range cases {
		if got := p.IsToolAllowed(tc.profile, tc.cap); got != tc.want {
			t.Errorf("IsToolAllowed(%q,%q)=%v want %v", tc.profile, tc.cap, got, tc.want)
		}
	}
}

func TestUnknownProfileDeniesAll(t *testing.T) {
	p := compile(t, &config.Config{
		Profiles:   map[string]config.Profile{"default": {Allow: []string{"x.y"}}},
		Activation: config.Activation{DefaultProfile: "default"},
	})
	if p.IsToolAllowed("ghost", "x.y") {
		t.Error("unknown profile must deny")
	}
}
