package policy

import (
	"testing"

	"github.com/osick/aegis-mcp/internal/config"
)

func TestResourceMatchingAndTraversal(t *testing.T) {
	p := compile(t, &config.Config{
		Profiles: map[string]config.Profile{
			"default": {Resources: []string{"file:///var/log/app/**"}},
		},
		Activation: config.Activation{DefaultProfile: "default"},
	})

	cases := []struct {
		uri  string
		want bool
	}{
		{"file:///var/log/app/today.log", true},
		{"file:///var/log/app/nested/deep.log", true},
		{"file:///var/log/other/secret", false},
		{"file:///var/log/app/../../etc/passwd", false},
		{"file:///var/log/app/%2e%2e/%2e%2e/etc/passwd", false},
	}
	for _, tc := range cases {
		if got := p.IsResourceAllowed("default", tc.uri); got != tc.want {
			t.Errorf("IsResourceAllowed(%q)=%v want %v", tc.uri, got, tc.want)
		}
	}
}

func TestResourceSingleSegmentAndExactGlob(t *testing.T) {
	p := compile(t, &config.Config{
		Profiles: map[string]config.Profile{
			"default": {Resources: []string{
				"file:///etc/conf/*",         // exactly one segment under conf
				"https://api.example/health", // exact match, no glob
			}},
		},
		Activation: config.Activation{DefaultProfile: "default"},
	})
	cases := []struct {
		uri  string
		want bool
	}{
		{"file:///etc/conf/app.ini", true},         // one segment: allowed
		{"file:///etc/conf/nested/app.ini", false}, // two segments: NOT allowed by /*
		{"file:///etc/conf/", false},               // empty segment
		{"https://api.example/health", true},       // exact match
		{"https://api.example/health/sub", false},  // exact pattern must not prefix-match
	}
	for _, tc := range cases {
		if got := p.IsResourceAllowed("default", tc.uri); got != tc.want {
			t.Errorf("IsResourceAllowed(%q)=%v want %v", tc.uri, got, tc.want)
		}
	}
}

// Regression: the URI authority/host must be part of matching, or a pattern scoped
// to one repo/host would match a different one (cross-repo/cross-host bypass).
func TestResourceHostScopingNotBypassable(t *testing.T) {
	p := compile(t, &config.Config{
		Profiles: map[string]config.Profile{
			"default": {Resources: []string{
				"github://my-repo/pulls/**",
				"file:///repo/**",
			}},
		},
		Activation: config.Activation{DefaultProfile: "default"},
	})
	cases := []struct {
		uri  string
		want bool
	}{
		{"github://my-repo/pulls/5", true},        // correct repo
		{"github://attacker-repo/pulls/5", false}, // different authority must NOT match
		{"file:///repo/a.txt", true},              // empty host (local)
		{"file://evil-host/repo/a.txt", false},    // injected host must NOT match
	}
	for _, tc := range cases {
		if got := p.IsResourceAllowed("default", tc.uri); got != tc.want {
			t.Errorf("IsResourceAllowed(%q)=%v want %v", tc.uri, got, tc.want)
		}
	}
}

func TestResourceUnknownProfileDenies(t *testing.T) {
	p := compile(t, &config.Config{
		Profiles:   map[string]config.Profile{"default": {Resources: []string{"file:///x/**"}}},
		Activation: config.Activation{DefaultProfile: "default"},
	})
	if p.IsResourceAllowed("ghost", "file:///x/y") {
		t.Error("unknown profile must deny resources")
	}
}
