package enforcer

import (
	"testing"

	"github.com/aegis-mcp/aegis/internal/config"
	"github.com/aegis-mcp/aegis/internal/policy"
)

func TestVerboseDenialNamesGrantingProfile(t *testing.T) {
	c := &config.Config{
		Profiles: map[string]config.Profile{
			"default":     {Allow: []string{"filesystem.read_file"}},
			"code-review": {Allow: []string{"sonarqube.scan"}},
		},
		Activation:      config.Activation{DefaultProfile: "default"},
		ErrorDisclosure: "verbose",
	}
	pol, err := policy.Compile(c)
	if err != nil {
		t.Fatal(err)
	}
	d := New(pol, "verbose").AuthorizeTool("default", Capability{"sonarqube", "scan"})
	if d.Allowed || d.Err == nil {
		t.Fatal("must be denied")
	}
	if d.Err.Map()["required_profile"] != "code-review" {
		t.Errorf("verbose denial should name the granting profile, got %v", d.Err.Map())
	}

	// minimal mode must NOT disclose it
	dm := New(pol, "minimal").AuthorizeTool("default", Capability{"sonarqube", "scan"})
	if _, present := dm.Err.Map()["required_profile"]; present {
		t.Errorf("minimal mode must not disclose required_profile")
	}
}

func mk(t *testing.T) *Enforcer {
	t.Helper()
	c := &config.Config{
		Profiles: map[string]config.Profile{
			"default": {Allow: []string{"filesystem.read_file"}, Resources: []string{"file:///repo/**"}},
		},
		Activation:      config.Activation{DefaultProfile: "default"},
		ErrorDisclosure: "verbose",
	}
	pol, err := policy.Compile(c)
	if err != nil {
		t.Fatal(err)
	}
	return New(pol, "verbose")
}

func TestFilterToolsKeepsOnlyAllowed(t *testing.T) {
	e := mk(t)
	in := []Capability{{"filesystem", "read_file"}, {"filesystem", "write_file"}, {"github", "search"}}
	out := e.FilterTools("default", in)
	if len(out) != 1 || out[0].Tool != "read_file" {
		t.Fatalf("filter wrong: %+v", out)
	}
}

func TestAuthorizeToolCall(t *testing.T) {
	e := mk(t)
	if d := e.AuthorizeTool("default", Capability{"filesystem", "read_file"}); !d.Allowed {
		t.Error("read_file must be allowed")
	}
	d := e.AuthorizeTool("default", Capability{"filesystem", "write_file"})
	if d.Allowed || d.Err == nil {
		t.Error("write_file must be denied with a structured error")
	}
}

func TestAuthorizeResourceTraversalDenied(t *testing.T) {
	e := mk(t)
	if d := e.AuthorizeResource("default", "file:///repo/a.txt"); !d.Allowed {
		t.Error("in-scope resource must be allowed")
	}
	if d := e.AuthorizeResource("default", "file:///repo/../etc/passwd"); d.Allowed {
		t.Error("traversal must be denied")
	}
}

func TestFilterResourcesKeepsOnlyAllowed(t *testing.T) {
	e := mk(t)
	out := e.FilterResources("default", []string{"file:///repo/ok.txt", "file:///etc/secret"})
	if len(out) != 1 || out[0] != "file:///repo/ok.txt" {
		t.Fatalf("filter resources wrong: %+v", out)
	}
}
