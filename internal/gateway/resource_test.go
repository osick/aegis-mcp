package gateway

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/osick/aegis-mcp/internal/approval"
	"github.com/osick/aegis-mcp/internal/audit"
	"github.com/osick/aegis-mcp/internal/config"
	"github.com/osick/aegis-mcp/internal/enforcer"
	"github.com/osick/aegis-mcp/internal/policy"
	"github.com/osick/aegis-mcp/internal/profilestate"
)

func newResourceCore(t *testing.T, buf *bytes.Buffer) *Core {
	t.Helper()
	c := &config.Config{
		Profiles: map[string]config.Profile{
			"default": {
				Allow:     []string{"filesystem.read_file"},
				Resources: []string{"file:///repo/**"},
			},
		},
		Activation:      config.Activation{DefaultProfile: "default"},
		ErrorDisclosure: "verbose",
	}
	pol, err := policy.Compile(c)
	if err != nil {
		t.Fatal(err)
	}
	clients := map[string]DownstreamClient{
		"filesystem": &fakeClient{
			tools:     []ToolDef{{Name: "read_file"}},
			resources: []string{"file:///repo/ok.txt", "file:///secret"},
		},
	}
	reg, _ := NewRegistry(clients)
	enf := enforcer.New(pol, "verbose")
	ps := profilestate.New(pol, approval.New(nopCh{}), "default")
	return NewCore(reg, enf, ps, audit.New(buf))
}

func TestListResourcesFilteredByProfile(t *testing.T) {
	var buf bytes.Buffer
	core := newResourceCore(t, &buf)
	got, err := core.ListResources(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].URI != "file:///repo/ok.txt" {
		t.Fatalf("expected only file:///repo/ok.txt, got %+v", got)
	}
}

func TestReadResourceDeniesOutOfScopeAndAudits(t *testing.T) {
	var buf bytes.Buffer
	core := newResourceCore(t, &buf)
	_, err := core.ReadResource(context.Background(), "file:///secret")
	if err == nil {
		t.Fatal("out-of-scope resource read must be denied")
	}
	if !strings.Contains(buf.String(), "\"decision\":\"deny\"") {
		t.Errorf("denial must be audited: %s", buf.String())
	}
	if !strings.Contains(err.Error(), "AEGIS_RESOURCE_DENIED") {
		t.Errorf("denial must carry structured error: %v", err)
	}
}

func TestReadResourceAllowsInScopeAndAudits(t *testing.T) {
	var buf bytes.Buffer
	core := newResourceCore(t, &buf)
	out, err := core.ReadResource(context.Background(), "file:///repo/ok.txt")
	if err != nil {
		t.Fatalf("in-scope read must succeed: %v", err)
	}
	if out != "data" {
		t.Errorf("expected fake resource contents %q, got %q", "data", out)
	}
	if !strings.Contains(buf.String(), "\"decision\":\"allow\"") {
		t.Errorf("allow must be audited: %s", buf.String())
	}
}
