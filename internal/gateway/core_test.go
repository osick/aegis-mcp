package gateway

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/aegis-mcp/aegis/internal/approval"
	"github.com/aegis-mcp/aegis/internal/audit"
	"github.com/aegis-mcp/aegis/internal/config"
	"github.com/aegis-mcp/aegis/internal/enforcer"
	"github.com/aegis-mcp/aegis/internal/policy"
	"github.com/aegis-mcp/aegis/internal/profilestate"
)

type nopCh struct{}

func (nopCh) Notify(approval.Request) {}

func newCore(t *testing.T, buf *bytes.Buffer) *Core {
	t.Helper()
	c := &config.Config{
		Profiles: map[string]config.Profile{
			"default":     {Allow: []string{"filesystem.read_file"}, AllowedTransitions: []string{"code-review"}},
			"code-review": {Extends: "default", Allow: []string{"github.search"}, AllowedTransitions: []string{"default"}},
			"deploy":      {Allow: []string{"github.deploy"}},
		},
		Activation:      config.Activation{DefaultProfile: "default"},
		ErrorDisclosure: "verbose",
	}
	pol, err := policy.Compile(c)
	if err != nil {
		t.Fatal(err)
	}
	clients := map[string]DownstreamClient{
		"filesystem": &fakeClient{tools: []ToolDef{{Name: "read_file"}, {Name: "write_file"}}},
		"github":     &fakeClient{tools: []ToolDef{{Name: "search"}, {Name: "deploy"}}},
	}
	reg, _ := NewRegistry(clients)
	enf := enforcer.New(pol, "verbose")
	ps := profilestate.New(pol, approval.New(nopCh{}), "default")
	return NewCore(reg, enf, ps, audit.New(buf))
}

// Regression for B1: a host may call a tool from a cached list without issuing
// tools/list in this session. CallTool must lazily populate the wire-name map and
// succeed for an allowed tool rather than returning "unknown tool".
func TestCallToolWithoutPriorListSucceeds(t *testing.T) {
	var buf bytes.Buffer
	core := newCore(t, &buf)
	// Deliberately NO ListTools() call first.
	out, err := core.CallTool(context.Background(), "filesystem__read_file", nil)
	if err != nil {
		t.Fatalf("allowed tool must be callable without a prior list, got %v", err)
	}
	if out != "ok:read_file" {
		t.Errorf("unexpected downstream result: %q", out)
	}
}

// A denied tools/call must surface the structured AEGIS_CAP_DENIED payload.
func TestDeniedCallCarriesStructuredError(t *testing.T) {
	var buf bytes.Buffer
	core := newCore(t, &buf)
	_, err := core.CallTool(context.Background(), "github__deploy", nil)
	if err == nil {
		t.Fatal("github__deploy must be denied in default profile")
	}
	if !strings.Contains(err.Error(), "AEGIS_CAP_DENIED") {
		t.Errorf("denial must carry the structured error code, got %q", err.Error())
	}
}

func TestListToolsFilteredByProfile(t *testing.T) {
	var buf bytes.Buffer
	core := newCore(t, &buf)
	got, err := core.ListTools(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Wire != "filesystem__read_file" {
		t.Fatalf("expected only filesystem__read_file, got %+v", got)
	}
}

func TestCallDeniedToolIsAuditedAndNotForwarded(t *testing.T) {
	var buf bytes.Buffer
	core := newCore(t, &buf)
	_, _ = core.ListTools(context.Background())
	_, derr := core.CallTool(context.Background(), "github__deploy", nil)
	if derr == nil {
		t.Fatal("denied tool must return a structured error")
	}
	if !strings.Contains(buf.String(), "\"decision\":\"deny\"") {
		t.Errorf("denial must be audited: %s", buf.String())
	}
}

func TestSetProfileEscalationReturnsPending(t *testing.T) {
	var buf bytes.Buffer
	core := newCore(t, &buf)
	res := core.SetProfile("deploy", false)
	if res.Code != "AEGIS_PENDING_APPROVAL" {
		t.Fatalf("agent escalation must be pending, got %+v", res)
	}
	got, _ := core.ListTools(context.Background())
	if len(got) != 1 {
		t.Errorf("profile must not change while pending")
	}
}
