package gateway

import (
	"context"
	"testing"

	"github.com/aegis-mcp/aegis/internal/naming"
)

func newRegistry(t *testing.T) *Registry {
	t.Helper()
	clients := map[string]DownstreamClient{
		"filesystem": &fakeClient{tools: []ToolDef{{Name: "read_file", Description: "read"}, {Name: "search", Description: "s"}}},
		"github":     &fakeClient{tools: []ToolDef{{Name: "search", Description: "s"}}},
	}
	r, err := NewRegistry(clients)
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	return r
}

func TestRegistryAggregatesAndNamespaces(t *testing.T) {
	r := newRegistry(t)
	tools, err := r.AllTools(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	wire := map[string]bool{}
	for _, td := range tools {
		wire[td.Wire] = true
	}
	if !wire["filesystem__search"] || !wire["github__search"] || !wire["filesystem__read_file"] {
		t.Fatalf("namespacing wrong: %v", wire)
	}
}

func TestRouterResolvesWireNameToDownstream(t *testing.T) {
	r := newRegistry(t)
	_, _ = r.AllTools(context.Background())
	out, err := r.Router().CallByWire(context.Background(), naming.Wire("github", "search"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if out != "ok:search" {
		t.Errorf("router called wrong downstream: %q", out)
	}
	if _, err := r.Router().CallByWire(context.Background(), "ghost__x", nil); err == nil {
		t.Error("unknown wire name must error, not reach any downstream")
	}
}
