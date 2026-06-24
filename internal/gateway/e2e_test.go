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

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// buildDownstreamServer creates a REAL MCP server exposing read_file and deploy,
// plus two resources (one in-scope, one out-of-scope for the default profile).
func buildDownstreamServer() *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "filesystem", Version: "0.0.1"}, nil)

	s.AddResource(&mcp.Resource{URI: "file:///repo/ok.txt", Name: "ok.txt"},
		func(ctx context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
			return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{URI: req.Params.URI, Text: "repo-data"}}}, nil
		})
	s.AddResource(&mcp.Resource{URI: "file:///secret", Name: "secret"},
		func(ctx context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
			return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{URI: req.Params.URI, Text: "TOP-SECRET"}}}, nil
		})

	type readIn struct {
		Path string `json:"path"`
	}
	mcp.AddTool(s, &mcp.Tool{Name: "read_file", Description: "Read a file"},
		func(ctx context.Context, _ *mcp.CallToolRequest, in readIn) (*mcp.CallToolResult, any, error) {
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "contents-of:" + in.Path}}}, nil, nil
		})

	type deployIn struct {
		Target string `json:"target"`
	}
	mcp.AddTool(s, &mcp.Tool{Name: "deploy", Description: "Deploy a build"},
		func(ctx context.Context, _ *mcp.CallToolRequest, in deployIn) (*mcp.CallToolResult, any, error) {
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "deployed:" + in.Target}}}, nil, nil
		})

	return s
}

// connectDownstream wires a real downstream server to a real client session over
// an in-memory transport pair, returning a DownstreamClient wrapping that session.
func connectDownstream(ctx context.Context, t *testing.T) DownstreamClient {
	t.Helper()
	srvTransport, cliTransport := mcp.NewInMemoryTransports()

	server := buildDownstreamServer()
	go func() { _ = server.Run(ctx, srvTransport) }()

	client := mcp.NewClient(&mcp.Implementation{Name: "aegis-mcp", Version: "0.1.0"}, nil)
	session, err := client.Connect(ctx, cliTransport, nil)
	if err != nil {
		t.Fatalf("connect downstream: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })
	return newSDKClient(session)
}

func buildE2ECore(t *testing.T, ds DownstreamClient, buf *bytes.Buffer) *Core {
	t.Helper()
	c := &config.Config{
		Profiles: map[string]config.Profile{
			"default": {
				Allow:              []string{"filesystem.read_file"},
				Resources:          []string{"file:///repo/**"},
				AllowedTransitions: []string{"code-review"},
			},
			"code-review": {
				Extends:            "default",
				Allow:              []string{"filesystem.deploy"},
				AllowedTransitions: []string{"default"},
			},
		},
		Activation:      config.Activation{DefaultProfile: "default"},
		ErrorDisclosure: "verbose",
	}
	pol, err := policy.Compile(c)
	if err != nil {
		t.Fatal(err)
	}
	reg, _ := NewRegistry(map[string]DownstreamClient{"filesystem": ds})
	enf := enforcer.New(pol, "verbose")
	ps := profilestate.New(pol, approval.New(nopCh{}), "default")
	return NewCore(reg, enf, ps, audit.New(buf))
}

// TestCoreAgainstRealSDKClient validates the SDK adapter against a REAL sdk
// server/session over in-memory transport (no fakeClient).
func TestCoreAgainstRealSDKClient(t *testing.T) {
	ctx := context.Background()
	ds := connectDownstream(ctx, t)
	var buf bytes.Buffer
	core := buildE2ECore(t, ds, &buf)

	tools, err := core.ListTools(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(tools) != 1 || tools[0].Wire != "filesystem__read_file" {
		t.Fatalf("default profile must expose only filesystem__read_file, got %+v", tools)
	}
	// InputSchema must be forwarded from the real downstream tool.
	if tools[0].InputSchema == nil {
		t.Errorf("input schema must be forwarded from downstream")
	}

	// Allowed call works against the real downstream.
	out, err := core.CallTool(ctx, "filesystem__read_file", map[string]any{"path": "/x"})
	if err != nil {
		t.Fatalf("allowed call failed: %v", err)
	}
	if out != "contents-of:/x" {
		t.Errorf("unexpected downstream result: %q", out)
	}

	// Denied call is blocked.
	if _, err := core.CallTool(ctx, "filesystem__deploy", nil); err == nil {
		t.Fatal("deploy must be denied in default profile")
	}
}

// TestEndToEndThroughAegisServer drives a REAL test client through the full
// Aegis server over a SECOND in-memory transport pair.
func TestEndToEndThroughAegisServer(t *testing.T) {
	ctx := context.Background()
	ds := connectDownstream(ctx, t)
	var buf bytes.Buffer
	core := buildE2ECore(t, ds, &buf)

	aegisServer := BuildServer(core)
	srvTransport, cliTransport := mcp.NewInMemoryTransports()
	go func() { _ = aegisServer.Run(ctx, srvTransport) }()

	hostClient := mcp.NewClient(&mcp.Implementation{Name: "host", Version: "0.0.1"}, nil)
	session, err := hostClient.Connect(ctx, cliTransport, nil)
	if err != nil {
		t.Fatalf("connect to aegis: %v", err)
	}
	defer session.Close()

	// Instructions must be present on the initialized session.
	if instr := session.InitializeResult().Instructions; !strings.Contains(instr, "Aegis-MCP") {
		t.Errorf("server instructions must mention Aegis-MCP, got %q", instr)
	}

	// tools/list: namespaced read_file + meta-tools, NOT deploy.
	lt, err := session.ListTools(ctx, &mcp.ListToolsParams{})
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, tool := range lt.Tools {
		names[tool.Name] = true
	}
	if !names["filesystem__read_file"] {
		t.Errorf("expected namespaced filesystem__read_file in list: %v", names)
	}
	if !names["aegis.set_profile"] {
		t.Errorf("expected aegis.set_profile meta-tool in list: %v", names)
	}
	if names["filesystem__deploy"] {
		t.Errorf("filesystem__deploy must NOT be visible under default profile: %v", names)
	}

	// Calling the denied deploy returns an error result.
	cr, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "filesystem__deploy", Arguments: map[string]any{"target": "prod"}})
	if err != nil {
		t.Fatalf("transport error calling deploy: %v", err)
	}
	if !cr.IsError {
		t.Errorf("denied deploy must return IsError result")
	}

	// set_profile to a declared edge succeeds.
	sp, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "aegis.set_profile", Arguments: map[string]any{"name": "code-review"}})
	if err != nil {
		t.Fatalf("set_profile transport error: %v", err)
	}
	if sp.IsError {
		t.Fatalf("set_profile to declared edge must succeed")
	}
	if txt := callText(sp); !strings.Contains(txt, "code=OK") || !strings.Contains(txt, "active=code-review") {
		t.Errorf("expected switch to code-review, got %q", txt)
	}

	// Now deploy becomes visible and callable.
	lt2, _ := session.ListTools(ctx, &mcp.ListToolsParams{})
	visible := map[string]bool{}
	for _, tool := range lt2.Tools {
		visible[tool.Name] = true
	}
	if !visible["filesystem__deploy"] {
		t.Errorf("filesystem__deploy must be visible after switch: %v", visible)
	}
	dep, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "filesystem__deploy", Arguments: map[string]any{"target": "prod"}})
	if err != nil {
		t.Fatalf("deploy transport error: %v", err)
	}
	if dep.IsError {
		t.Errorf("deploy must succeed after switching to code-review: %q", callText(dep))
	}
	if txt := callText(dep); !strings.Contains(txt, "deployed:prod") {
		t.Errorf("unexpected deploy result: %q", txt)
	}

	// resources/list must show only the in-scope resource (default profile scope
	// carries over; code-review extends default's file:///repo/** glob).
	rl, err := session.ListResources(ctx, &mcp.ListResourcesParams{})
	if err != nil {
		t.Fatalf("resources/list error: %v", err)
	}
	uris := map[string]bool{}
	for _, r := range rl.Resources {
		uris[r.URI] = true
	}
	if !uris["file:///repo/ok.txt"] {
		t.Errorf("in-scope resource must be listed: %v", uris)
	}
	if uris["file:///secret"] {
		t.Errorf("out-of-scope resource must NOT be listed: %v", uris)
	}

	// resources/read: in-scope succeeds, out-of-scope is blocked.
	rr, err := session.ReadResource(ctx, &mcp.ReadResourceParams{URI: "file:///repo/ok.txt"})
	if err != nil {
		t.Fatalf("in-scope resource read must succeed: %v", err)
	}
	if len(rr.Contents) == 0 || rr.Contents[0].Text != "repo-data" {
		t.Errorf("unexpected resource contents: %+v", rr.Contents)
	}
	if _, err := session.ReadResource(ctx, &mcp.ReadResourceParams{URI: "file:///secret"}); err == nil {
		t.Errorf("out-of-scope resource read must be blocked")
	}
}

// TestApprovalStatusMetaTool exercises the aegis.approval_status meta-tool path.
func TestApprovalStatusMetaTool(t *testing.T) {
	ctx := context.Background()
	ds := connectDownstream(ctx, t)
	var buf bytes.Buffer
	core := buildE2ECore(t, ds, &buf)

	aegisServer := BuildServer(core)
	srvTransport, cliTransport := mcp.NewInMemoryTransports()
	go func() { _ = aegisServer.Run(ctx, srvTransport) }()
	hostClient := mcp.NewClient(&mcp.Implementation{Name: "host", Version: "0.0.1"}, nil)
	session, err := hostClient.Connect(ctx, cliTransport, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer session.Close()

	res, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "aegis.approval_status", Arguments: map[string]any{"id": "apr_does_not_exist"}})
	if err != nil {
		t.Fatalf("approval_status transport error: %v", err)
	}
	if txt := callText(res); txt != "pending" {
		t.Errorf("unknown approval id must report pending, got %q", txt)
	}
}

func callText(r *mcp.CallToolResult) string {
	var sb strings.Builder
	for _, c := range r.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			sb.WriteString(tc.Text)
		}
	}
	return sb.String()
}
