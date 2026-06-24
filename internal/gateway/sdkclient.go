package gateway

import (
	"context"
	"os/exec"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// sdkClient wraps a live MCP client session as a DownstreamClient.
type sdkClient struct {
	session *mcp.ClientSession
}

// newSDKClient adapts an established MCP client session to the DownstreamClient
// interface. It is independently testable over an in-memory transport.
func newSDKClient(session *mcp.ClientSession) DownstreamClient {
	return &sdkClient{session: session}
}

func (c *sdkClient) ListTools(ctx context.Context) ([]ToolDef, error) {
	res, err := c.session.ListTools(ctx, &mcp.ListToolsParams{})
	if err != nil {
		return nil, err
	}
	out := make([]ToolDef, 0, len(res.Tools))
	for _, t := range res.Tools {
		out = append(out, ToolDef{
			Name:        t.Name,
			Description: t.Description,
			InputSchema: t.InputSchema,
		})
	}
	return out, nil
}

func (c *sdkClient) ListResources(ctx context.Context) ([]string, error) {
	res, err := c.session.ListResources(ctx, &mcp.ListResourcesParams{})
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(res.Resources))
	for _, r := range res.Resources {
		out = append(out, r.URI)
	}
	return out, nil
}

func (c *sdkClient) CallTool(ctx context.Context, tool string, args map[string]any) (string, error) {
	res, err := c.session.CallTool(ctx, &mcp.CallToolParams{Name: tool, Arguments: args})
	if err != nil {
		return "", err
	}
	return joinTextContent(res.Content), nil
}

func (c *sdkClient) ReadResource(ctx context.Context, uri string) (string, error) {
	res, err := c.session.ReadResource(ctx, &mcp.ReadResourceParams{URI: uri})
	if err != nil {
		return "", err
	}
	var sb strings.Builder
	for _, rc := range res.Contents {
		sb.WriteString(rc.Text)
	}
	return sb.String(), nil
}

func (c *sdkClient) Close() error { return c.session.Close() }

// joinTextContent concatenates the text of all TextContent blocks in a result.
func joinTextContent(content []mcp.Content) string {
	var sb strings.Builder
	for _, ct := range content {
		if tc, ok := ct.(*mcp.TextContent); ok {
			sb.WriteString(tc.Text)
		}
	}
	return sb.String()
}

// DialStdio launches a downstream MCP server as a stdio subprocess and returns a
// connected DownstreamClient. Kept thin so newSDKClient stays unit-testable.
func DialStdio(ctx context.Context, command string, args []string) (DownstreamClient, error) {
	client := mcp.NewClient(&mcp.Implementation{Name: "aegis-mcp", Version: "0.1.0"}, nil)
	transport := &mcp.CommandTransport{Command: exec.Command(command, args...)}
	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		return nil, err
	}
	return newSDKClient(session), nil
}
