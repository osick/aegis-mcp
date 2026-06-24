// Package gateway is the I/O shell adapting the MCP SDK to the pure core.
package gateway

import "context"

// ToolDef is a downstream tool as Aegis tracks it (SDK-independent).
type ToolDef struct {
	Name        string
	Description string
	// InputSchema is the downstream tool's JSON Schema (typically a map[string]any).
	// It must be forwarded upward or the tool becomes uncallable by the host.
	InputSchema any
}

// DownstreamClient is the minimal surface Aegis needs from each downstream server.
type DownstreamClient interface {
	ListTools(ctx context.Context) ([]ToolDef, error)
	ListResources(ctx context.Context) ([]string, error)
	CallTool(ctx context.Context, tool string, args map[string]any) (string, error)
	ReadResource(ctx context.Context, uri string) (string, error)
	Close() error
}
