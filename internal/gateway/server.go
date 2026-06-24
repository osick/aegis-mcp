package gateway

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const serverInstructions = "You are operating behind Aegis-MCP. Every tool is prefixed with its server origin via a double underscore (e.g. filesystem__read_file). Use the prefixed names exactly as listed. Some profile switches require human approval."

// textResult builds a non-error CallToolResult carrying a single text block.
func textResult(s string) *mcp.CallToolResult {
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: s}}}
}

func errorResult(s string) *mcp.CallToolResult {
	return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: s}}}
}

// BuildServer wires a Core into an MCP server: meta-tools plus an enforcing
// receiving middleware that filters tools/list, gates tools/call, and filters
// resources/list and resources/read against the active profile.
func BuildServer(core *Core) *mcp.Server {
	srv := mcp.NewServer(
		&mcp.Implementation{Name: "aegis-mcp", Version: "0.1.0"},
		&mcp.ServerOptions{Instructions: serverInstructions},
	)

	// Meta-tool: aegis.set_profile
	type setProfileIn struct {
		Name string `json:"name"`
	}
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "aegis.set_profile",
		Description: "Request a switch to a different Aegis profile. Some switches require human approval.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in setProfileIn) (*mcp.CallToolResult, any, error) {
		res := core.SetProfile(in.Name, false)
		text := fmt.Sprintf("code=%s active=%s approval=%s", res.Code, res.Active, res.ApprovalID)
		return textResult(text), nil, nil
	})

	// Meta-tool: aegis.approval_status
	type approvalStatusIn struct {
		ID string `json:"id"`
	}
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "aegis.approval_status",
		Description: "Apply a pending profile-switch approval by id, or report it is still pending.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in approvalStatusIn) (*mcp.CallToolResult, any, error) {
		if core.ApplyApproval(in.ID) {
			return textResult("approved"), nil, nil
		}
		return textResult("pending"), nil, nil
	})

	srv.AddReceivingMiddleware(enforcingMiddleware(core))
	return srv
}

func enforcingMiddleware(core *Core) mcp.Middleware {
	return func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			switch method {
			case "tools/list":
				return handleToolsList(ctx, core, next, method, req)
			case "tools/call":
				return handleToolsCall(ctx, core, next, method, req)
			case "resources/list":
				return handleResourcesList(ctx, core)
			case "resources/read":
				return handleResourcesRead(ctx, core, req)
			default:
				return next(ctx, method, req)
			}
		}
	}
}

func handleToolsList(ctx context.Context, core *Core, next mcp.MethodHandler, method string, req mcp.Request) (mcp.Result, error) {
	downstream, err := core.ListTools(ctx)
	if err != nil {
		return nil, err
	}
	tools := make([]*mcp.Tool, 0, len(downstream))
	for _, t := range downstream {
		tools = append(tools, &mcp.Tool{
			Name:        t.Wire,
			Description: t.Description,
			InputSchema: t.InputSchema,
		})
	}
	// Let the default handler produce the registered meta-tools, then merge.
	res, err := next(ctx, method, req)
	if err != nil {
		return nil, err
	}
	if ltr, ok := res.(*mcp.ListToolsResult); ok {
		tools = append(tools, ltr.Tools...)
	}
	return &mcp.ListToolsResult{Tools: tools}, nil
}

func handleToolsCall(ctx context.Context, core *Core, next mcp.MethodHandler, method string, req mcp.Request) (mcp.Result, error) {
	ctr, ok := req.(*mcp.CallToolRequest)
	if !ok {
		return next(ctx, method, req)
	}
	name := ctr.Params.Name
	if len(name) >= 6 && name[:6] == "aegis." {
		return next(ctx, method, req)
	}
	var args map[string]any
	if len(ctr.Params.Arguments) > 0 {
		if err := json.Unmarshal(ctr.Params.Arguments, &args); err != nil {
			return errorResult(fmt.Sprintf("invalid arguments: %v", err)), nil
		}
	}
	out, err := core.CallTool(ctx, name, args)
	if err != nil {
		return errorResult(err.Error()), nil
	}
	return textResult(out), nil
}

func handleResourcesList(ctx context.Context, core *Core) (mcp.Result, error) {
	items, err := core.ListResources(ctx)
	if err != nil {
		return nil, err
	}
	resources := make([]*mcp.Resource, 0, len(items))
	for _, it := range items {
		resources = append(resources, &mcp.Resource{URI: it.URI, Name: it.URI})
	}
	return &mcp.ListResourcesResult{Resources: resources}, nil
}

func handleResourcesRead(ctx context.Context, core *Core, req mcp.Request) (mcp.Result, error) {
	rrr, ok := req.(*mcp.ReadResourceRequest)
	if !ok {
		return nil, fmt.Errorf("unexpected resources/read request type")
	}
	uri := rrr.Params.URI
	out, err := core.ReadResource(ctx, uri)
	if err != nil {
		// Block the read on deny; surface the structured error.
		return nil, err
	}
	return &mcp.ReadResourceResult{
		Contents: []*mcp.ResourceContents{{URI: uri, Text: out}},
	}, nil
}
