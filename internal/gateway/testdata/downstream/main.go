// Command downstream is a minimal stdio MCP server used by gateway DialStdio tests.
package main

import (
	"context"
	"log"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
	s := mcp.NewServer(&mcp.Implementation{Name: "downstream", Version: "0.0.1"}, nil)
	type echoIn struct {
		Msg string `json:"msg"`
	}
	mcp.AddTool(s, &mcp.Tool{Name: "echo", Description: "Echo a message"},
		func(ctx context.Context, _ *mcp.CallToolRequest, in echoIn) (*mcp.CallToolResult, any, error) {
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "echo:" + in.Msg}}}, nil, nil
		})
	if err := s.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatal(err)
	}
}
