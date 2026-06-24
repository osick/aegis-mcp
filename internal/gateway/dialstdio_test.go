package gateway

import (
	"context"
	"os/exec"
	"testing"
)

// TestDialStdioAgainstRealSubprocess launches a real stdio MCP server as a
// subprocess via DialStdio and exercises the wrapped client end to end.
func TestDialStdioAgainstRealSubprocess(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not on PATH; skipping subprocess dial test")
	}
	ctx := context.Background()

	client, err := DialStdio(ctx, "go", []string{"run", "./testdata/downstream"})
	if err != nil {
		t.Fatalf("DialStdio: %v", err)
	}
	defer client.Close()

	tools, err := client.ListTools(ctx)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	found := false
	for _, td := range tools {
		if td.Name == "echo" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected echo tool from subprocess, got %+v", tools)
	}

	out, err := client.CallTool(ctx, "echo", map[string]any{"msg": "hi"})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if out != "echo:hi" {
		t.Errorf("unexpected subprocess result: %q", out)
	}
}
