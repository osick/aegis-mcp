package gateway

import (
	"context"
	"testing"
)

// fakeClient is an in-memory DownstreamClient for tests.
type fakeClient struct {
	tools     []ToolDef
	resources []string
	called    []string
}

func (f *fakeClient) ListTools(context.Context) ([]ToolDef, error)    { return f.tools, nil }
func (f *fakeClient) ListResources(context.Context) ([]string, error) { return f.resources, nil }
func (f *fakeClient) CallTool(_ context.Context, tool string, _ map[string]any) (string, error) {
	f.called = append(f.called, tool)
	return "ok:" + tool, nil
}
func (f *fakeClient) ReadResource(context.Context, string) (string, error) { return "data", nil }
func (f *fakeClient) Close() error                                         { return nil }

func TestFakeSatisfiesInterface(t *testing.T) {
	var _ DownstreamClient = &fakeClient{}
}
