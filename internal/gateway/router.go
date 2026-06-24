package gateway

import (
	"context"
	"fmt"
)

// Router resolves namespaced wire names and resource URIs to the correct downstream
// client. It resolves through the Registry, which guards the lookup maps.
type Router struct {
	reg *Registry
}

// CallByWire resolves a namespaced wire name and forwards to the right downstream.
func (r *Router) CallByWire(ctx context.Context, wire string, args map[string]any) (string, error) {
	server, tool, ok := r.reg.resolveTool(wire)
	if !ok {
		return "", fmt.Errorf("unknown tool %q", wire)
	}
	c, ok := r.reg.clients[server]
	if !ok {
		return "", fmt.Errorf("server %q not connected", server)
	}
	return c.CallTool(ctx, tool, args)
}

// ReadByURI resolves a resource URI to its owning downstream and reads it there.
// Reads only ever go to the owning server.
func (r *Router) ReadByURI(ctx context.Context, uri string) (string, error) {
	server, ok := r.reg.ownerOf(uri)
	if !ok {
		return "", fmt.Errorf("unknown resource %q", uri)
	}
	c, ok := r.reg.clients[server]
	if !ok {
		return "", fmt.Errorf("server %q not connected", server)
	}
	return c.ReadResource(ctx, uri)
}
