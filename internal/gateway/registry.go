package gateway

import (
	"context"
	"sort"
	"sync"

	"github.com/osick/aegis-mcp/internal/naming"
)

// AggregatedTool is a downstream tool with its namespaced wire name.
type AggregatedTool struct {
	Server      string
	Tool        string
	Wire        string
	Description string
	InputSchema any
}

// ResourceItem is a downstream resource with its owning server.
type ResourceItem struct {
	Server string
	URI    string
}

// Registry aggregates downstream clients and manages wire-name + resource ownership
// mapping. The maps are rebuilt by AllTools/AllResources and read by the Router during
// CallByWire/ReadByURI; mu guards those reads/writes so the gateway is safe under
// concurrent or async request dispatch (not only the serial single-connection case).
type Registry struct {
	clients       map[string]DownstreamClient
	mu            sync.RWMutex
	names         *naming.Map
	resourceOwner map[string]string // uri -> server, rebuilt by AllResources
	router        *Router
}

// NewRegistry constructs a Registry from the given map of server-name → client.
func NewRegistry(clients map[string]DownstreamClient) (*Registry, error) {
	r := &Registry{
		clients:       clients,
		names:         naming.New(),
		resourceOwner: map[string]string{},
	}
	r.router = &Router{reg: r}
	return r, nil
}

// Router returns the Router bound to this Registry.
func (r *Registry) Router() *Router { return r.router }

// AllTools lists every downstream tool, registers wire names (collision-checked),
// and applies namespacing + description annotation. It rebuilds the wire-name map.
func (r *Registry) AllTools(ctx context.Context) ([]AggregatedTool, error) {
	servers := r.sortedServers()

	names := naming.New()
	var out []AggregatedTool
	for _, s := range servers {
		tools, err := r.clients[s].ListTools(ctx)
		if err != nil {
			continue // per-server fail-closed: drop unreachable server's tools
		}
		for _, td := range tools {
			if err := names.Register(s, td.Name); err != nil {
				return nil, err
			}
			out = append(out, AggregatedTool{
				Server:      s,
				Tool:        td.Name,
				Wire:        naming.Wire(s, td.Name),
				Description: naming.AnnotateDescription(td.Description, s),
				InputSchema: td.InputSchema,
			})
		}
	}

	r.mu.Lock()
	r.names = names
	r.mu.Unlock()
	return out, nil
}

// AllResources lists every downstream resource (deterministic server order),
// rebuilding the uri→server ownership map so reads can route to the owner.
// Per-server fail-closed: a client whose ListResources errors is skipped.
func (r *Registry) AllResources(ctx context.Context) ([]ResourceItem, error) {
	servers := r.sortedServers()

	owner := make(map[string]string)
	var out []ResourceItem
	for _, s := range servers {
		uris, err := r.clients[s].ListResources(ctx)
		if err != nil {
			continue // per-server fail-closed
		}
		for _, u := range uris {
			owner[u] = s
			out = append(out, ResourceItem{Server: s, URI: u})
		}
	}

	r.mu.Lock()
	r.resourceOwner = owner
	r.mu.Unlock()
	return out, nil
}

// resolveTool maps a wire name back to (server, tool) under the read lock.
func (r *Registry) resolveTool(wire string) (server, tool string, ok bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.names.Resolve(wire)
}

// ownerOf returns the server that owns a resource URI, under the read lock.
func (r *Registry) ownerOf(uri string) (server string, ok bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	s, ok := r.resourceOwner[uri]
	return s, ok
}

func (r *Registry) sortedServers() []string {
	servers := make([]string, 0, len(r.clients))
	for s := range r.clients {
		servers = append(servers, s)
	}
	sort.Strings(servers)
	return servers
}
