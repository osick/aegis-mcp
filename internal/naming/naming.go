// Package naming maps internal server.tool identifiers to unspoofable wire names.
package naming

import (
	"fmt"
	"strings"
)

const sep = "__"

type pair struct{ server, tool string }

type Map struct {
	wireToPair map[string]pair
	seen       map[string]bool // server\x00tool
}

func New() *Map {
	return &Map{wireToPair: map[string]pair{}, seen: map[string]bool{}}
}

// Register records a downstream tool. A duplicate (server,tool) is a startup error,
// and so is a wire-name collision: distinct pairs whose names happen to produce the
// same wire string (e.g. ("a","b__c") and ("a__b","c") both yield "a__b__c"). Without
// this check the second Register would silently overwrite the first and Resolve would
// be ambiguous — a tool-shadowing vector.
func (m *Map) Register(server, tool string) error {
	key := server + "\x00" + tool
	if m.seen[key] {
		return fmt.Errorf("duplicate tool %s.%s", server, tool)
	}
	wire := Wire(server, tool)
	if existing, ok := m.wireToPair[wire]; ok {
		return fmt.Errorf("wire-name collision: %s.%s and %s.%s both map to %q",
			server, tool, existing.server, existing.tool, wire)
	}
	m.seen[key] = true
	m.wireToPair[wire] = pair{server, tool}
	return nil
}

// Wire returns the namespaced name presented to the host.
func Wire(server, tool string) string { return server + sep + tool }

// Wire (method form) for convenience.
func (m *Map) Wire(server, tool string) string { return Wire(server, tool) }

// Resolve maps a wire name back to (server, tool).
func (m *Map) Resolve(wire string) (server, tool string, ok bool) {
	p, ok := m.wireToPair[wire]
	return p.server, p.tool, ok
}

// AnnotateDescription preserves the original description and appends origin.
func AnnotateDescription(desc, server string) string {
	desc = strings.TrimSpace(desc)
	if desc == "" {
		desc = "(no description)"
	}
	return fmt.Sprintf("%s [origin: %s]", desc, server)
}
