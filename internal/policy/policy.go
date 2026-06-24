// Package policy is the pure, network-free decision core compiled from config.
package policy

import (
	"fmt"
	"path"
	"sort"

	"github.com/aegis-mcp/aegis/internal/config"
)

type compiledProfile struct {
	tools       []string
	resources   []string
	transitions map[string]bool
}

type Policy struct {
	profiles map[string]compiledProfile
}

// Compile flattens extends-chains once so lookups are pure map/glob ops.
func Compile(c *config.Config) (*Policy, error) {
	pol := &Policy{profiles: map[string]compiledProfile{}}
	for name := range c.Profiles {
		tools, res, err := flatten(c, name, map[string]bool{})
		if err != nil {
			return nil, err
		}
		trans := map[string]bool{}
		for _, t := range c.Profiles[name].AllowedTransitions {
			trans[t] = true
		}
		pol.profiles[name] = compiledProfile{tools: tools, resources: res, transitions: trans}
	}
	return pol, nil
}

func flatten(c *config.Config, name string, seen map[string]bool) (tools, res []string, err error) {
	if seen[name] {
		return nil, nil, fmt.Errorf("profile %q: cyclic extends", name)
	}
	seen[name] = true
	p, ok := c.Profiles[name]
	if !ok {
		return nil, nil, fmt.Errorf("profile %q not defined", name)
	}
	if p.Extends != "" {
		bt, br, err := flatten(c, p.Extends, seen)
		if err != nil {
			return nil, nil, err
		}
		tools, res = append(tools, bt...), append(res, br...)
	}
	tools = append(tools, p.Allow...)
	res = append(res, p.Resources...)
	return tools, res, nil
}

// IsToolAllowed reports whether capability "server.tool" is permitted in profile.
func (p *Policy) IsToolAllowed(profile, capability string) bool {
	cp, ok := p.profiles[profile]
	if !ok {
		return false
	}
	for _, pat := range cp.tools {
		if matchGlob(pat, capability) {
			return true
		}
	}
	return false
}

// matchGlob matches a single-segment glob on the tool portion (server is literal).
func matchGlob(pattern, s string) bool {
	ok, err := path.Match(pattern, s)
	return err == nil && ok
}

// FindGrantingProfile returns the lexicographically-first profile whose allow-list
// would permit the capability, for populating "required_profile" in verbose errors.
// Returns ok=false if no profile grants it.
func (p *Policy) FindGrantingProfile(capability string) (string, bool) {
	names := make([]string, 0, len(p.profiles))
	for name := range p.profiles {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if p.IsToolAllowed(name, capability) {
			return name, true
		}
	}
	return "", false
}
