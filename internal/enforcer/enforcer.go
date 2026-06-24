// Package enforcer is the chokepoint: filter lists, authorize calls.
package enforcer

import (
	"github.com/aegis-mcp/aegis/internal/aegiserr"
	"github.com/aegis-mcp/aegis/internal/policy"
)

type Capability struct {
	Server string
	Tool   string
}

func (c Capability) String() string { return c.Server + "." + c.Tool }

type Decision struct {
	Allowed bool
	Err     *aegiserr.Error // set when !Allowed
	Reason  string
}

type Enforcer struct {
	pol        *policy.Policy
	disclosure string
}

func New(pol *policy.Policy, disclosure string) *Enforcer {
	return &Enforcer{pol: pol, disclosure: disclosure}
}

func (e *Enforcer) FilterTools(profile string, caps []Capability) []Capability {
	var out []Capability
	for _, c := range caps {
		if e.pol.IsToolAllowed(profile, c.String()) {
			out = append(out, c)
		}
	}
	return out
}

func (e *Enforcer) AuthorizeTool(profile string, c Capability) Decision {
	if e.pol.IsToolAllowed(profile, c.String()) {
		return Decision{Allowed: true}
	}
	// In verbose mode, tell the orchestrator which profile would grant the capability
	// (omitted in minimal mode by aegiserr to avoid handing an attacker a target).
	required := ""
	if e.disclosure == "verbose" {
		if g, ok := e.pol.FindGrantingProfile(c.String()); ok {
			required = g
		}
	}
	return Decision{
		Allowed: false,
		Reason:  "not in active profile allow-list",
		Err:     aegiserr.CapDenied(c.String(), profile, required, e.disclosure),
	}
}

func (e *Enforcer) FilterResources(profile string, uris []string) []string {
	var out []string
	for _, u := range uris {
		if e.pol.IsResourceAllowed(profile, u) {
			out = append(out, u)
		}
	}
	return out
}

func (e *Enforcer) AuthorizeResource(profile, uri string) Decision {
	if e.pol.IsResourceAllowed(profile, uri) {
		return Decision{Allowed: true}
	}
	return Decision{Allowed: false, Reason: "resource not permitted",
		Err: aegiserr.ResourceDenied(uri, profile)}
}
