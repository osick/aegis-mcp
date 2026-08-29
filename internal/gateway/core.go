package gateway

import (
	"context"
	"fmt"

	"github.com/osick/aegis-mcp/internal/audit"
	"github.com/osick/aegis-mcp/internal/enforcer"
	"github.com/osick/aegis-mcp/internal/profilestate"
)

// Core is the SDK-independent orchestration layer: it ties together the
// Registry, Enforcer, profile state, and audit log.
type Core struct {
	reg *Registry
	enf *enforcer.Enforcer
	ps  *profilestate.State
	aud *audit.Logger
}

// NewCore constructs the Core. All dependencies are required.
func NewCore(reg *Registry, enf *enforcer.Enforcer, ps *profilestate.State, aud *audit.Logger) *Core {
	return &Core{reg: reg, enf: enf, ps: ps, aud: aud}
}

// ListTools returns the profile-filtered, namespaced tool set visible to the active profile.
func (c *Core) ListTools(ctx context.Context) ([]AggregatedTool, error) {
	all, err := c.reg.AllTools(ctx)
	if err != nil {
		return nil, err
	}
	profile := c.ps.Active()
	var out []AggregatedTool
	for _, t := range all {
		if c.enf.AuthorizeTool(profile, enforcer.Capability{Server: t.Server, Tool: t.Tool}).Allowed {
			out = append(out, t)
		}
	}
	return out, nil
}

// CallTool authorizes the call by wire name, audits the decision, and forwards
// only if the active profile permits the tool.
func (c *Core) CallTool(ctx context.Context, wire string, args map[string]any) (string, error) {
	server, tool, ok := c.reg.resolveTool(wire)
	if !ok {
		// The wire-name map is populated by AllTools (via ListTools). A host may call a
		// tool from a cached list without re-listing this session, so lazily populate
		// the map on a miss before failing (mirrors ReadResource's AllResources call).
		if _, err := c.reg.AllTools(ctx); err != nil {
			return "", err
		}
		server, tool, ok = c.reg.resolveTool(wire)
		if !ok {
			return "", fmt.Errorf("unknown tool %q", wire)
		}
	}
	profile := c.ps.Active()
	d := c.enf.AuthorizeTool(profile, enforcer.Capability{Server: server, Tool: tool})
	if !d.Allowed {
		c.aud.Emit(audit.Record{
			Decision:   "deny",
			Profile:    profile,
			Capability: server + "." + tool,
			Reason:     d.Reason,
		})
		return "", fmt.Errorf("%s", d.Err.JSON())
	}
	c.aud.Emit(audit.Record{
		Decision:   "allow",
		Profile:    profile,
		Capability: server + "." + tool,
	})
	return c.reg.Router().CallByWire(ctx, wire, args)
}

// ListResources returns the profile-filtered resources visible to the active profile.
// Listing audits nothing (it is not an access event); only reads are audited.
func (c *Core) ListResources(ctx context.Context) ([]ResourceItem, error) {
	all, err := c.reg.AllResources(ctx)
	if err != nil {
		return nil, err
	}
	profile := c.ps.Active()
	var out []ResourceItem
	for _, it := range all {
		if c.enf.AuthorizeResource(profile, it.URI).Allowed {
			out = append(out, it)
		}
	}
	return out, nil
}

// ReadResource authorizes a resource read against the active profile, audits the
// decision, and forwards to the owning downstream only when allowed.
func (c *Core) ReadResource(ctx context.Context, uri string) (string, error) {
	// Ensure ownership routing is populated for this URI.
	if _, err := c.reg.AllResources(ctx); err != nil {
		return "", err
	}
	profile := c.ps.Active()
	d := c.enf.AuthorizeResource(profile, uri)
	if !d.Allowed {
		c.aud.Emit(audit.Record{
			Decision: "deny",
			Profile:  profile,
			URI:      uri,
			Reason:   d.Reason,
		})
		return "", fmt.Errorf("%s", d.Err.JSON())
	}
	c.aud.Emit(audit.Record{
		Decision: "allow",
		Profile:  profile,
		URI:      uri,
	})
	return c.reg.Router().ReadByURI(ctx, uri)
}

// SetProfileResult is the structured response returned to the MCP host.
type SetProfileResult struct {
	Code       string
	Active     string
	ApprovalID string
}

// SetProfile applies the transition graph. human=false means the agent requested it.
func (c *Core) SetProfile(target string, human bool) SetProfileResult {
	src := profilestate.SourceAgent
	if human {
		src = profilestate.SourceHuman
	}
	res := c.ps.RequestSwitch(target, src)
	switch res.Outcome {
	case profilestate.OutcomeSwitched:
		c.aud.Emit(audit.Record{Decision: "switch", Profile: res.Active, Source: srcStr(human)})
		return SetProfileResult{Code: "OK", Active: res.Active}
	case profilestate.OutcomePending:
		c.aud.Emit(audit.Record{
			Decision: "pending",
			Profile:  res.Active,
			Reason:   "escalation to " + target,
			Source:   srcStr(human),
		})
		return SetProfileResult{Code: "AEGIS_PENDING_APPROVAL", Active: res.Active, ApprovalID: res.ApprovalID}
	default:
		c.aud.Emit(audit.Record{Decision: "deny", Profile: res.Active, Reason: "unknown profile " + target})
		return SetProfileResult{Code: "AEGIS_PROFILE_UNKNOWN", Active: res.Active}
	}
}

// ApplyApproval completes a pending escalation after the human approves it via
// the CLI, auditing the applied switch as a human decision.
func (c *Core) ApplyApproval(id string) bool {
	if !c.ps.ApplyIfApproved(id) {
		return false
	}
	c.aud.Emit(audit.Record{Decision: "switch", Profile: c.ps.Active(), Source: srcStr(true)})
	return true
}

func srcStr(human bool) string {
	if human {
		return "human"
	}
	return "agent"
}
