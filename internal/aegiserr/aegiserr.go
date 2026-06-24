// Package aegiserr defines stable, machine-readable gateway errors.
package aegiserr

import "encoding/json"

type Code string

const (
	CodeCapDenied       Code = "AEGIS_CAP_DENIED"
	CodeResourceDenied  Code = "AEGIS_RESOURCE_DENIED"
	CodeProfileUnknown  Code = "AEGIS_PROFILE_UNKNOWN"
	CodePendingApproval Code = "AEGIS_PENDING_APPROVAL"
)

type Error struct {
	fields map[string]any
}

func (e *Error) JSON() string {
	b, _ := json.Marshal(e.fields)
	return string(b)
}

// Map exposes fields for embedding in MCP results.
func (e *Error) Map() map[string]any { return e.fields }

func CapDenied(capability, active, required, disclosure string) *Error {
	f := map[string]any{
		"code":           string(CodeCapDenied),
		"capability":     capability,
		"active_profile": active,
		"hint":           "capability requires a profile that allows it",
	}
	if disclosure == "verbose" && required != "" {
		f["required_profile"] = required
	}
	return &Error{fields: f}
}

func ResourceDenied(uri, active string) *Error {
	return &Error{fields: map[string]any{
		"code": string(CodeResourceDenied), "uri": uri,
		"active_profile": active, "hint": "resource not permitted in active profile",
	}}
}

func ProfileUnknown(target string) *Error {
	return &Error{fields: map[string]any{
		"code": string(CodeProfileUnknown), "requested_profile": target,
		"hint": "no such profile",
	}}
}

func PendingApproval(id, active, requested string) *Error {
	return &Error{fields: map[string]any{
		"code": string(CodePendingApproval), "approval_id": id,
		"active_profile": active, "requested_profile": requested,
		"hint": "human approval requested; re-issue set_profile or poll aegis.approval_status",
	}}
}
