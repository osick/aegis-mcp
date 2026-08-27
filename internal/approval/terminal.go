package approval

import (
	"fmt"
	"io"
)

// TerminalChannel notifies a human of a pending escalation by writing to a stream
// (typically stderr), telling them the approval id, the target profile, and the
// exact CLI command to approve it.
type TerminalChannel struct {
	w io.Writer
}

// NewTerminalChannel returns a TerminalChannel writing to w.
func NewTerminalChannel(w io.Writer) *TerminalChannel {
	return &TerminalChannel{w: w}
}

// Notify prints the escalation request and how to approve it.
func (t *TerminalChannel) Notify(r Request) {
	fmt.Fprintf(t.w, "[aegis] approval required: id=%s requesting profile %q\n", r.ID, r.ToProf)
	fmt.Fprintf(t.w, "[aegis] to approve, run: aegis approve %s\n", r.ID)
	fmt.Fprintf(t.w, "[aegis] to deny,    run: aegis deny %s\n", r.ID)
}
