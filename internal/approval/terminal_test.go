package approval

import (
	"bytes"
	"strings"
	"testing"
)

func TestTerminalChannelNotify(t *testing.T) {
	var buf bytes.Buffer
	ch := NewTerminalChannel(&buf)
	ch.Notify(Request{ID: "apr_7", FromProf: "default", ToProf: "deploy"})

	out := buf.String()
	if !strings.Contains(out, "apr_7") {
		t.Errorf("output must contain the approval id: %q", out)
	}
	if !strings.Contains(out, "deploy") {
		t.Errorf("output must name the target profile: %q", out)
	}
	if !strings.Contains(out, "aegis approve ") {
		t.Errorf("output must instruct how to approve: %q", out)
	}
	if !strings.Contains(out, "aegis deny ") {
		t.Errorf("output must instruct how to deny: %q", out)
	}
}

func TestTerminalChannelSatisfiesChannel(t *testing.T) {
	var _ Channel = NewTerminalChannel(&bytes.Buffer{})
}
