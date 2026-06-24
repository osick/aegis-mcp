package audit

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestEmitWritesOneJSONLinePerRecord(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf)
	l.Emit(Record{Decision: "deny", Profile: "default", Capability: "sonarqube.scan", Reason: "denied"})
	l.Emit(Record{Decision: "allow", Profile: "default", Capability: "filesystem.read_file"})

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 JSON lines, got %d", len(lines))
	}
	var r Record
	if err := json.Unmarshal([]byte(lines[0]), &r); err != nil {
		t.Fatalf("line is not valid JSON: %v", err)
	}
	if r.Decision != "deny" || r.Capability != "sonarqube.scan" {
		t.Errorf("record fields wrong: %+v", r)
	}
	if r.TS == "" {
		t.Error("timestamp must be populated")
	}
}
