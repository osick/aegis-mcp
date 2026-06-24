package naming

import "testing"

func TestWireRoundTripAndCollision(t *testing.T) {
	m := New()
	if err := m.Register("github", "search"); err != nil {
		t.Fatal(err)
	}
	if err := m.Register("filesystem", "search"); err != nil {
		t.Fatal(err)
	}
	if got := m.Wire("github", "search"); got != "github__search" {
		t.Errorf("Wire=%q", got)
	}
	srv, tool, ok := m.Resolve("filesystem__search")
	if !ok || srv != "filesystem" || tool != "search" {
		t.Errorf("Resolve wrong: %q %q %v", srv, tool, ok)
	}
	if _, _, ok := m.Resolve("unknown__x"); ok {
		t.Error("unknown wire name must not resolve")
	}
	if err := m.Register("github", "search"); err == nil {
		t.Error("duplicate (server,tool) must be a startup error")
	}
}

func TestWireNameCollisionRejected(t *testing.T) {
	m := New()
	if err := m.Register("a", "b__c"); err != nil {
		t.Fatal(err)
	}
	// Distinct pair, same wire string "a__b__c" — must be rejected, not silently shadow.
	if err := m.Register("a__b", "c"); err == nil {
		t.Error("wire-name collision must be a startup error")
	}
	// The original mapping must survive.
	srv, tool, ok := m.Resolve("a__b__c")
	if !ok || srv != "a" || tool != "b__c" {
		t.Errorf("original mapping must be intact, got %q %q %v", srv, tool, ok)
	}
}

func TestAnnotateDescriptionEmpty(t *testing.T) {
	if got := AnnotateDescription("   ", "github"); got == "" {
		t.Error("empty description must still produce an annotated origin")
	}
}

func TestAnnotateDescription(t *testing.T) {
	got := AnnotateDescription("read a file", "filesystem")
	if got == "read a file" || got == "" {
		t.Errorf("expected origin annotation, got %q", got)
	}
}
