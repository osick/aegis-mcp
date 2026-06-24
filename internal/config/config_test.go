package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aegis.yaml")
	if err := os.WriteFile(path, []byte(sample), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Activation.DefaultProfile != "default" {
		t.Errorf("loaded config not parsed correctly")
	}
}

func TestLoadMissingFileFailsClosed(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "nope.yaml")); err == nil {
		t.Fatal("missing config file must be an error (fail-closed)")
	}
}

func TestValidateRejectsCyclicExtends(t *testing.T) {
	bad := `
profiles:
  a: { extends: b }
  b: { extends: a }
activation: { default_profile: a }
`
	if _, err := Parse([]byte(bad)); err == nil {
		t.Fatal("cyclic extends must be rejected at config validation (fail-closed)")
	}
}

const sample = `
servers:
  filesystem: { transport: stdio, command: "mcp-fs", args: ["/repo"] }
profiles:
  default:
    allow: ["filesystem.read_file"]
    resources: ["file:///repo/**"]
    allowed_transitions: ["code-review"]
  code-review:
    extends: default
    allow: ["sonarqube.*"]
    allowed_transitions: ["default"]
activation:
  default_profile: default
error_disclosure: verbose
`

func TestLoadValidConfig(t *testing.T) {
	c, err := Parse([]byte(sample))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.Servers["filesystem"].Command != "mcp-fs" {
		t.Errorf("server command not parsed: %+v", c.Servers["filesystem"])
	}
	if got := c.Profiles["default"].AllowedTransitions; len(got) != 1 || got[0] != "code-review" {
		t.Errorf("transitions not parsed: %v", got)
	}
	if c.Activation.DefaultProfile != "default" {
		t.Errorf("default_profile not parsed")
	}
}

func TestValidateRejectsUnknownDefaultProfile(t *testing.T) {
	_, err := Parse([]byte("activation:\n  default_profile: nope\n"))
	if err == nil {
		t.Fatal("expected validation error for unknown default_profile")
	}
}

func TestValidateRejectsUnknownTransitionTarget(t *testing.T) {
	bad := `
profiles:
  default: { allow: [], allowed_transitions: ["ghost"] }
activation: { default_profile: default }
`
	if _, err := Parse([]byte(bad)); err == nil {
		t.Fatal("expected validation error for transition to unknown profile")
	}
}
