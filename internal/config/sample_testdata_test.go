package config

import "testing"

// TestLoadSampleTestdata ensures the shipped sample config parses and validates.
func TestLoadSampleTestdata(t *testing.T) {
	c, err := Load("../../testdata/aegis.yaml")
	if err != nil {
		t.Fatalf("sample testdata/aegis.yaml must parse and validate: %v", err)
	}
	if c.Activation.DefaultProfile != "default" {
		t.Errorf("expected default_profile=default, got %q", c.Activation.DefaultProfile)
	}
	for _, p := range []string{"default", "code-review", "deploy"} {
		if _, ok := c.Profiles[p]; !ok {
			t.Errorf("expected profile %q to be defined", p)
		}
	}
}
