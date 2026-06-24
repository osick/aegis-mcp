// Package config defines the aegis.yaml schema and loads/validates it.
package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Server struct {
	Transport string   `yaml:"transport"`
	Command   string   `yaml:"command"`
	Args      []string `yaml:"args"`
}

type Profile struct {
	Extends            string   `yaml:"extends"`
	Allow              []string `yaml:"allow"`
	Resources          []string `yaml:"resources"`
	AllowedTransitions []string `yaml:"allowed_transitions"`
}

type Activation struct {
	DefaultProfile string `yaml:"default_profile"`
}

type Config struct {
	Servers         map[string]Server  `yaml:"servers"`
	Profiles        map[string]Profile `yaml:"profiles"`
	Activation      Activation         `yaml:"activation"`
	ErrorDisclosure string             `yaml:"error_disclosure"`
}

// Parse unmarshals and validates raw YAML. Fail-closed: any error means refuse to start.
func Parse(data []byte) (*Config, error) {
	var c Config
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("aegis.yaml: %w", err)
	}
	if c.ErrorDisclosure == "" {
		c.ErrorDisclosure = "verbose"
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

// Load reads and parses a config file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	return Parse(data)
}

func (c *Config) Validate() error {
	if c.Activation.DefaultProfile == "" {
		return fmt.Errorf("activation.default_profile is required")
	}
	if _, ok := c.Profiles[c.Activation.DefaultProfile]; !ok {
		return fmt.Errorf("activation.default_profile %q not defined", c.Activation.DefaultProfile)
	}
	for name, p := range c.Profiles {
		if p.Extends != "" {
			if _, ok := c.Profiles[p.Extends]; !ok {
				return fmt.Errorf("profile %q extends unknown profile %q", name, p.Extends)
			}
		}
		for _, t := range p.AllowedTransitions {
			if _, ok := c.Profiles[t]; !ok {
				return fmt.Errorf("profile %q: allowed_transitions target %q not defined", name, t)
			}
		}
	}
	// Detect cyclic extends here (not only at policy.Compile) so config is fail-closed
	// regardless of which caller loads it.
	for name := range c.Profiles {
		if err := c.checkExtendsCycle(name, map[string]bool{}); err != nil {
			return err
		}
	}
	switch c.ErrorDisclosure {
	case "verbose", "minimal":
	default:
		return fmt.Errorf("error_disclosure must be verbose|minimal, got %q", c.ErrorDisclosure)
	}
	return nil
}

func (c *Config) checkExtendsCycle(name string, seen map[string]bool) error {
	if seen[name] {
		return fmt.Errorf("profile %q: cyclic extends", name)
	}
	seen[name] = true
	p, ok := c.Profiles[name]
	if !ok || p.Extends == "" {
		return nil
	}
	return c.checkExtendsCycle(p.Extends, seen)
}
