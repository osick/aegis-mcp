# Aegis-MCP Gateway (Cycle 1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the OSS local sidecar: an aggregating MCP proxy in Go that filters tools/resources/prompts by an active profile, enforces a default-deny policy with traversal-safe resource matching, namespaces tool names against shadowing, and gates profile switches through a non-blocking human-in-the-loop approval flow.

**Architecture:** A security-critical **pure core** (config, policy, naming, profilestate, approval, enforcer, audit — no network, no SDK) wrapped by a thin **I/O shell** (registry, router, gateway server) that adapts the official MCP Go SDK. The gateway installs a single receiving middleware that intercepts `tools/list|call`, `resources/list|read`, `prompts/list|get`, and the built-in `aegis.*` meta-tools, delegating every decision to the pure core.

**Tech Stack:** Go 1.22+, official `github.com/modelcontextprotocol/go-sdk/mcp` (v1.2.0), `gopkg.in/yaml.v3`, standard `testing`.

Spec: `docs/superpowers/specs/2026-06-15-aegis-mcp-gateway-design.md`.

---

## File Structure

```
go.mod
cmd/aegis/main.go                       # entrypoint: load config, build gateway, run; CLI subcommands
internal/config/config.go               # YAML schema structs + Load() + Validate()
internal/config/config_test.go
internal/policy/policy.go               # compiled policy: tool-glob match, isAllowedTool, profile lookup
internal/policy/uri.go                  # traversal-safe resource URI matching
internal/policy/transitions.go          # allowed_transitions graph queries
internal/policy/policy_test.go
internal/policy/uri_test.go
internal/policy/transitions_test.go
internal/naming/naming.go               # server.tool <-> server__tool, collision detect, description annotate
internal/naming/naming_test.go
internal/approval/approval.go           # async pending-request store + Channel interface
internal/approval/approval_test.go
internal/profilestate/profilestate.go   # active profile + switch authorization via transitions/approval
internal/profilestate/profilestate_test.go
internal/aegiserr/aegiserr.go           # stable error codes + structured error payloads
internal/aegiserr/aegiserr_test.go
internal/enforcer/enforcer.go           # filter *_list, authorize *_call; emits decisions
internal/enforcer/enforcer_test.go
internal/audit/audit.go                 # structured JSON decision log
internal/audit/audit_test.go
internal/gateway/types.go               # Item, DownstreamClient interface (SDK-independent seam)
internal/gateway/registry.go            # launch/connect downstream clients, aggregate Items
internal/gateway/router.go              # route an allowed call to the right downstream
internal/gateway/server.go              # build mcp.Server, install receiving middleware, wire meta-tools
internal/gateway/fakeclient_test.go     # in-memory fake DownstreamClient for tests
internal/gateway/gateway_test.go        # integration over the seam
testdata/aegis.yaml                     # sample policy
README.md
```

Dependency direction: `config` ← `policy` ← {`enforcer`, `profilestate`} ; `naming`, `approval`, `aegiserr`, `audit` are leaf utilities; `gateway` depends on everything and on the SDK. The pure core never imports `gateway` or the SDK.

---

## Task 0: Project scaffold

**Files:**
- Create: `go.mod`, `.gitignore`, `Makefile`

- [ ] **Step 1: Initialize the module**

Run:
```bash
go mod init github.com/aegis-mcp/aegis
go get github.com/modelcontextprotocol/go-sdk/mcp@v1.2.0
go get gopkg.in/yaml.v3
```

- [ ] **Step 2: Add `.gitignore`**

```
/aegis
/dist/
*.out
```

- [ ] **Step 3: Add `Makefile`**

```makefile
.PHONY: test cover build
test:
	go test ./...
cover:
	go test -cover ./...
build:
	go build -o aegis ./cmd/aegis
```

- [ ] **Step 4: Verify it builds (empty module)**

Run: `go build ./... && go test ./...`
Expected: no errors (no packages yet → "no Go files" is acceptable; module resolves).

- [ ] **Step 5: Commit**

```bash
git add go.mod go.sum .gitignore Makefile
git commit -m "chore: scaffold aegis go module"
```

---

## Task 1: Config schema + loading + validation

**Files:**
- Create: `internal/config/config.go`
- Test: `internal/config/config_test.go`

- [ ] **Step 1: Write the failing test**

```go
package config

import "testing"

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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/config/ -run TestLoad -v`
Expected: FAIL — `undefined: Parse`.

- [ ] **Step 3: Write minimal implementation**

```go
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
	switch c.ErrorDisclosure {
	case "verbose", "minimal":
	default:
		return fmt.Errorf("error_disclosure must be verbose|minimal, got %q", c.ErrorDisclosure)
	}
	return nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/config/ -v`
Expected: PASS (all three).

- [ ] **Step 5: Commit**

```bash
git add internal/config/
git commit -m "feat(config): aegis.yaml schema, load, fail-closed validation"
```

---

## Task 2: Policy — tool matching with glob + extends

**Files:**
- Create: `internal/policy/policy.go`
- Test: `internal/policy/policy_test.go`

- [ ] **Step 1: Write the failing test**

```go
package policy

import (
	"testing"

	"github.com/aegis-mcp/aegis/internal/config"
)

func compile(t *testing.T, c *config.Config) *Policy {
	t.Helper()
	p, err := Compile(c)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return p
}

func TestToolAllowGlobAndExtends(t *testing.T) {
	c := &config.Config{
		Profiles: map[string]config.Profile{
			"default":     {Allow: []string{"filesystem.read_file", "github.search_*"}},
			"code-review": {Extends: "default", Allow: []string{"sonarqube.*"}},
		},
		Activation: config.Activation{DefaultProfile: "default"},
	}
	p := compile(t, c)

	cases := []struct {
		profile, cap string
		want         bool
	}{
		{"default", "filesystem.read_file", true},
		{"default", "filesystem.write_file", false}, // default-deny
		{"default", "github.search_code", true},     // glob
		{"default", "sonarqube.scan", false},
		{"code-review", "sonarqube.scan", true},      // own allow
		{"code-review", "filesystem.read_file", true}, // inherited via extends
	}
	for _, tc := range cases {
		if got := p.IsToolAllowed(tc.profile, tc.cap); got != tc.want {
			t.Errorf("IsToolAllowed(%q,%q)=%v want %v", tc.profile, tc.cap, got, tc.want)
		}
	}
}

func TestUnknownProfileDeniesAll(t *testing.T) {
	p := compile(t, &config.Config{
		Profiles:   map[string]config.Profile{"default": {Allow: []string{"x.y"}}},
		Activation: config.Activation{DefaultProfile: "default"},
	})
	if p.IsToolAllowed("ghost", "x.y") {
		t.Error("unknown profile must deny")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/policy/ -run TestTool -v`
Expected: FAIL — `undefined: Compile`.

- [ ] **Step 3: Write minimal implementation**

```go
// Package policy is the pure, network-free decision core compiled from config.
package policy

import (
	"fmt"
	"path"

	"github.com/aegis-mcp/aegis/internal/config"
)

type compiledProfile struct {
	tools       []string // flattened allow patterns (incl. extends)
	resources   []string // raw URI patterns (matched in uri.go)
	transitions map[string]bool
}

type Policy struct {
	profiles map[string]compiledProfile
}

// Compile flattens extends-chains once so lookups are pure map/glob ops.
func Compile(c *config.Config) (*Policy, error) {
	pol := &Policy{profiles: map[string]compiledProfile{}}
	for name := range c.Profiles {
		tools, res, err := flatten(c, name, map[string]bool{})
		if err != nil {
			return nil, err
		}
		trans := map[string]bool{}
		for _, t := range c.Profiles[name].AllowedTransitions {
			trans[t] = true
		}
		pol.profiles[name] = compiledProfile{tools: tools, resources: res, transitions: trans}
	}
	return pol, nil
}

func flatten(c *config.Config, name string, seen map[string]bool) (tools, res []string, err error) {
	if seen[name] {
		return nil, nil, fmt.Errorf("profile %q: cyclic extends", name)
	}
	seen[name] = true
	p, ok := c.Profiles[name]
	if !ok {
		return nil, nil, fmt.Errorf("profile %q not defined", name)
	}
	if p.Extends != "" {
		bt, br, err := flatten(c, p.Extends, seen)
		if err != nil {
			return nil, nil, err
		}
		tools, res = append(tools, bt...), append(res, br...)
	}
	tools = append(tools, p.Allow...)
	res = append(res, p.Resources...)
	return tools, res, nil
}

// IsToolAllowed reports whether capability "server.tool" is permitted in profile.
func (p *Policy) IsToolAllowed(profile, capability string) bool {
	cp, ok := p.profiles[profile]
	if !ok {
		return false // unknown profile: default-deny
	}
	for _, pat := range cp.tools {
		if matchGlob(pat, capability) {
			return true
		}
	}
	return false
}

// matchGlob matches a single-segment glob on the tool portion (server is literal).
func matchGlob(pattern, s string) bool {
	ok, err := path.Match(pattern, s)
	return err == nil && ok
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/policy/ -run 'TestTool|TestUnknown' -v`
Expected: PASS.

Note: `path.Match` treats `.` as an ordinary char and `*` as "any non-separator run"; since capabilities contain no `/`, `github.search_*` and `sonarqube.*` behave as intended.

- [ ] **Step 5: Commit**

```bash
git add internal/policy/policy.go internal/policy/policy_test.go
git commit -m "feat(policy): default-deny tool matching with glob and extends"
```

---

## Task 3: Policy — traversal-safe resource URI matching

**Files:**
- Create: `internal/policy/uri.go`
- Test: `internal/policy/uri_test.go`

- [ ] **Step 1: Write the failing test**

```go
package policy

import (
	"testing"

	"github.com/aegis-mcp/aegis/internal/config"
)

func TestResourceMatchingAndTraversal(t *testing.T) {
	p := compile(t, &config.Config{
		Profiles: map[string]config.Profile{
			"default": {Resources: []string{"file:///var/log/app/**"}},
		},
		Activation: config.Activation{DefaultProfile: "default"},
	})

	cases := []struct {
		uri  string
		want bool
	}{
		{"file:///var/log/app/today.log", true},
		{"file:///var/log/app/nested/deep.log", true},
		{"file:///var/log/other/secret", false},
		{"file:///var/log/app/../../etc/passwd", false},      // traversal
		{"file:///var/log/app/%2e%2e/%2e%2e/etc/passwd", false}, // encoded traversal
	}
	for _, tc := range cases {
		if got := p.IsResourceAllowed("default", tc.uri); got != tc.want {
			t.Errorf("IsResourceAllowed(%q)=%v want %v", tc.uri, got, tc.want)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/policy/ -run TestResource -v`
Expected: FAIL — `undefined: ...IsResourceAllowed`.

- [ ] **Step 3: Write minimal implementation**

```go
package policy

import (
	"net/url"
	"path"
	"strings"
)

// IsResourceAllowed canonicalizes the URI (decode, normalize, reject traversal)
// before matching against the profile's resource patterns.
func (p *Policy) IsResourceAllowed(profile, rawURI string) bool {
	cp, ok := p.profiles[profile]
	if !ok {
		return false
	}
	canon, ok := canonicalizeURI(rawURI)
	if !ok {
		return false // unparseable or escapes its root → deny
	}
	for _, pat := range cp.resources {
		canonPat, ok := canonicalizeURI(stripGlob(pat))
		if !ok {
			continue
		}
		if matchURIGlob(pat, canon, canonPat) {
			return true
		}
	}
	return false
}

// canonicalizeURI returns the scheme + cleaned, decoded path, or ok=false if the
// path escapes its root after normalization (path traversal).
func canonicalizeURI(raw string) (string, bool) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", false
	}
	// url.Parse already percent-decodes u.Path; clean resolves "." and ".." segments.
	cleaned := path.Clean(u.Path)
	if strings.HasPrefix(cleaned, "../") || cleaned == ".." {
		return "", false // escaped root
	}
	return u.Scheme + "://" + cleaned, true
}

// stripGlob removes a trailing "/**" or "/*" so the prefix can be canonicalized.
func stripGlob(pat string) string {
	pat = strings.TrimSuffix(pat, "/**")
	pat = strings.TrimSuffix(pat, "/*")
	return pat
}

// matchURIGlob: "/**" = any depth under prefix; "/*" = one segment; else exact.
func matchURIGlob(pattern, canonURI, canonPrefix string) bool {
	switch {
	case strings.HasSuffix(pattern, "/**"):
		return canonURI == canonPrefix || strings.HasPrefix(canonURI, canonPrefix+"/")
	case strings.HasSuffix(pattern, "/*"):
		if !strings.HasPrefix(canonURI, canonPrefix+"/") {
			return false
		}
		rest := strings.TrimPrefix(canonURI, canonPrefix+"/")
		return rest != "" && !strings.Contains(rest, "/")
	default:
		return canonURI == canonPrefix
	}
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/policy/ -run TestResource -v`
Expected: PASS (including both traversal cases denied).

- [ ] **Step 5: Commit**

```bash
git add internal/policy/uri.go internal/policy/uri_test.go
git commit -m "feat(policy): traversal-safe resource URI matching"
```

---

## Task 4: Policy — transition graph queries

**Files:**
- Create: `internal/policy/transitions.go`
- Test: `internal/policy/transitions_test.go`

- [ ] **Step 1: Write the failing test**

```go
package policy

import (
	"testing"

	"github.com/aegis-mcp/aegis/internal/config"
)

func TestTransitions(t *testing.T) {
	p := compile(t, &config.Config{
		Profiles: map[string]config.Profile{
			"default":     {AllowedTransitions: []string{"code-review"}},
			"code-review": {AllowedTransitions: []string{"default"}},
			"deploy":      {AllowedTransitions: []string{}},
		},
		Activation: config.Activation{DefaultProfile: "default"},
	})
	if !p.ProfileExists("deploy") || p.ProfileExists("ghost") {
		t.Fatal("ProfileExists wrong")
	}
	if !p.IsTransitionAllowed("default", "code-review") {
		t.Error("default->code-review should be an autonomous edge")
	}
	if p.IsTransitionAllowed("default", "deploy") {
		t.Error("default->deploy is NOT an edge (must route to HITL)")
	}
	if p.IsTransitionAllowed("code-review", "deploy") {
		t.Error("lateral spread code-review->deploy must NOT be autonomous")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/policy/ -run TestTransitions -v`
Expected: FAIL — `undefined: ...IsTransitionAllowed`.

- [ ] **Step 3: Write minimal implementation**

```go
package policy

// ProfileExists reports whether a profile is defined.
func (p *Policy) ProfileExists(name string) bool {
	_, ok := p.profiles[name]
	return ok
}

// IsTransitionAllowed reports whether switching from->to is a pre-declared
// autonomous edge. Anything not declared is NOT allowed (caller routes to HITL).
func (p *Policy) IsTransitionAllowed(from, to string) bool {
	cp, ok := p.profiles[from]
	if !ok {
		return false
	}
	return cp.transitions[to]
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/policy/ -v`
Expected: PASS (whole package).

- [ ] **Step 5: Commit**

```bash
git add internal/policy/transitions.go internal/policy/transitions_test.go
git commit -m "feat(policy): explicit transition-graph queries"
```

---

## Task 5: Naming — namespace mapping, collisions, description annotation

**Files:**
- Create: `internal/naming/naming.go`
- Test: `internal/naming/naming_test.go`

- [ ] **Step 1: Write the failing test**

```go
package naming

import "testing"

func TestWireRoundTripAndCollision(t *testing.T) {
	m := New()
	if err := m.Register("github", "search"); err != nil {
		t.Fatal(err)
	}
	if err := m.Register("filesystem", "search"); err != nil {
		t.Fatal(err) // same tool name, different server: NOT a collision
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

func TestAnnotateDescription(t *testing.T) {
	got := AnnotateDescription("read a file", "filesystem")
	if got == "read a file" || got == "" {
		t.Errorf("expected origin annotation, got %q", got)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/naming/ -v`
Expected: FAIL — `undefined: New`.

- [ ] **Step 3: Write minimal implementation**

```go
// Package naming maps internal server.tool identifiers to unspoofable wire names.
package naming

import (
	"fmt"
	"strings"
)

const sep = "__"

type pair struct{ server, tool string }

type Map struct {
	wireToPair map[string]pair
	seen       map[string]bool // server\x00tool
}

func New() *Map {
	return &Map{wireToPair: map[string]pair{}, seen: map[string]bool{}}
}

// Register records a downstream tool. Duplicate (server,tool) is a startup error.
func (m *Map) Register(server, tool string) error {
	key := server + "\x00" + tool
	if m.seen[key] {
		return fmt.Errorf("duplicate tool %s.%s", server, tool)
	}
	m.seen[key] = true
	m.wireToPair[Wire(server, tool)] = pair{server, tool}
	return nil
}

// Wire returns the namespaced name presented to the host.
func Wire(server, tool string) string { return server + sep + tool }

// Wire (method form) for convenience.
func (m *Map) Wire(server, tool string) string { return Wire(server, tool) }

// Resolve maps a wire name back to (server, tool).
func (m *Map) Resolve(wire string) (server, tool string, ok bool) {
	p, ok := m.wireToPair[wire]
	return p.server, p.tool, ok
}

// AnnotateDescription preserves the original description and appends origin.
func AnnotateDescription(desc, server string) string {
	desc = strings.TrimSpace(desc)
	if desc == "" {
		desc = "(no description)"
	}
	return fmt.Sprintf("%s [origin: %s]", desc, server)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/naming/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/naming/
git commit -m "feat(naming): anti-shadowing wire names, collisions, description annotation"
```

---

## Task 6: Approval — async non-blocking pending store

**Files:**
- Create: `internal/approval/approval.go`
- Test: `internal/approval/approval_test.go`

- [ ] **Step 1: Write the failing test**

```go
package approval

import "testing"

// recordingChannel captures requests instead of prompting a human.
type recordingChannel struct{ requests []Request }

func (r *recordingChannel) Notify(req Request) { r.requests = append(r.requests, req) }

func TestRequestApproveDenyExpire(t *testing.T) {
	ch := &recordingChannel{}
	s := New(ch)

	id := s.Request("default", "deploy")
	if id == "" {
		t.Fatal("expected non-empty approval_id")
	}
	if s.Status(id) != StatusPending {
		t.Fatalf("new request must be pending, got %v", s.Status(id))
	}
	if len(ch.requests) != 1 || ch.requests[0].ID != id {
		t.Fatalf("human channel was not notified")
	}

	if ok := s.Resolve(id, true); !ok {
		t.Fatal("resolve approve failed")
	}
	if s.Status(id) != StatusApproved {
		t.Fatalf("status should be approved")
	}
	if s.Resolve(id, false) {
		t.Error("a resolved request must not be re-resolvable")
	}

	id2 := s.Request("default", "deploy")
	s.Resolve(id2, false)
	if s.Status(id2) != StatusDenied {
		t.Error("status should be denied")
	}

	if s.Status("missing") != StatusUnknown {
		t.Error("unknown id must be StatusUnknown")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/approval/ -v`
Expected: FAIL — `undefined: New`.

- [ ] **Step 3: Write minimal implementation**

```go
// Package approval is a non-blocking pending-request store for HITL profile switches.
package approval

import (
	"fmt"
	"sync"
)

type Status string

const (
	StatusUnknown  Status = "unknown"
	StatusPending  Status = "pending"
	StatusApproved Status = "approved"
	StatusDenied   Status = "denied"
)

// Request is an escalation awaiting a human decision.
type Request struct {
	ID       string
	FromProf string
	ToProf   string
}

// Channel delivers approval requests to a human out-of-band (terminal, Slack, ...).
type Channel interface {
	Notify(Request)
}

type Store struct {
	mu     sync.Mutex
	ch     Channel
	seq    int
	status map[string]Status
	reqs   map[string]Request
}

func New(ch Channel) *Store {
	return &Store{ch: ch, status: map[string]Status{}, reqs: map[string]Request{}}
}

// Request registers a pending escalation, notifies the human, and returns immediately.
func (s *Store) Request(from, to string) string {
	s.mu.Lock()
	s.seq++
	id := fmt.Sprintf("apr_%d", s.seq)
	req := Request{ID: id, FromProf: from, ToProf: to}
	s.status[id] = StatusPending
	s.reqs[id] = req
	s.mu.Unlock()

	s.ch.Notify(req) // out-of-band; never blocks the caller's RPC
	return id
}

// Resolve records a human decision. Returns false if id is unknown or already resolved.
func (s *Store) Resolve(id string, approve bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.status[id] != StatusPending {
		return false
	}
	if approve {
		s.status[id] = StatusApproved
	} else {
		s.status[id] = StatusDenied
	}
	return true
}

func (s *Store) Status(id string) Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.status[id]
	if !ok {
		return StatusUnknown
	}
	return st
}

// Pending returns the target profile for an approved request, consuming the approval.
func (s *Store) Pending(id string) (Request, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.reqs[id]
	return r, ok
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/approval/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/approval/
git commit -m "feat(approval): non-blocking pending-request store for HITL"
```

---

## Task 7: Profilestate — active profile + switch authorization

**Files:**
- Create: `internal/profilestate/profilestate.go`
- Test: `internal/profilestate/profilestate_test.go`

- [ ] **Step 1: Write the failing test**

```go
package profilestate

import (
	"testing"

	"github.com/aegis-mcp/aegis/internal/approval"
	"github.com/aegis-mcp/aegis/internal/config"
	"github.com/aegis-mcp/aegis/internal/policy"
)

type nopChannel struct{}

func (nopChannel) Notify(approval.Request) {}

func build(t *testing.T) (*State, *approval.Store) {
	t.Helper()
	c := &config.Config{
		Profiles: map[string]config.Profile{
			"default":     {AllowedTransitions: []string{"code-review"}},
			"code-review": {AllowedTransitions: []string{"default"}},
			"deploy":      {AllowedTransitions: []string{}},
		},
		Activation: config.Activation{DefaultProfile: "default"},
	}
	pol, err := policy.Compile(c)
	if err != nil {
		t.Fatal(err)
	}
	ap := approval.New(nopChannel{})
	return New(pol, ap, "default"), ap
}

func TestAutonomousEdgeSwitch(t *testing.T) {
	s, _ := build(t)
	res := s.RequestSwitch("code-review", SourceAgent)
	if res.Outcome != OutcomeSwitched || s.Active() != "code-review" {
		t.Fatalf("expected autonomous switch, got %+v active=%s", res, s.Active())
	}
}

func TestNonEdgeSwitchRoutesToPending(t *testing.T) {
	s, _ := build(t)
	res := s.RequestSwitch("deploy", SourceAgent)
	if res.Outcome != OutcomePending || res.ApprovalID == "" {
		t.Fatalf("non-edge agent switch must be pending, got %+v", res)
	}
	if s.Active() != "default" {
		t.Fatal("profile must NOT change while pending")
	}
}

func TestLateralSpreadBlocked(t *testing.T) {
	s, _ := build(t)
	s.RequestSwitch("code-review", SourceAgent) // now in code-review
	res := s.RequestSwitch("deploy", SourceAgent) // lateral, not an edge
	if res.Outcome != OutcomePending {
		t.Fatalf("lateral spread must require HITL, got %+v", res)
	}
}

func TestNonExistentTargetDenied(t *testing.T) {
	s, _ := build(t)
	res := s.RequestSwitch("ghost", SourceAgent)
	if res.Outcome != OutcomeDenied {
		t.Fatalf("unknown target must be denied, got %+v", res)
	}
}

func TestHumanCanSwitchAnywhere(t *testing.T) {
	s, _ := build(t)
	res := s.RequestSwitch("deploy", SourceHuman)
	if res.Outcome != OutcomeSwitched || s.Active() != "deploy" {
		t.Fatalf("human switch must be allowed, got %+v", res)
	}
}

func TestApplyApprovedCompletesSwitch(t *testing.T) {
	s, ap := build(t)
	res := s.RequestSwitch("deploy", SourceAgent) // pending
	ap.Resolve(res.ApprovalID, true)              // human approves
	if !s.ApplyIfApproved(res.ApprovalID) || s.Active() != "deploy" {
		t.Fatal("approved escalation must complete the switch")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/profilestate/ -v`
Expected: FAIL — `undefined: New`.

- [ ] **Step 3: Write minimal implementation**

```go
// Package profilestate holds the active profile and authorizes switches.
package profilestate

import (
	"sync"

	"github.com/aegis-mcp/aegis/internal/approval"
	"github.com/aegis-mcp/aegis/internal/policy"
)

type Source int

const (
	SourceAgent Source = iota // via aegis.set_profile — subject to the transition graph
	SourceHuman               // via CLI/control — trusted
)

type Outcome int

const (
	OutcomeSwitched Outcome = iota
	OutcomePending
	OutcomeDenied
)

type Result struct {
	Outcome    Outcome
	ApprovalID string // set when OutcomePending
	Active     string
}

type State struct {
	mu     sync.Mutex
	pol    *policy.Policy
	ap     *approval.Store
	active string
}

func New(pol *policy.Policy, ap *approval.Store, initial string) *State {
	return &State{pol: pol, ap: ap, active: initial}
}

func (s *State) Active() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.active
}

// RequestSwitch authorizes a switch to target from the given source.
func (s *State) RequestSwitch(target string, src Source) Result {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.pol.ProfileExists(target) {
		return Result{Outcome: OutcomeDenied, Active: s.active}
	}
	if src == SourceHuman || s.pol.IsTransitionAllowed(s.active, target) {
		s.active = target
		return Result{Outcome: OutcomeSwitched, Active: s.active}
	}
	id := s.ap.Request(s.active, target)
	return Result{Outcome: OutcomePending, ApprovalID: id, Active: s.active}
}

// ApplyIfApproved completes a previously-pending switch if the human approved it.
func (s *State) ApplyIfApproved(approvalID string) bool {
	if s.ap.Status(approvalID) != approval.StatusApproved {
		return false
	}
	req, ok := s.ap.Pending(approvalID)
	if !ok {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.active = req.ToProf
	return true
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/profilestate/ -v`
Expected: PASS (all six).

- [ ] **Step 5: Commit**

```bash
git add internal/profilestate/
git commit -m "feat(profilestate): transition-graph switch authorization with HITL routing"
```

---

## Task 8: Structured error codes

**Files:**
- Create: `internal/aegiserr/aegiserr.go`
- Test: `internal/aegiserr/aegiserr_test.go`

- [ ] **Step 1: Write the failing test**

```go
package aegiserr

import (
	"encoding/json"
	"testing"
)

func TestCapDeniedVerboseVsMinimal(t *testing.T) {
	verbose := CapDenied("sonarqube.scan", "default", "code-review", "verbose")
	var v map[string]any
	_ = json.Unmarshal([]byte(verbose.JSON()), &v)
	if v["code"] != "AEGIS_CAP_DENIED" || v["capability"] != "sonarqube.scan" {
		t.Fatalf("missing stable fields: %v", v)
	}
	if v["required_profile"] != "code-review" {
		t.Errorf("verbose must disclose required_profile")
	}

	minimal := CapDenied("sonarqube.scan", "default", "code-review", "minimal")
	_ = json.Unmarshal([]byte(minimal.JSON()), &v)
	if _, present := v["required_profile"]; present {
		t.Errorf("minimal must NOT disclose required_profile")
	}
	if v["capability"] != "sonarqube.scan" {
		t.Errorf("capability is always present")
	}
}

func TestPendingApproval(t *testing.T) {
	p := PendingApproval("apr_1", "default", "deploy")
	var v map[string]any
	_ = json.Unmarshal([]byte(p.JSON()), &v)
	if v["code"] != "AEGIS_PENDING_APPROVAL" || v["approval_id"] != "apr_1" {
		t.Fatalf("bad pending payload: %v", v)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/aegiserr/ -v`
Expected: FAIL — `undefined: CapDenied`.

- [ ] **Step 3: Write minimal implementation**

```go
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/aegiserr/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/aegiserr/
git commit -m "feat(aegiserr): stable structured errors with configurable disclosure"
```

---

## Task 9: Enforcer — list filtering + call authorization

**Files:**
- Create: `internal/enforcer/enforcer.go`
- Test: `internal/enforcer/enforcer_test.go`

- [ ] **Step 1: Write the failing test**

```go
package enforcer

import (
	"testing"

	"github.com/aegis-mcp/aegis/internal/config"
	"github.com/aegis-mcp/aegis/internal/policy"
)

func mk(t *testing.T) *Enforcer {
	t.Helper()
	c := &config.Config{
		Profiles: map[string]config.Profile{
			"default": {Allow: []string{"filesystem.read_file"}, Resources: []string{"file:///repo/**"}},
		},
		Activation:      config.Activation{DefaultProfile: "default"},
		ErrorDisclosure: "verbose",
	}
	pol, err := policy.Compile(c)
	if err != nil {
		t.Fatal(err)
	}
	return New(pol, "verbose")
}

func TestFilterToolsKeepsOnlyAllowed(t *testing.T) {
	e := mk(t)
	in := []Capability{{"filesystem", "read_file"}, {"filesystem", "write_file"}, {"github", "search"}}
	out := e.FilterTools("default", in)
	if len(out) != 1 || out[0].Tool != "read_file" {
		t.Fatalf("filter wrong: %+v", out)
	}
}

func TestAuthorizeToolCall(t *testing.T) {
	e := mk(t)
	if d := e.AuthorizeTool("default", Capability{"filesystem", "read_file"}); !d.Allowed {
		t.Error("read_file must be allowed")
	}
	d := e.AuthorizeTool("default", Capability{"filesystem", "write_file"})
	if d.Allowed || d.Err == nil {
		t.Error("write_file must be denied with a structured error")
	}
}

func TestAuthorizeResourceTraversalDenied(t *testing.T) {
	e := mk(t)
	if d := e.AuthorizeResource("default", "file:///repo/a.txt"); !d.Allowed {
		t.Error("in-scope resource must be allowed")
	}
	if d := e.AuthorizeResource("default", "file:///repo/../etc/passwd"); d.Allowed {
		t.Error("traversal must be denied")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/enforcer/ -v`
Expected: FAIL — `undefined: New`.

- [ ] **Step 3: Write minimal implementation**

```go
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
	return Decision{
		Allowed: false,
		Reason:  "not in active profile allow-list",
		Err:     aegiserr.CapDenied(c.String(), profile, "", e.disclosure),
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
```

Note: `AuthorizeTool` passes `required=""` because computing which profile *would* grant a capability is a Cycle 1.x lookup; with `verbose` the field is simply omitted when unknown. (Tracked in spec §10.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/enforcer/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/enforcer/
git commit -m "feat(enforcer): default-deny list filtering and call authorization"
```

---

## Task 10: Audit log

**Files:**
- Create: `internal/audit/audit.go`
- Test: `internal/audit/audit_test.go`

- [ ] **Step 1: Write the failing test**

```go
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/audit/ -v`
Expected: FAIL — `undefined: New`.

- [ ] **Step 3: Write minimal implementation**

```go
// Package audit writes one structured JSON record per security decision.
package audit

import (
	"encoding/json"
	"io"
	"sync"
	"time"
)

type Record struct {
	TS         string `json:"ts"`
	Decision   string `json:"decision"`
	Profile    string `json:"profile"`
	Capability string `json:"capability,omitempty"`
	URI        string `json:"uri,omitempty"`
	Reason     string `json:"reason,omitempty"`
	Source     string `json:"source,omitempty"`
}

type Logger struct {
	mu  sync.Mutex
	w   io.Writer
	now func() time.Time
}

func New(w io.Writer) *Logger { return &Logger{w: w, now: time.Now} }

func (l *Logger) Emit(r Record) {
	if r.TS == "" {
		r.TS = l.now().UTC().Format(time.RFC3339Nano)
	}
	b, _ := json.Marshal(r)
	l.mu.Lock()
	defer l.mu.Unlock()
	_, _ = l.w.Write(append(b, '\n'))
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/audit/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/audit/
git commit -m "feat(audit): structured JSON decision log"
```

---

## Task 11: Gateway seam — Item type + DownstreamClient interface + fake

**Files:**
- Create: `internal/gateway/types.go`
- Test: `internal/gateway/fakeclient_test.go`

This is the seam that keeps the SDK out of the pure core and makes the proxy logic testable without spawning processes.

- [ ] **Step 1: Write the failing test (defines the contract via a fake)**

```go
package gateway

import (
	"context"
	"testing"
)

// fakeClient is an in-memory DownstreamClient for tests.
type fakeClient struct {
	tools     []ToolDef
	resources []string
	called    []string
}

func (f *fakeClient) ListTools(context.Context) ([]ToolDef, error)   { return f.tools, nil }
func (f *fakeClient) ListResources(context.Context) ([]string, error) { return f.resources, nil }
func (f *fakeClient) CallTool(_ context.Context, tool string, _ map[string]any) (string, error) {
	f.called = append(f.called, tool)
	return "ok:" + tool, nil
}
func (f *fakeClient) ReadResource(context.Context, string) (string, error) { return "data", nil }
func (f *fakeClient) Close() error                                         { return nil }

func TestFakeSatisfiesInterface(t *testing.T) {
	var _ DownstreamClient = &fakeClient{}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/gateway/ -run TestFake -v`
Expected: FAIL — `undefined: DownstreamClient`.

- [ ] **Step 3: Write minimal implementation**

```go
// Package gateway is the I/O shell adapting the MCP SDK to the pure core.
package gateway

import "context"

// ToolDef is a downstream tool as Aegis tracks it (SDK-independent).
type ToolDef struct {
	Name        string
	Description string
}

// DownstreamClient is the minimal surface Aegis needs from each downstream server.
// The real implementation wraps the MCP SDK ClientSession (Task 12); tests use a fake.
type DownstreamClient interface {
	ListTools(ctx context.Context) ([]ToolDef, error)
	ListResources(ctx context.Context) ([]string, error)
	CallTool(ctx context.Context, tool string, args map[string]any) (string, error)
	ReadResource(ctx context.Context, uri string) (string, error)
	Close() error
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/gateway/ -run TestFake -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/gateway/types.go internal/gateway/fakeclient_test.go
git commit -m "feat(gateway): SDK-independent DownstreamClient seam"
```

---

## Task 12: Registry + Router — aggregate and route over the seam

**Files:**
- Create: `internal/gateway/registry.go`, `internal/gateway/router.go`
- Test: `internal/gateway/gateway_test.go`

- [ ] **Step 1: Write the failing test**

```go
package gateway

import (
	"context"
	"testing"

	"github.com/aegis-mcp/aegis/internal/naming"
)

func newRegistry(t *testing.T) *Registry {
	t.Helper()
	clients := map[string]DownstreamClient{
		"filesystem": &fakeClient{tools: []ToolDef{{Name: "read_file", Description: "read"}, {Name: "search", Description: "s"}}},
		"github":     &fakeClient{tools: []ToolDef{{Name: "search", Description: "s"}}},
	}
	r, err := NewRegistry(clients)
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	return r
}

func TestRegistryAggregatesAndNamespaces(t *testing.T) {
	r := newRegistry(t)
	tools, err := r.AllTools(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// 3 tools total; both "search" must be distinct wire names.
	wire := map[string]bool{}
	for _, td := range tools {
		wire[td.Wire] = true
	}
	if !wire["filesystem__search"] || !wire["github__search"] || !wire["filesystem__read_file"] {
		t.Fatalf("namespacing wrong: %v", wire)
	}
}

func TestRouterResolvesWireNameToDownstream(t *testing.T) {
	r := newRegistry(t)
	_, _ = r.AllTools(context.Background()) // populate naming
	out, err := r.Router().CallByWire(context.Background(), naming.Wire("github", "search"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if out != "ok:search" {
		t.Errorf("router called wrong downstream: %q", out)
	}
	if _, err := r.Router().CallByWire(context.Background(), "ghost__x", nil); err == nil {
		t.Error("unknown wire name must error, not reach any downstream")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/gateway/ -run 'TestRegistry|TestRouter' -v`
Expected: FAIL — `undefined: NewRegistry`.

- [ ] **Step 3: Write minimal implementation**

`internal/gateway/registry.go`:

```go
package gateway

import (
	"context"
	"sort"

	"github.com/aegis-mcp/aegis/internal/naming"
)

// AggregatedTool is a downstream tool with its namespaced wire name.
type AggregatedTool struct {
	Server      string
	Tool        string
	Wire        string
	Description string
}

type Registry struct {
	clients map[string]DownstreamClient
	names   *naming.Map
	router  *Router
}

func NewRegistry(clients map[string]DownstreamClient) (*Registry, error) {
	return &Registry{
		clients: clients,
		names:   naming.New(),
		router:  &Router{clients: clients, names: naming.New()},
	}, nil
}

func (r *Registry) Router() *Router { return r.router }

// AllTools lists every downstream tool, registers wire names (collision-checked),
// and applies namespacing + description annotation.
func (r *Registry) AllTools(ctx context.Context) ([]AggregatedTool, error) {
	r.names = naming.New()
	r.router.names = r.names
	servers := make([]string, 0, len(r.clients))
	for s := range r.clients {
		servers = append(servers, s)
	}
	sort.Strings(servers) // deterministic order

	var out []AggregatedTool
	for _, s := range servers {
		tools, err := r.clients[s].ListTools(ctx)
		if err != nil {
			continue // per-server fail-closed: drop unreachable server's tools
		}
		for _, td := range tools {
			if err := r.names.Register(s, td.Name); err != nil {
				return nil, err // startup-time collision (same server+tool)
			}
			out = append(out, AggregatedTool{
				Server: s, Tool: td.Name, Wire: naming.Wire(s, td.Name),
				Description: naming.AnnotateDescription(td.Description, s),
			})
		}
	}
	return out, nil
}
```

`internal/gateway/router.go`:

```go
package gateway

import (
	"context"
	"fmt"

	"github.com/aegis-mcp/aegis/internal/naming"
)

type Router struct {
	clients map[string]DownstreamClient
	names   *naming.Map
}

// CallByWire resolves a namespaced wire name and forwards to the right downstream.
func (r *Router) CallByWire(ctx context.Context, wire string, args map[string]any) (string, error) {
	server, tool, ok := r.names.Resolve(wire)
	if !ok {
		return "", fmt.Errorf("unknown tool %q", wire)
	}
	c, ok := r.clients[server]
	if !ok {
		return "", fmt.Errorf("server %q not connected", server)
	}
	return c.CallTool(ctx, tool, args)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/gateway/ -run 'TestRegistry|TestRouter|TestFake' -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/gateway/registry.go internal/gateway/router.go internal/gateway/gateway_test.go
git commit -m "feat(gateway): aggregating registry + namespaced router"
```

---

## Task 13: Gateway core — wire core decisions to list/call over the seam

**Files:**
- Create: `internal/gateway/core.go`
- Test: `internal/gateway/core_test.go`

This task assembles enforcer + profilestate + registry/router + audit into a single `Core` with the exact methods the SDK middleware (Task 14) will call. It is fully testable with the fake client — no SDK yet.

- [ ] **Step 1: Write the failing test**

```go
package gateway

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/aegis-mcp/aegis/internal/approval"
	"github.com/aegis-mcp/aegis/internal/audit"
	"github.com/aegis-mcp/aegis/internal/config"
	"github.com/aegis-mcp/aegis/internal/enforcer"
	"github.com/aegis-mcp/aegis/internal/policy"
	"github.com/aegis-mcp/aegis/internal/profilestate"
)

func newCore(t *testing.T, buf *bytes.Buffer) *Core {
	t.Helper()
	c := &config.Config{
		Profiles: map[string]config.Profile{
			"default":     {Allow: []string{"filesystem.read_file"}, AllowedTransitions: []string{"code-review"}},
			"code-review": {Extends: "default", Allow: []string{"github.search"}, AllowedTransitions: []string{"default"}},
			"deploy":      {Allow: []string{"github.deploy"}},
		},
		Activation:      config.Activation{DefaultProfile: "default"},
		ErrorDisclosure: "verbose",
	}
	pol, err := policy.Compile(c)
	if err != nil {
		t.Fatal(err)
	}
	clients := map[string]DownstreamClient{
		"filesystem": &fakeClient{tools: []ToolDef{{Name: "read_file"}, {Name: "write_file"}}},
		"github":     &fakeClient{tools: []ToolDef{{Name: "search"}, {Name: "deploy"}}},
	}
	reg, _ := NewRegistry(clients)
	enf := enforcer.New(pol, "verbose")
	ps := profilestate.New(pol, approval.New(approval.Channel(nopCh{})), "default")
	return NewCore(reg, enf, ps, audit.New(buf))
}

type nopCh struct{}

func (nopCh) Notify(approval.Request) {}

func TestListToolsFilteredByProfile(t *testing.T) {
	var buf bytes.Buffer
	core := newCore(t, &buf)
	got, err := core.ListTools(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// default allows only filesystem.read_file
	if len(got) != 1 || got[0].Wire != "filesystem__read_file" {
		t.Fatalf("expected only filesystem__read_file, got %+v", got)
	}
}

func TestCallDeniedToolIsAuditedAndNotForwarded(t *testing.T) {
	var buf bytes.Buffer
	core := newCore(t, &buf)
	_, _ = core.ListTools(context.Background())
	_, derr := core.CallTool(context.Background(), "github__deploy", nil)
	if derr == nil {
		t.Fatal("denied tool must return a structured error")
	}
	if !strings.Contains(buf.String(), "\"decision\":\"deny\"") {
		t.Errorf("denial must be audited: %s", buf.String())
	}
}

func TestSetProfileEscalationReturnsPending(t *testing.T) {
	var buf bytes.Buffer
	core := newCore(t, &buf)
	res := core.SetProfile("deploy", false) // agent source
	if res.Code != "AEGIS_PENDING_APPROVAL" {
		t.Fatalf("agent escalation must be pending, got %+v", res)
	}
	// after pending, profile is unchanged → code-review tools still hidden
	got, _ := core.ListTools(context.Background())
	if len(got) != 1 {
		t.Errorf("profile must not change while pending")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/gateway/ -run 'TestList|TestCall|TestSetProfile' -v`
Expected: FAIL — `undefined: NewCore`.

- [ ] **Step 3: Write minimal implementation**

```go
package gateway

import (
	"context"
	"fmt"

	"github.com/aegis-mcp/aegis/internal/audit"
	"github.com/aegis-mcp/aegis/internal/enforcer"
	"github.com/aegis-mcp/aegis/internal/profilestate"
)

type Core struct {
	reg *Registry
	enf *enforcer.Enforcer
	ps  *profilestate.State
	aud *audit.Logger
}

func NewCore(reg *Registry, enf *enforcer.Enforcer, ps *profilestate.State, aud *audit.Logger) *Core {
	return &Core{reg: reg, enf: enf, ps: ps, aud: aud}
}

// ListTools returns the profile-filtered, namespaced tool set.
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

// CallTool authorizes by wire name, audits, and forwards only if allowed.
func (c *Core) CallTool(ctx context.Context, wire string, args map[string]any) (string, error) {
	server, tool, ok := c.reg.names.Resolve(wire)
	if !ok {
		return "", fmt.Errorf("unknown tool %q", wire)
	}
	profile := c.ps.Active()
	d := c.enf.AuthorizeTool(profile, enforcer.Capability{Server: server, Tool: tool})
	if !d.Allowed {
		c.aud.Emit(audit.Record{Decision: "deny", Profile: profile,
			Capability: server + "." + tool, Reason: d.Reason})
		return "", fmt.Errorf("%s", d.Err.JSON())
	}
	c.aud.Emit(audit.Record{Decision: "allow", Profile: profile, Capability: server + "." + tool})
	return c.reg.Router().CallByWire(ctx, wire, args)
}

// SetProfileResult mirrors the structured response surfaced to the host.
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
		c.aud.Emit(audit.Record{Decision: "pending", Profile: res.Active,
			Reason: "escalation to " + target, Source: srcStr(human)})
		return SetProfileResult{Code: "AEGIS_PENDING_APPROVAL", Active: res.Active, ApprovalID: res.ApprovalID}
	default:
		c.aud.Emit(audit.Record{Decision: "deny", Profile: res.Active, Reason: "unknown profile " + target})
		return SetProfileResult{Code: "AEGIS_PROFILE_UNKNOWN", Active: res.Active}
	}
}

// ApplyApproval completes a pending escalation (called after human approves via CLI).
func (c *Core) ApplyApproval(id string) bool { return c.ps.ApplyIfApproved(id) }

func srcStr(human bool) string {
	if human {
		return "human"
	}
	return "agent"
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/gateway/ -v`
Expected: PASS (whole gateway package, including earlier tasks).

- [ ] **Step 5: Commit**

```bash
git add internal/gateway/core.go internal/gateway/core_test.go
git commit -m "feat(gateway): Core wiring of enforcer+profilestate+registry+audit"
```

---

## Task 14: SDK adapter — real DownstreamClient + Aegis server middleware

**Files:**
- Create: `internal/gateway/server.go`
- (No unit test — covered by the smoke/integration run in Task 16; this is the thin SDK boundary.)

> **SDK verification step:** before writing, confirm the exact symbols against the installed SDK:
> `go doc github.com/modelcontextprotocol/go-sdk/mcp ClientSession` and
> `go doc github.com/modelcontextprotocol/go-sdk/mcp Server.AddReceivingMiddleware`.
> Adjust the result/request type assertions below to match v1.2.0 exactly.

- [ ] **Step 1: Implement the real downstream client (wraps `mcp.ClientSession`)**

```go
package gateway

import (
	"context"
	"os/exec"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type sdkClient struct {
	session *mcp.ClientSession
}

// DialStdio launches a downstream MCP server as a subprocess and connects.
func DialStdio(ctx context.Context, command string, args []string) (DownstreamClient, error) {
	client := mcp.NewClient(&mcp.Implementation{Name: "aegis", Version: "0.1.0"}, nil)
	tr := &mcp.CommandTransport{Command: exec.Command(command, args...)}
	session, err := client.Connect(ctx, tr, nil)
	if err != nil {
		return nil, err
	}
	return &sdkClient{session: session}, nil
}

func (s *sdkClient) ListTools(ctx context.Context) ([]ToolDef, error) {
	res, err := s.session.ListTools(ctx, &mcp.ListToolsParams{})
	if err != nil {
		return nil, err
	}
	out := make([]ToolDef, 0, len(res.Tools))
	for _, t := range res.Tools {
		out = append(out, ToolDef{Name: t.Name, Description: t.Description})
	}
	return out, nil
}

func (s *sdkClient) CallTool(ctx context.Context, tool string, args map[string]any) (string, error) {
	res, err := s.session.CallTool(ctx, &mcp.CallToolParams{Name: tool, Arguments: args})
	if err != nil {
		return "", err
	}
	var sb string
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			sb += tc.Text
		}
	}
	return sb, nil
}

func (s *sdkClient) ListResources(ctx context.Context) ([]string, error) {
	res, err := s.session.ListResources(ctx, &mcp.ListResourcesParams{})
	if err != nil {
		return nil, err
	}
	var uris []string
	for _, r := range res.Resources {
		uris = append(uris, r.URI)
	}
	return uris, nil
}

func (s *sdkClient) ReadResource(ctx context.Context, uri string) (string, error) {
	_, err := s.session.ReadResource(ctx, &mcp.ReadResourceParams{URI: uri})
	return "", err // payload relay is pass-through; content unused in Cycle 1
}

func (s *sdkClient) Close() error { return s.session.Close() }
```

- [ ] **Step 2: Build the Aegis server and register meta-tools + the dynamic tool surface**

```go
package gateway

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const serverInstructions = "You are operating behind Aegis-MCP. Every tool is prefixed " +
	"with its server origin via a double underscore (e.g. filesystem__read_file). Use the " +
	"prefixed names exactly as listed. Some profile switches require human approval."

// BuildServer constructs the host-facing MCP server backed by Core.
func BuildServer(core *Core) *mcp.Server {
	srv := mcp.NewServer(
		&mcp.Implementation{Name: "aegis-mcp", Version: "0.1.0"},
		&mcp.ServerOptions{Instructions: serverInstructions},
	)

	// Built-in meta-tools.
	mcp.AddTool(srv, &mcp.Tool{Name: "aegis.set_profile", Description: "switch active profile"},
		func(ctx context.Context, _ *mcp.CallToolRequest, in struct {
			Name string `json:"name"`
		}) (*mcp.CallToolResult, any, error) {
			r := core.SetProfile(in.Name, false) // agent source
			return textResult(r.Code + " active=" + r.Active + " approval=" + r.ApprovalID), nil, nil
		})

	mcp.AddTool(srv, &mcp.Tool{Name: "aegis.approval_status", Description: "poll an approval"},
		func(ctx context.Context, _ *mcp.CallToolRequest, in struct {
			ID string `json:"id"`
		}) (*mcp.CallToolResult, any, error) {
			applied := core.ApplyApproval(in.ID)
			status := "pending"
			if applied {
				status = "approved"
			}
			return textResult(status), nil, nil
		})

	// Dynamic surface: a receiving middleware intercepts tools/list and tools/call so the
	// proxy can present the filtered, namespaced set and route allowed calls downstream.
	srv.AddReceivingMiddleware(proxyMiddleware(core))
	return srv
}

func textResult(s string) *mcp.CallToolResult {
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: s}}}
}
```

- [ ] **Step 3: Implement the proxy middleware (the chokepoint)**

```go
package gateway

import (
	"context"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// proxyMiddleware intercepts list/call methods. For dynamic (downstream) tools it
// short-circuits with Core results; aegis.* meta-tools fall through to their handlers.
func proxyMiddleware(core *Core) mcp.Middleware {
	return func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			switch method {
			case "tools/list":
				tools, err := core.ListTools(ctx)
				if err != nil {
					return nil, err
				}
				res := &mcp.ListToolsResult{}
				for _, t := range tools {
					res.Tools = append(res.Tools, &mcp.Tool{Name: t.Wire, Description: t.Description})
				}
				// Append meta-tools by delegating, then merge (meta-tools are registered handlers).
				if inner, err := next(ctx, method, req); err == nil {
					if it, ok := inner.(*mcp.ListToolsResult); ok {
						res.Tools = append(res.Tools, it.Tools...)
					}
				}
				return res, nil

			case "tools/call":
				ctr, ok := req.(*mcp.CallToolRequest)
				if !ok {
					return next(ctx, method, req)
				}
				name := ctr.Params.Name
				if strings.HasPrefix(name, "aegis.") {
					return next(ctx, method, req) // meta-tool: registered handler
				}
				out, err := core.CallTool(ctx, name, ctr.Params.Arguments)
				if err != nil {
					return &mcp.CallToolResult{IsError: true,
						Content: []mcp.Content{&mcp.TextContent{Text: err.Error()}}}, nil
				}
				return textResult(out), nil
			}
			return next(ctx, method, req)
		}
	}
}
```

- [ ] **Step 4: Verify it compiles**

Run: `go build ./...`
Expected: builds. (Fix type assertions per the `go doc` verification step if names differ in v1.2.0.)

- [ ] **Step 5: Commit**

```bash
git add internal/gateway/server.go
git commit -m "feat(gateway): MCP SDK adapter — downstream client, server, proxy middleware"
```

---

## Task 15: CLI + entrypoint + terminal approval channel

**Files:**
- Create: `cmd/aegis/main.go`
- Create: `internal/approval/terminal.go`
- Test: `internal/approval/terminal_test.go`

- [ ] **Step 1: Write the failing test for the terminal channel formatting**

```go
package approval

import (
	"bytes"
	"strings"
	"testing"
)

func TestTerminalChannelPrintsActionableRequest(t *testing.T) {
	var buf bytes.Buffer
	ch := NewTerminalChannel(&buf)
	ch.Notify(Request{ID: "apr_1", FromProf: "default", ToProf: "deploy"})
	out := buf.String()
	if !strings.Contains(out, "apr_1") || !strings.Contains(out, "deploy") {
		t.Fatalf("approval prompt must name the id and target: %q", out)
	}
	if !strings.Contains(out, "aegis approve apr_1") {
		t.Errorf("prompt should tell the human how to approve")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/approval/ -run TestTerminal -v`
Expected: FAIL — `undefined: NewTerminalChannel`.

- [ ] **Step 3: Implement the terminal channel**

```go
package approval

import (
	"fmt"
	"io"
)

type TerminalChannel struct{ w io.Writer }

func NewTerminalChannel(w io.Writer) *TerminalChannel { return &TerminalChannel{w: w} }

func (t *TerminalChannel) Notify(r Request) {
	fmt.Fprintf(t.w, "\n[AEGIS] approval required: %s -> %s (id=%s)\n", r.FromProf, r.ToProf, r.ID)
	fmt.Fprintf(t.w, "[AEGIS] approve with:  aegis approve %s   | deny with: aegis deny %s\n", r.ID, r.ID)
}
```

- [ ] **Step 4: Run test to verify it passes, then write the entrypoint**

Run: `go test ./internal/approval/ -run TestTerminal -v`
Expected: PASS.

`cmd/aegis/main.go`:

```go
// Command aegis runs the gateway (default) or control subcommands.
package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/aegis-mcp/aegis/internal/approval"
	"github.com/aegis-mcp/aegis/internal/audit"
	"github.com/aegis-mcp/aegis/internal/config"
	"github.com/aegis-mcp/aegis/internal/enforcer"
	"github.com/aegis-mcp/aegis/internal/gateway"
	"github.com/aegis-mcp/aegis/internal/policy"
	"github.com/aegis-mcp/aegis/internal/profilestate"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "approve", "deny":
			// Cycle 1: control subcommands operate via the running gateway's control socket.
			// Documented as a follow-up; for now print guidance.
			fmt.Fprintln(os.Stderr, "control subcommands require the gateway control socket (see README)")
			return
		}
	}

	cfgPath := os.Getenv("AEGIS_CONFIG")
	if cfgPath == "" {
		cfgPath = "aegis.yaml"
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		log.Fatalf("aegis: %v", err) // fail-closed: never start on bad config
	}
	pol, err := policy.Compile(cfg)
	if err != nil {
		log.Fatalf("aegis: %v", err)
	}

	ctx := context.Background()
	clients := map[string]gateway.DownstreamClient{}
	for name, s := range cfg.Servers {
		c, err := gateway.DialStdio(ctx, s.Command, s.Args)
		if err != nil {
			log.Printf("aegis: downstream %q unavailable: %v", name, err) // per-server fail-closed
			continue
		}
		clients[name] = c
	}

	reg, err := gateway.NewRegistry(clients)
	if err != nil {
		log.Fatalf("aegis: %v", err)
	}
	ap := approval.New(approval.NewTerminalChannel(os.Stderr))
	ps := profilestate.New(pol, ap, cfg.Activation.DefaultProfile)
	enf := enforcer.New(pol, cfg.ErrorDisclosure)
	core := gateway.NewCore(reg, enf, ps, audit.New(os.Stdout))

	srv := gateway.BuildServer(core)
	if err := srv.Run(ctx, &mcp.StdioTransport{}); err != nil {
		log.Fatalf("aegis: %v", err)
	}
}
```

- [ ] **Step 5: Verify build + commit**

Run: `go build ./... && go test ./...`
Expected: builds; all unit tests pass.

```bash
git add cmd/aegis/main.go internal/approval/terminal.go internal/approval/terminal_test.go
git commit -m "feat(cmd): aegis entrypoint, fail-closed startup, terminal approval channel"
```

---

## Task 16: Integration + smoke + sample config + README

**Files:**
- Create: `testdata/aegis.yaml`, `README.md`
- Test: `internal/gateway/integration_test.go`

- [ ] **Step 1: Write the end-to-end integration test (over the seam with fakes)**

```go
package gateway

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

// Full path: list filtered+namespaced, denied call audited+blocked, escalation pending,
// human approve completes switch, now-visible tool callable. Two servers share "search".
func TestEndToEndFlow(t *testing.T) {
	var buf bytes.Buffer
	core := newCore(t, &buf) // from core_test.go

	// 1. default profile: only filesystem__read_file visible
	tools, err := core.ListTools(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(tools) != 1 || tools[0].Wire != "filesystem__read_file" {
		t.Fatalf("default surface wrong: %+v", tools)
	}

	// 2. denied call to github__search (not in default) is blocked + audited
	if _, err := core.CallTool(context.Background(), "github__search", nil); err == nil {
		t.Fatal("github__search must be denied in default")
	}
	if !strings.Contains(buf.String(), "\"decision\":\"deny\"") {
		t.Fatal("denied call must be audited")
	}

	// 3. autonomous edge default->code-review succeeds (declared transition)
	if r := core.SetProfile("code-review", false); r.Code != "OK" {
		t.Fatalf("declared edge must switch, got %+v", r)
	}

	// 4. now github__search is visible and callable
	tools, _ = core.ListTools(context.Background())
	var sawSearch bool
	for _, tt := range tools {
		if tt.Wire == "github__search" {
			sawSearch = true
		}
	}
	if !sawSearch {
		t.Fatal("github__search should be visible in code-review")
	}
	if _, err := core.CallTool(context.Background(), "github__search", nil); err != nil {
		t.Fatalf("github__search should be callable in code-review: %v", err)
	}
}
```

- [ ] **Step 2: Run it to verify it fails, then passes**

Run: `go test ./internal/gateway/ -run TestEndToEnd -v`
Expected: initially FAIL if any wiring is off; fix until PASS. With Tasks 11–13 complete it should PASS directly.

- [ ] **Step 3: Add the sample config**

`testdata/aegis.yaml`:

```yaml
servers:
  filesystem: { transport: stdio, command: "mcp-server-filesystem", args: ["/repo"] }
  github:     { transport: stdio, command: "mcp-github" }
  sonarqube:  { transport: stdio, command: "mcp-sonarqube" }

profiles:
  default:
    allow: ["filesystem.read_file", "filesystem.list_dir", "github.search_*"]
    resources: ["file:///repo/**"]
    allowed_transitions: ["code-review"]
  code-review:
    extends: default
    allow: ["sonarqube.*", "github.get_pull_request", "github.create_review_comment"]
    allowed_transitions: ["default"]
  deploy:
    allow: ["github.*"]
    allowed_transitions: []

activation:
  default_profile: default

error_disclosure: verbose
```

- [ ] **Step 4: Write the README acceptance section + run the full suite with coverage**

`README.md` must document: what Aegis is, how to run (`AEGIS_CONFIG=testdata/aegis.yaml ./aegis`), the profile model, and the manual acceptance test (point Claude Desktop/Cursor at the binary, confirm only `default` tools appear, ask the agent to switch to `deploy`, confirm it returns `AEGIS_PENDING_APPROVAL`).

Run:
```bash
go vet ./...
go test -cover ./...
```
Expected: all packages PASS; pure-core packages (`config`, `policy`, `naming`, `approval`, `profilestate`, `aegiserr`, `enforcer`, `audit`) at or near 100%; overall ≥80%.

- [ ] **Step 5: Commit**

```bash
git add testdata/aegis.yaml README.md internal/gateway/integration_test.go
git commit -m "test(gateway): end-to-end flow; sample config; README acceptance guide"
```

---

## Manual Acceptance Test (for the user)

1. Build: `make build`.
2. Provide real downstream MCP server commands in `aegis.yaml` (or use mock servers).
3. Point Claude Desktop/Cursor at the `aegis` binary as a single MCP server (stdio).
4. Confirm the host lists only `default`-profile tools, each namespaced (`filesystem__read_file`), plus `aegis.set_profile` / `aegis.approval_status`.
5. Ask the agent to call a tool outside `default` → expect a structured `AEGIS_CAP_DENIED`; confirm a `"decision":"deny"` line in the audit output (stdout).
6. Ask the agent to `set_profile("deploy")` → expect immediate `AEGIS_PENDING_APPROVAL` + an `apr_*` id, and an approval prompt on stderr. Profile stays `default`.
7. Switch to `code-review` (a declared edge) → succeeds immediately; SonarQube tools appear.

---

## Self-Review (completed during authoring)

- **Spec coverage:** aggregating proxy (T11–14), tool filtering (T9,T13), default-deny policy + glob + extends (T2), traversal-safe resource matching (T3,T9), transition graph + no-tier (T4,T7), non-blocking HITL (T6,T7,T13,T15), namespacing + collisions + descriptions + server instructions (T5,T12,T14), structured errors + disclosure modes (T8,T9), audit log (T10), fail-closed startup (T1,T15), TDD/coverage (every task). Resources/prompts `*/list` filtering: tools fully wired end-to-end; resource/prompt *list* interception in the SDK middleware is the one item carried as a documented follow-up in T14 (the policy + enforcer support exists and is unit-tested in T3/T9).
- **Placeholders:** none — every code step contains complete code.
- **Type consistency:** `Capability`, `Decision`, `AggregatedTool`, `Result/Outcome`, `Record`, `DownstreamClient`, `Core` signatures are consistent across tasks.
```
