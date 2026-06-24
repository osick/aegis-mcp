// Command aegis is the Aegis-MCP gateway entrypoint. It loads a policy config,
// dials each configured downstream MCP server, and serves a single enforcing MCP
// server over stdio.
package main

import (
	"context"
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
	ctx := context.Background()

	configPath := os.Getenv("AEGIS_CONFIG")
	if configPath == "" {
		configPath = "aegis.yaml"
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		log.Fatalf("aegis: load config: %v", err) // fail-closed
	}

	pol, err := policy.Compile(cfg)
	if err != nil {
		log.Fatalf("aegis: compile policy: %v", err)
	}

	// Dial each downstream server; per-server fail-closed (log and continue).
	clients := map[string]gateway.DownstreamClient{}
	for name, s := range cfg.Servers {
		client, err := gateway.DialStdio(ctx, s.Command, s.Args)
		if err != nil {
			log.Printf("aegis: server %q: dial failed, skipping: %v", name, err)
			continue
		}
		clients[name] = client
	}

	reg, err := gateway.NewRegistry(clients)
	if err != nil {
		log.Fatalf("aegis: build registry: %v", err)
	}

	ap := approval.New(approval.NewTerminalChannel(os.Stderr))
	ps := profilestate.New(pol, ap, cfg.Activation.DefaultProfile)
	enf := enforcer.New(pol, cfg.ErrorDisclosure)
	aud := audit.New(os.Stdout)

	core := gateway.NewCore(reg, enf, ps, aud)
	srv := gateway.BuildServer(core)

	if err := srv.Run(ctx, &mcp.StdioTransport{}); err != nil {
		log.Fatalf("aegis: server exited: %v", err)
	}
}
