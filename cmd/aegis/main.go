// Command aegis is the Aegis-MCP gateway entrypoint.
//
// With no arguments it loads a policy config, dials each configured downstream
// MCP server, and serves a single enforcing MCP server over stdio, while
// listening on a per-user unix socket for out-of-band approval decisions.
//
// `aegis approve <id>` / `aegis deny <id>` deliver a human decision for a
// pending profile-switch escalation to the running gateway over that socket.
package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/osick/aegis-mcp/internal/approval"
	"github.com/osick/aegis-mcp/internal/approvalipc"
	"github.com/osick/aegis-mcp/internal/audit"
	"github.com/osick/aegis-mcp/internal/config"
	"github.com/osick/aegis-mcp/internal/enforcer"
	"github.com/osick/aegis-mcp/internal/gateway"
	"github.com/osick/aegis-mcp/internal/policy"
	"github.com/osick/aegis-mcp/internal/profilestate"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
	switch {
	case len(os.Args) == 1:
		runGateway()
	case len(os.Args) == 3 && (os.Args[1] == "approve" || os.Args[1] == "deny"):
		runDecision(os.Args[1], os.Args[2])
	default:
		fmt.Fprintf(os.Stderr, "usage:\n  aegis                 run the gateway (stdio MCP server)\n  aegis approve <id>    approve a pending profile switch\n  aegis deny <id>       deny a pending profile switch\n")
		os.Exit(2)
	}
}

// runDecision sends a human approval decision to the running gateway.
func runDecision(verb, id string) {
	reply, err := approvalipc.Send(approvalipc.SocketPath(), verb, id)
	if err != nil {
		log.Fatalf("aegis %s: %v", verb, err)
	}
	fmt.Println(reply)
	if reply != "ok" {
		os.Exit(1)
	}
}

func runGateway() {
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

	// Audit must never share stdout with the MCP protocol stream. Default to
	// stderr; AEGIS_AUDIT_LOG selects a file (append, owner-only).
	auditW, auditC, err := audit.OpenSink(os.Getenv("AEGIS_AUDIT_LOG"), os.Stderr)
	if err != nil {
		log.Fatalf("aegis: open audit log: %v", err) // fail-closed
	}
	if auditC != nil {
		defer auditC.Close()
	}
	aud := audit.New(auditW)

	// Out-of-band approval channel for `aegis approve <id>` / `aegis deny <id>`.
	ipc, err := approvalipc.Serve(approvalipc.SocketPath(), ap)
	if err != nil {
		log.Fatalf("aegis: approval socket: %v", err) // fail-closed: HITL must work
	}
	defer ipc.Close()

	core := gateway.NewCore(reg, enf, ps, aud)
	srv := gateway.BuildServer(core)

	if err := srv.Run(ctx, &mcp.StdioTransport{}); err != nil {
		log.Fatalf("aegis: server exited: %v", err)
	}
}
