// Package approvalipc carries human approval decisions from the `aegis approve`
// CLI into the running gateway's in-memory approval store, over a per-user unix
// domain socket. The wire protocol is one request line "approve <id>" or
// "deny <id>" answered by one reply line; anything else is rejected.
package approvalipc

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Resolver records a human decision for a pending approval id. Satisfied by
// *approval.Store.
type Resolver interface {
	Resolve(id string, approve bool) bool
}

// Server accepts approval decisions on a unix socket until closed.
type Server struct {
	ln net.Listener
}

// Serve binds a unix socket at path (replacing a stale socket file from a
// previous run, creating the parent directory owner-only) and resolves incoming
// decisions against r.
func Serve(path string, r Resolver) (*Server, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("approval socket dir: %w", err)
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("remove stale approval socket: %w", err)
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("bind approval socket: %w", err)
	}
	s := &Server{ln: ln}
	go s.acceptLoop(r)
	return s, nil
}

// Close stops accepting decisions and removes the socket.
func (s *Server) Close() error { return s.ln.Close() }

func (s *Server) acceptLoop(r Resolver) {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return // listener closed
		}
		go handle(conn, r)
	}
}

func handle(conn net.Conn, r Resolver) {
	defer conn.Close()
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return
	}
	verb, id, found := strings.Cut(strings.TrimSpace(line), " ")
	if !found || id == "" || (verb != "approve" && verb != "deny") {
		fmt.Fprintln(conn, "bad request")
		return
	}
	if !r.Resolve(id, verb == "approve") {
		fmt.Fprintln(conn, "unknown or already resolved id")
		return
	}
	fmt.Fprintln(conn, "ok")
}

// Send delivers one decision ("approve" or "deny") for id to the gateway
// listening at path and returns its one-line reply.
func Send(path, verb, id string) (string, error) {
	conn, err := net.Dial("unix", path)
	if err != nil {
		return "", fmt.Errorf("connect to gateway approval socket %s (is aegis running?): %w", path, err)
	}
	defer conn.Close()
	if _, err := fmt.Fprintf(conn, "%s %s\n", verb, id); err != nil {
		return "", err
	}
	reply, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(reply), nil
}

// SocketPath returns the approval socket location: $AEGIS_APPROVAL_SOCKET if
// set, else a per-user path under $XDG_RUNTIME_DIR, else a per-user directory
// under the system temp dir. The gateway and the `aegis approve` CLI must agree,
// so both call this.
func SocketPath() string {
	if p := os.Getenv("AEGIS_APPROVAL_SOCKET"); p != "" {
		return p
	}
	if dir := os.Getenv("XDG_RUNTIME_DIR"); dir != "" {
		return filepath.Join(dir, "aegis", "approval.sock")
	}
	return filepath.Join(os.TempDir(), "aegis-"+userID(), "approval.sock")
}

func userID() string { return strconv.Itoa(os.Getuid()) }
