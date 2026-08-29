package approvalipc

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/osick/aegis-mcp/internal/approval"
)

// nopChannel discards notifications; tests drive the store directly.
type nopChannel struct{}

func (nopChannel) Notify(approval.Request) {}

func newStoreWithPending(t *testing.T) (*approval.Store, string) {
	t.Helper()
	st := approval.New(nopChannel{})
	id := st.Request("default", "deploy")
	return st, id
}

func sockPath(t *testing.T) string {
	t.Helper()
	// Unix socket paths are length-limited (~104 bytes); keep it short.
	dir, err := os.MkdirTemp("", "aegis")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return filepath.Join(dir, "a.sock")
}

func TestApproveRoundTrip(t *testing.T) {
	st, id := newStoreWithPending(t)
	path := sockPath(t)

	srv, err := Serve(path, st)
	if err != nil {
		t.Fatalf("Serve: %v", err)
	}
	defer srv.Close()

	reply, err := Send(path, "approve", id)
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if reply != "ok" {
		t.Fatalf("reply %q, want %q", reply, "ok")
	}
	if got := st.Status(id); got != approval.StatusApproved {
		t.Fatalf("status %q, want approved", got)
	}
}

func TestDenyRoundTrip(t *testing.T) {
	st, id := newStoreWithPending(t)
	path := sockPath(t)

	srv, err := Serve(path, st)
	if err != nil {
		t.Fatalf("Serve: %v", err)
	}
	defer srv.Close()

	reply, err := Send(path, "deny", id)
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if reply != "ok" {
		t.Fatalf("reply %q, want %q", reply, "ok")
	}
	if got := st.Status(id); got != approval.StatusDenied {
		t.Fatalf("status %q, want denied", got)
	}
}

func TestUnknownIDIsRejected(t *testing.T) {
	st, _ := newStoreWithPending(t)
	path := sockPath(t)

	srv, err := Serve(path, st)
	if err != nil {
		t.Fatalf("Serve: %v", err)
	}
	defer srv.Close()

	reply, err := Send(path, "approve", "apr_999")
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if reply != "unknown or already resolved id" {
		t.Fatalf("reply %q, want unknown-id rejection", reply)
	}
}

func TestSecondResolveIsRejected(t *testing.T) {
	st, id := newStoreWithPending(t)
	path := sockPath(t)

	srv, err := Serve(path, st)
	if err != nil {
		t.Fatalf("Serve: %v", err)
	}
	defer srv.Close()

	if reply, _ := Send(path, "approve", id); reply != "ok" {
		t.Fatalf("first approve reply %q, want ok", reply)
	}
	reply, err := Send(path, "deny", id)
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if reply != "unknown or already resolved id" {
		t.Fatalf("second resolve reply %q, want rejection (single-use)", reply)
	}
}

func TestBadVerbIsRejected(t *testing.T) {
	st, id := newStoreWithPending(t)
	path := sockPath(t)

	srv, err := Serve(path, st)
	if err != nil {
		t.Fatalf("Serve: %v", err)
	}
	defer srv.Close()

	reply, err := Send(path, "elevate", id)
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if reply != "bad request" {
		t.Fatalf("reply %q, want %q", reply, "bad request")
	}
	if got := st.Status(id); got != approval.StatusPending {
		t.Fatalf("status %q, want still pending after bad verb", got)
	}
}

func TestServeReplacesStaleSocketFile(t *testing.T) {
	st, id := newStoreWithPending(t)
	path := sockPath(t)

	// A previous gateway crash leaves the socket file behind.
	srv1, err := Serve(path, st)
	if err != nil {
		t.Fatalf("first Serve: %v", err)
	}
	srv1.Close()

	srv2, err := Serve(path, st)
	if err != nil {
		t.Fatalf("Serve over stale socket: %v", err)
	}
	defer srv2.Close()

	if reply, err := Send(path, "approve", id); err != nil || reply != "ok" {
		t.Fatalf("Send after rebind: reply=%q err=%v", reply, err)
	}
}

func TestSendWithoutServerFails(t *testing.T) {
	if _, err := Send(sockPath(t), "approve", "apr_1"); err == nil {
		t.Fatal("Send with no server succeeded, want error")
	}
}

func TestSocketPathEnvOverrideWins(t *testing.T) {
	t.Setenv("AEGIS_APPROVAL_SOCKET", "/custom/path.sock")
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/1000")
	if got := SocketPath(); got != "/custom/path.sock" {
		t.Fatalf("SocketPath() = %q, want env override", got)
	}
}

func TestSocketPathUsesXDGRuntimeDir(t *testing.T) {
	t.Setenv("AEGIS_APPROVAL_SOCKET", "")
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/1000")
	want := filepath.Join("/run/user/1000", "aegis", "approval.sock")
	if got := SocketPath(); got != want {
		t.Fatalf("SocketPath() = %q, want %q", got, want)
	}
}

func TestSocketPathFallbackIsPerUser(t *testing.T) {
	t.Setenv("AEGIS_APPROVAL_SOCKET", "")
	t.Setenv("XDG_RUNTIME_DIR", "")
	got := SocketPath()
	want := filepath.Join(os.TempDir(), "aegis-"+userID(), "approval.sock")
	if got != want {
		t.Fatalf("SocketPath() = %q, want per-user fallback %q", got, want)
	}
}

func TestServeCreatesParentDirOwnerOnly(t *testing.T) {
	st, _ := newStoreWithPending(t)
	base, err := os.MkdirTemp("", "aegis")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	path := filepath.Join(base, "sub", "a.sock")

	srv, err := Serve(path, st)
	if err != nil {
		t.Fatalf("Serve with missing parent dir: %v", err)
	}
	defer srv.Close()

	info, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatalf("stat parent: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Fatalf("socket dir perms %o, want 700", perm)
	}
}
