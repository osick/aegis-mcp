package audit

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestOpenSinkEmptyPathReturnsFallback(t *testing.T) {
	var fallback bytes.Buffer
	w, closer, err := OpenSink("", &fallback)
	if err != nil {
		t.Fatalf("OpenSink(\"\") error: %v", err)
	}
	if closer != nil {
		t.Fatalf("OpenSink(\"\") returned a closer; fallback needs none")
	}
	if _, err := w.Write([]byte("x")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if fallback.String() != "x" {
		t.Fatalf("fallback got %q, want %q", fallback.String(), "x")
	}
}

func TestOpenSinkCreatesFileAndAppends(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")

	w1, c1, err := OpenSink(path, nil)
	if err != nil {
		t.Fatalf("first OpenSink: %v", err)
	}
	if _, err := w1.Write([]byte("one\n")); err != nil {
		t.Fatalf("write one: %v", err)
	}
	if err := c1.Close(); err != nil {
		t.Fatalf("close one: %v", err)
	}

	// Re-open: must append, not truncate.
	w2, c2, err := OpenSink(path, nil)
	if err != nil {
		t.Fatalf("second OpenSink: %v", err)
	}
	if _, err := w2.Write([]byte("two\n")); err != nil {
		t.Fatalf("write two: %v", err)
	}
	if err := c2.Close(); err != nil {
		t.Fatalf("close two: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(got) != "one\ntwo\n" {
		t.Fatalf("file content %q, want %q", got, "one\ntwo\n")
	}
}

func TestOpenSinkFilePermissionsAreOwnerOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	_, c, err := OpenSink(path, nil)
	if err != nil {
		t.Fatalf("OpenSink: %v", err)
	}
	defer c.Close()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("audit log perms %o, want 600", perm)
	}
}

func TestOpenSinkUnwritablePathFails(t *testing.T) {
	_, _, err := OpenSink(filepath.Join(t.TempDir(), "no-such-dir", "audit.log"), nil)
	if err == nil {
		t.Fatal("OpenSink into a missing directory succeeded, want error (fail-closed)")
	}
}
