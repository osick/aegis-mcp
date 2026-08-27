package audit

import (
	"io"
	"os"
)

// OpenSink resolves where audit records are written. An empty path selects the
// fallback writer (no closer); otherwise the file at path is opened for append,
// created owner-only if missing. Errors must be treated as fatal by the caller:
// a gateway that cannot audit must not run (fail-closed).
func OpenSink(path string, fallback io.Writer) (io.Writer, io.Closer, error) {
	if path == "" {
		return fallback, nil, nil
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, nil, err
	}
	return f, f, nil
}
