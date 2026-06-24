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
