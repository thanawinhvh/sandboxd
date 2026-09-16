package api

import (
	"errors"
	"net/http"
	"runtime"
	"strconv"
	"time"

	"github.com/sandboxd/control-plane/internal/audit"
	"github.com/sandboxd/control-plane/internal/store"
	"github.com/sandboxd/control-plane/internal/terminal"
)

// --- GET /v1/sandboxes/{id}/terminal -------------------------------
//
// WebSocket terminal: one interactive bash per connection inside the
// sandbox (`docker exec -it` on a PTY). Query params: cols, rows
// (default 80x24). Wire protocol: see internal/terminal.
//
// Like the task submit path, a stopped sandbox is woken first. An
// open terminal counts as live activity (inflight), so the idle
// reaper never stops a sandbox mid-session.
func (s *Server) v1Terminal(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	sb, err := s.Store.Get(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeV1Err(w, http.StatusNotFound, "not_found", "no such sandbox")
		return
	}
	if err != nil {
		writeV1Err(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}

	// Wake-on-terminal-open, same as wake-on-task-submit: a stopped
	// sandbox is woken via the proven internal wake path.
	if sb.Status == "stopped" {
		code, body := s.delegate(r, s.handleWakeJSON, http.MethodPost, "/wake/"+id,
			map[string]string{"id": id}, nil)
		if code != http.StatusOK {
			relayV1Error(w, code, body) // 503 -> sandbox_capacity, etc.
			return
		}
		if sb, err = s.Store.Get(r.Context(), id); err != nil {
			writeV1Err(w, http.StatusInternalServerError, "internal", err.Error())
			return
		}
	}
	if sb.Status != "running" {
		writeV1Err(w, http.StatusConflict, "conflict",
			"sandbox is "+sb.Status+" — cannot open a terminal")
		return
	}

	cols := queryInt(r, "cols", 80)
	rows := queryInt(r, "rows", 24)

	s.auditAction(r, audit.Entry{
		Action: "sandbox.terminal",
		Target: id,
		Detail: map[string]any{"cols": cols, "rows": rows},
	})

	// Live activity for the session duration (same shape as
	// handleExec): the idle reaper skips inflight sandboxes, and
	// last-active is bumped at both ends.
	if s.Inflight != nil {
		s.Inflight.Enter(id)
		defer s.Inflight.Exit(id)
	}
	_ = s.Store.BumpLastActive(r.Context(), id, time.Now().UTC())
	defer func() {
		_ = s.Store.BumpLastActive(r.Context(), id, time.Now().UTC())
	}()

	ws, err := terminal.Accept(w, r)
	if err != nil {
		return // Accept already wrote the HTTP error
	}
	// The docker CLI needs its stdio on a TTY for -it; the PTY
	// backend provides exactly that (Linux). Elsewhere (dev,
	// tests) the same command runs on pipes.
	usePTY := runtime.GOOS == "linux"
	if err := terminal.Serve(ws, terminal.Config{
		Cmd:    []string{s.Docker.Bin, "exec", "-i", "-t", "-e", "TERM=xterm-256color", "s-" + id, "bash"},
		Cols:   cols,
		Rows:   rows,
		UsePTY: usePTY,
		Log:    s.loggerFor(r, id),
	}); err != nil {
		s.loggerFor(r, id).Warn("terminal: session failed", "err", err.Error())
	}
}

// queryInt reads a positive int query param, defaulting to dflt on
// absence or garbage. Clamped — a resize must not break a session.
func queryInt(r *http.Request, key string, dflt int) int {
	v := r.URL.Query().Get(key)
	if v == "" {
		return dflt
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 {
		return dflt
	}
	if n > 1000 {
		return 1000
	}
	return n
}
