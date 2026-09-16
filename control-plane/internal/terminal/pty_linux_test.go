//go:build linux

package terminal

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestStartPtySessionLeader runs startPty from a helper that is a
// session leader with no controlling terminal — the exact state of
// the control plane as container PID 1. Regression test: opening
// the slave without O_NOCTTY acquires it as the helper's ctty, and
// the child's TIOCSCTTY then fails with EPERM (Docker drops
// CAP_SYS_ADMIN), which surfaced as "fork/exec: operation not
// permitted" and broke every terminal session.
func TestStartPtySessionLeader(t *testing.T) {
	if os.Getenv("GO_TEST_HELPER_PTY") == "1" {
		helperStartPty()
		os.Exit(0) // unreachable: helperStartPty always exits
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestStartPtySessionLeader")
	cmd.Env = append(os.Environ(), "GO_TEST_HELPER_PTY=1")
	// New session + piped stdio: a session leader with no ctty,
	// like container PID 1.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("helper failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "pty-ok") {
		t.Fatalf("helper output missing pty-ok:\n%s", out)
	}
}

// helperStartPty runs inside the re-execed helper. It must exit the
// process (0 = pass); returning is a harness bug.
func helperStartPty() {
	fail := func(format string, args ...any) {
		fmt.Fprintf(os.Stderr, format+"\n", args...)
		os.Exit(1)
	}
	if n := selfTTYNR(); n != 0 {
		fail("helper started with ctty (tty_nr=%d), want none", n)
	}
	be, err := startPty(Config{Cmd: []string{"echo", "pty-ok"}, UsePTY: true}, 80, 24)
	if err != nil {
		fail("startPty: %v", err)
	}
	defer be.Close()
	defer be.Kill()
	done := make(chan string, 1)
	go func() {
		buf := make([]byte, 64)
		n, _ := be.Read(buf)
		done <- string(buf[:n])
	}()
	select {
	case out := <-done:
		if !strings.Contains(out, "pty-ok") {
			fail("child output %q, want pty-ok", out)
		}
		fmt.Printf("child output: %q\n", out)
	case <-time.After(10 * time.Second):
		fail("timed out reading child output")
	}
	if code := be.Wait(); code != 0 {
		fail("child exit code = %d, want 0", code)
	}
	// The session must not have acquired a ctty as a side effect —
	// this assertion catches the bug even when run as root (where
	// the TIOCSCTTY steal would otherwise succeed).
	if n := selfTTYNR(); n != 0 {
		fail("startPty stole a ctty (tty_nr=%d)", n)
	}
	os.Exit(0)
}

// selfTTYNR returns this process's controlling terminal device
// number from /proc/self/stat (0 = none).
func selfTTYNR() int64 {
	b, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		return -1
	}
	s := string(b)
	end := strings.LastIndexByte(s, ')')
	if end < 0 {
		return -1
	}
	// Fields after comm(2): state(3) ppid(4) pgrp(5)
	// session(6) tty_nr(7).
	parts := strings.Fields(s[end+1:])
	if len(parts) < 5 {
		return -1
	}
	var n int64
	if _, err := fmt.Sscanf(parts[4], "%d", &n); err != nil {
		return -1
	}
	return n
}
