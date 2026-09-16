package terminal

import (
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"syscall"
	"time"
)

// Logger is the narrow logging slice a session needs. Both
// *slog.Logger and the api package's request loggers satisfy it.
type Logger interface {
	Info(string, ...any)
	Warn(string, ...any)
	Error(string, ...any)
}

// Config describes one terminal session: the command to run
// (production: {"docker","exec","-it","s-<id>","bash"}) and the
// initial terminal size.
type Config struct {
	Cmd  []string // required, non-empty
	Env  []string // extra env entries ("K=V"), appended to os.Environ()
	Cols int      // initial width; <=0 means 80
	Rows int      // initial height; <=0 means 24

	// UsePTY attaches the command to a real PTY (Linux). When
	// false the command runs on pipes — no job control, no
	// window size, but portable (tests, non-Linux dev).
	UsePTY bool

	Log Logger // nil-safe
}

// backend is a running shell: something readable/writable that can
// be resized, reaped, and killed.
type backend interface {
	io.ReadWriteCloser
	Resize(cols, rows int)
	Wait() int // exit code; blocks until the process ends
	Kill()     // best-effort; safe to call twice
}

// Serve runs one terminal session to completion: it starts cfg.Cmd,
// shuttles bytes between ws and the shell, and returns when the
// shell exits or the client disconnects. It owns ws — ws is closed
// on return.
func Serve(ws *Conn, cfg Config) error {
	log := cfg.Log
	if log == nil {
		log = slog.Default()
	}
	defer ws.Close()
	if len(cfg.Cmd) == 0 {
		return sendError(ws, "no command")
	}
	cols, rows := cfg.Cols, cfg.Rows
	if cols <= 0 {
		cols = 80
	}
	if rows <= 0 {
		rows = 24
	}

	be, err := start(cfg, cols, rows)
	if err != nil {
		log.Warn("terminal: start failed", "err", err.Error())
		return sendError(ws, "failed to start shell")
	}
	defer be.Kill()
	defer be.Close()

	// Reap the process in the background; waitCh decides the
	// session outcome when the shell exits first.
	waitCh := make(chan int, 1)
	go func() { waitCh <- be.Wait() }()

	// doneCh fires when either pump breaks (client gone, shell
	// output ended, or a protocol error). outDone fires when the
	// shell→client pump ends, so the exit branch can drain
	// trailing output before reporting the exit.
	doneCh := make(chan struct{})
	outDone := make(chan struct{})
	var doneOnce = make(chan struct{}, 1)
	done := func() {
		select {
		case doneOnce <- struct{}{}:
			close(doneCh)
		default:
		}
	}

	// Shell → client.
	go func() {
		defer done()
		defer close(outDone)
		buf := make([]byte, 32*1024)
		for {
			n, err := be.Read(buf)
			if n > 0 {
				if werr := ws.WriteBinary(buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				return // EOF / EIO: shell side ended
			}
		}
	}()

	// Client → shell.
	go func() {
		defer done()
		for {
			op, msg, err := ws.ReadMessage()
			if err != nil {
				return // disconnect or protocol error
			}
			switch op {
			case opBinary:
				if len(msg) > 0 {
					if _, err := be.Write(msg); err != nil {
						return
					}
				}
			case opText:
				applyControl(be, msg) // resize; malformed input is ignored
			}
		}
	}()

	select {
	case code := <-waitCh:
		// Shell exited first: drain trailing output, report the
		// exit, then close gracefully. The drain is bounded — a
		// daemonized child holding the pty open must not wedge
		// the session.
		select {
		case <-outDone:
		case <-time.After(5 * time.Second):
		}
		sendExit(ws, code)
		log.Info("terminal: shell exited", "code", code)
		return nil
	case <-doneCh:
		// Client gone (or a pump broke): kill the shell, reap
		// it, and end the session. The exit frame is still
		// attempted — doneCh also fires on plain shell EOF
		// while the client is alive; a dead client just makes
		// the write fail silently.
		be.Kill()
		code := <-waitCh
		sendExit(ws, code)
		log.Info("terminal: session ended", "code", code)
		return nil
	}
}

// sendExit delivers the {"type":"exit"} frame plus the close
// handshake. Best-effort: the client may already be gone.
func sendExit(ws *Conn, code int) {
	out, _ := json.Marshal(map[string]any{"type": "exit", "code": code})
	_ = ws.WriteText(out)
	_ = ws.WriteClose()
}

// controlMsg is the client→server JSON control envelope. Only
// "resize" exists today; unknown types are ignored so the protocol
// can grow without breaking old servers.
type controlMsg struct {
	Type string `json:"type"`
	Cols int    `json:"cols"`
	Rows int    `json:"rows"`
}

func applyControl(be backend, raw []byte) {
	var msg controlMsg
	if err := json.Unmarshal(raw, &msg); err != nil {
		return
	}
	if msg.Type == "resize" {
		be.Resize(msg.Cols, msg.Rows)
	}
}

// sendError delivers a fatal session error to the client (the HTTP
// handshake already succeeded, so this is the only channel left),
// then closes the session.
func sendError(ws *Conn, msg string) error {
	out, _ := json.Marshal(map[string]any{"type": "error", "message": msg})
	_ = ws.WriteText(out)
	_ = ws.WriteClose()
	return &Error{Message: msg}
}

// Error is a fatal session error (also delivered to the client as a
// {"type":"error"} frame before the close).
type Error struct{ Message string }

func (e *Error) Error() string { return "terminal: " + e.Message }

// --- backends -------------------------------------------------------

func start(cfg Config, cols, rows int) (backend, error) {
	if cfg.UsePTY {
		return startPty(cfg, cols, rows)
	}
	return startPipe(cfg)
}

// ptyBackend runs the command on a real PTY (Linux production
// path): full job control, colors, vim/htop, window-sizeable.
type ptyBackend struct {
	cmd    *exec.Cmd
	master *os.File
}

func startPty(cfg Config, cols, rows int) (backend, error) {
	master, slavePath, err := openPty()
	if err != nil {
		return nil, err
	}
	// O_NOCTTY is load-bearing: the control plane runs as
	// container PID 1 (a session leader with no ctty), so opening
	// the slave without it acquires the slave as OUR ctty — and the
	// child's TIOCSCTTY then fails with EPERM (Docker drops
	// CAP_SYS_ADMIN), surfacing as "fork/exec: operation not
	// permitted".
	slave, err := os.OpenFile(slavePath, os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		_ = master.Close()
		return nil, err
	}
	setWinsize(master, cols, rows)

	cmd := exec.Command(cfg.Cmd[0], cfg.Cmd[1:]...)
	cmd.Env = os.Environ()
	cmd.Env = append(cmd.Env, cfg.Env...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if err := cmd.Start(); err != nil {
		_ = slave.Close()
		_ = master.Close()
		return nil, err
	}
	_ = slave.Close() // child has its own copy; we keep the master
	return &ptyBackend{cmd: cmd, master: master}, nil
}

func (b *ptyBackend) Read(p []byte) (int, error)  { return b.master.Read(p) }
func (b *ptyBackend) Write(p []byte) (int, error) { return b.master.Write(p) }
func (b *ptyBackend) Close() error                { return b.master.Close() }

func (b *ptyBackend) Resize(cols, rows int) { setWinsize(b.master, cols, rows) }

func (b *ptyBackend) Wait() int {
	if err := b.cmd.Wait(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return exitErr.ExitCode()
		}
		return 1
	}
	return 0
}

// Kill kills the whole session (Setsid made the child a process
// group leader, so -pid reaches the full tree).
func (b *ptyBackend) Kill() {
	if b.cmd.Process != nil {
		_ = syscall.Kill(-b.cmd.Process.Pid, syscall.SIGKILL)
	}
}

// pipeBackend runs the command on pipes (tests, non-Linux dev):
// interactive stdin/stdout, but no TTY and no resize.
type pipeBackend struct {
	cmd   *exec.Cmd
	stdin *os.File
	out   *os.File // read end of the combined stdout+stderr pipe
}

func startPipe(cfg Config) (backend, error) {
	inR, inW, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	outR, outW, err := os.Pipe()
	if err != nil {
		_ = inR.Close()
		_ = inW.Close()
		return nil, err
	}
	cmd := exec.Command(cfg.Cmd[0], cfg.Cmd[1:]...)
	cmd.Env = os.Environ()
	cmd.Env = append(cmd.Env, cfg.Env...)
	cmd.Stdin = inR
	cmd.Stdout = outW // stderr merged into stdout: a shell
	cmd.Stderr = outW // without visible stderr is unusable
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		_ = inR.Close()
		_ = inW.Close()
		_ = outR.Close()
		_ = outW.Close()
		return nil, err
	}
	// Child has its own copies; we keep inW (write) + outR (read).
	_ = inR.Close()
	_ = outW.Close()
	return &pipeBackend{cmd: cmd, stdin: inW, out: outR}, nil
}

func (b *pipeBackend) Read(p []byte) (int, error)  { return b.out.Read(p) }
func (b *pipeBackend) Write(p []byte) (int, error) { return b.stdin.Write(p) }

func (b *pipeBackend) Close() error {
	_ = b.stdin.Close()
	return b.out.Close()
}

func (b *pipeBackend) Resize(_, _ int) {} // no TTY: nothing to resize

func (b *pipeBackend) Wait() int {
	if err := b.cmd.Wait(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return exitErr.ExitCode()
		}
		return 1
	}
	return 0
}

// Kill kills the whole process group (Setpgid, same as the agent
// runner in cmd/runtimed).
func (b *pipeBackend) Kill() {
	if b.cmd.Process != nil {
		_ = syscall.Kill(-b.cmd.Process.Pid, syscall.SIGKILL)
	}
}
