//go:build linux

package terminal

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

// Linux ioctl numbers for PTY setup. These are arch-independent
// across amd64/arm64.
const (
	tiocgptn   = 0x80045430 // TIOCGPTN: get pty number
	tiocsptlck = 0x40045431 // TIOCSPTLCK: lock/unlock pty
	tiocswinsz = 0x5414     // TIOCSWINSZ: set window size
)

// winsize mirrors struct winsize for the TIOCSWINSZ ioctl.
type winsize struct {
	rows, cols, x, y uint16
}

// openPty allocates a PTY pair and returns the master plus the slave
// path. Pure syscalls (open /dev/ptmx, unlock, /dev/pts/N) so the
// control plane gains no new dependency for one terminal endpoint.
func openPty() (master *os.File, slavePath string, err error) {
	master, err = os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		return nil, "", fmt.Errorf("terminal: open /dev/ptmx: %w", err)
	}
	closeOnErr := func() { _ = master.Close() }

	var ptyNum uint32
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, master.Fd(), tiocgptn,
		uintptr(unsafe.Pointer(&ptyNum))); errno != 0 {
		closeOnErr()
		return nil, "", fmt.Errorf("terminal: TIOCGPTN: %w", errno)
	}
	var unlock int32 // 0 = unlock
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, master.Fd(), tiocsptlck,
		uintptr(unsafe.Pointer(&unlock))); errno != 0 {
		closeOnErr()
		return nil, "", fmt.Errorf("terminal: TIOCSPTLCK: %w", errno)
	}
	return master, fmt.Sprintf("/dev/pts/%d", ptyNum), nil
}

// setWinsize sets the terminal size on an open PTY fd (master or
// slave). Out-of-range values are clamped, never rejected — a resize
// must not kill a session.
func setWinsize(f *os.File, cols, rows int) {
	if cols < 1 {
		cols = 1
	}
	if rows < 1 {
		rows = 1
	}
	if cols > 1000 {
		cols = 1000
	}
	if rows > 1000 {
		rows = 1000
	}
	ws := winsize{rows: uint16(rows), cols: uint16(cols)}
	_, _, _ = syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), tiocswinsz,
		uintptr(unsafe.Pointer(&ws)))
}
