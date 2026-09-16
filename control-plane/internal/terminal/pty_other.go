//go:build !linux

package terminal

import (
	"errors"
	"os"
)

// Non-Linux builds (dev machines, tests) have no PTY support — the
// production control plane always runs on Linux. Sessions there use
// pipe mode (see session.go), which needs no PTY.
func openPty() (master *os.File, slavePath string, err error) {
	return nil, "", errors.New("terminal: pty requires linux")
}

func setWinsize(f *os.File, cols, rows int) {}
