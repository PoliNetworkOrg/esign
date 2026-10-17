//go:build unix

package worker

import (
	"os"

	"golang.org/x/sys/unix"
)

// isolateStdout returns a duplicate of stdout for the protocol and points file descriptor 1 at stderr.
func isolateStdout() (*os.File, error) {
	fd, err := unix.Dup(1)
	if err != nil {
		return nil, err
	}
	unix.CloseOnExec(fd)
	if err := dup2(2, 1); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	out := os.NewFile(uintptr(fd), "worker-protocol")
	os.Stdout = os.Stderr
	return out, nil
}
