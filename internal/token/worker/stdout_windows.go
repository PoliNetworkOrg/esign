package worker

import (
	"os"

	"golang.org/x/sys/windows"
)

// isolateStdout returns the original stdout for the protocol and makes stderr the process's standard output, before
// any module (and its C runtime) is loaded.
func isolateStdout() (*os.File, error) {
	out, err := windows.GetStdHandle(windows.STD_OUTPUT_HANDLE)
	if err != nil {
		return nil, err
	}
	errh, err := windows.GetStdHandle(windows.STD_ERROR_HANDLE)
	if err != nil {
		return nil, err
	}
	if err := windows.SetStdHandle(windows.STD_OUTPUT_HANDLE, errh); err != nil {
		return nil, err
	}
	os.Stdout = os.Stderr
	return os.NewFile(uintptr(out), "worker-protocol"), nil
}
