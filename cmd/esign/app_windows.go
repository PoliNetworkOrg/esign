package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// openedAsApp is true without arguments: the Run key starts `serve` and links start `open-url`, so a bare start is a
// double-click on the executable.
func openedAsApp() bool { return true }

const attachParentProcess = ^uint32(0) // ATTACH_PARENT_PROCESS

var (
	kernel32          = windows.NewLazySystemDLL("kernel32.dll")
	procAttachConsole = kernel32.NewProc("AttachConsole")
)

func validHandle(h windows.Handle) bool { return h != 0 && h != windows.InvalidHandle }

// attachConsole connects the agent, built as a GUI program so that it never opens a console window, to the console
// of the terminal that started it, so that subcommands print there. Handles redirected to a file or pipe are kept. It
// reports whether output reaches anybody.
func attachConsole() bool {
	out, _ := windows.GetStdHandle(windows.STD_OUTPUT_HANDLE)
	errh, _ := windows.GetStdHandle(windows.STD_ERROR_HANDLE)
	if validHandle(out) && validHandle(errh) {
		return true
	}
	if r, _, _ := procAttachConsole.Call(uintptr(attachParentProcess)); r == 0 {
		return validHandle(out) || validHandle(errh)
	}
	con, err := os.OpenFile("CONOUT$", os.O_WRONLY, 0)
	if err != nil {
		return false
	}
	if !validHandle(out) {
		_ = windows.SetStdHandle(windows.STD_OUTPUT_HANDLE, windows.Handle(con.Fd()))
		os.Stdout = con
	}
	if !validHandle(errh) {
		_ = windows.SetStdHandle(windows.STD_ERROR_HANDLE, windows.Handle(con.Fd()))
		os.Stderr = con
	}
	return true
}

// serviceLog is the agent's log when nobody sees its output: started at login or by a link. It is restarted when it
// grows past 1 MB.
func serviceLog(dir string) io.Writer {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return io.Discard
	}
	path := filepath.Join(dir, "esign.log")
	flags := os.O_CREATE | os.O_WRONLY | os.O_APPEND
	if st, err := os.Stat(path); err == nil && st.Size() > 1<<20 {
		flags |= os.O_TRUNC
	}
	f, err := os.OpenFile(path, flags, 0o600)
	if err != nil {
		return io.Discard
	}
	return f
}

func osVersion() string {
	v := windows.RtlGetVersion()
	return fmt.Sprintf("Windows %d.%d.%d", v.MajorVersion, v.MinorVersion, v.BuildNumber)
}

// systemNotes reports the Smart Card service, which every provider reads cards through.
func systemNotes() []string {
	m, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return []string{"Smart Card service: unknown (" + err.Error() + ")"}
	}
	defer windows.CloseServiceHandle(m)
	name, _ := windows.UTF16PtrFromString("SCardSvr")
	s, err := windows.OpenService(m, name, windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return []string{"Smart Card service (SCardSvr): " + err.Error()}
	}
	defer windows.CloseServiceHandle(s)
	var st windows.SERVICE_STATUS
	if err := windows.QueryServiceStatus(s, &st); err != nil {
		return []string{"Smart Card service (SCardSvr): " + err.Error()}
	}
	state := map[uint32]string{windows.SERVICE_RUNNING: "running", windows.SERVICE_STOPPED: "stopped (Windows starts it when a reader is connected)"}[st.CurrentState]
	if state == "" {
		state = fmt.Sprintf("state %d", st.CurrentState)
	}
	return []string{"Smart Card service (SCardSvr): " + state}
}
