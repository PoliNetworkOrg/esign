package launch

import (
	"os"
	"os/exec"
	"syscall"

	"golang.org/x/sys/windows"
)

const (
	detachedProcess = 0x00000008
	createNewGroup  = 0x00000200
	createNoWindow  = 0x08000000
)

// SpawnDetached starts exe with args without a console, so it outlives the caller.
func SpawnDetached(exe string, args ...string) error {
	cmd := exec.Command(exe, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: detachedProcess | createNewGroup | createNoWindow, HideWindow: true}
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}

// OpenBrowser opens url in the default browser.
func OpenBrowser(url string) error {
	verb, _ := windows.UTF16PtrFromString("open")
	target, err := windows.UTF16PtrFromString(url)
	if err != nil {
		return err
	}
	return windows.ShellExecute(0, verb, target, nil, nil, windows.SW_SHOWNORMAL)
}

// Message shows msg in a message box; it also goes to stderr.
func Message(msg string, isError bool) {
	os.Stderr.WriteString(msg + "\n")
	title, _ := windows.UTF16PtrFromString("PoliNetwork eSign")
	text, err := windows.UTF16PtrFromString(msg)
	if err != nil {
		return
	}
	icon := uint32(windows.MB_ICONINFORMATION)
	if isError {
		icon = windows.MB_ICONERROR
	}
	_, _ = windows.MessageBox(0, text, title, windows.MB_OK|icon)
}
