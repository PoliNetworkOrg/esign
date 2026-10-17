//go:build unix

package launch

import (
	"os"
	"os/exec"
	"runtime"
	"syscall"
)

// SpawnDetached starts exe with args in a new session, so it outlives the caller and its terminal.
func SpawnDetached(exe string, args ...string) error {
	null, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer null.Close()
	cmd := exec.Command(exe, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = null, null, null
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}

// OpenBrowser opens url in the default browser.
func OpenBrowser(url string) error {
	if runtime.GOOS == "darwin" {
		return exec.Command("/usr/bin/open", url).Run()
	}
	return SpawnDetached("xdg-open", url)
}

// Message shows msg to a user who started the agent without a terminal; it also goes to stderr.
func Message(msg string, isError bool) {
	os.Stderr.WriteString(msg + "\n")
	if runtime.GOOS == "darwin" {
		as := "informational"
		if isError {
			as = "critical"
		}
		script := `on run argv
display alert "PoliNetwork Sign Agent" message (item 1 of argv) as ` + as + `
end run`
		_ = exec.Command("/usr/bin/osascript", "-e", script, msg).Run()
		return
	}
	if path, err := exec.LookPath("notify-send"); err == nil {
		_ = exec.Command(path, "PoliNetwork Sign Agent", msg).Run()
	}
}
