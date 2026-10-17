package install

import (
	"os"
	"os/exec"
	"path/filepath"
)

// removeLegacy removes what versions up to v0.1.x, named polinetwork-sign-agent, installed for the user: their
// service or autostart entry, which would start the old agent on the same port, link handler and copy. It also stops
// an old agent that a package installed; the new package replaces that one.
func removeLegacy() {
	const name = "polinetwork-sign-agent"
	if _, err := exec.LookPath("systemctl"); err == nil {
		_ = exec.Command("systemctl", "--user", "disable", "--now", name+".service").Run()
	}
	for _, p := range []string{
		filepath.Join(configHome(), "systemd", "user", name+".service"),
		filepath.Join(configHome(), "autostart", name+".desktop"),
		filepath.Join(dataHome(), "applications", name+".desktop"),
	} {
		_ = os.Remove(p)
	}
	exe := filepath.Join(home(), ".local", "bin", name)
	stopRunning(exe)
	stopRunning("/usr/bin/" + name)
	_ = os.Remove(exe)
	if _, err := exec.LookPath("systemctl"); err == nil {
		_ = exec.Command("systemctl", "--user", "daemon-reload").Run()
	}
}
