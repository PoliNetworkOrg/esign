//go:build linux || freebsd

package autostart

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/PoliNetworkOrg/sign-agent/internal/launch"
)

// UnitName is the systemd user service.
const UnitName = "polinetwork-sign-agent.service"

func configHome() (string, error) {
	if dir := os.Getenv("XDG_CONFIG_HOME"); dir != "" {
		return dir, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config"), nil
}

func paths() (unit, desktop string, err error) {
	cfg, err := configHome()
	if err != nil {
		return "", "", err
	}
	return filepath.Join(cfg, "systemd", "user", UnitName), filepath.Join(cfg, "autostart", "polinetwork-sign-agent.desktop"), nil
}

// systemUnits are where a package installs the user service, and where `systemctl --global enable` links it.
var (
	systemUnits   = []string{"/usr/lib/systemd/user/" + UnitName, "/etc/systemd/user/" + UnitName}
	globalEnabled = "/etc/systemd/user/default.target.wants/" + UnitName
)

// unitFile returns the user service's unit: the user's own, or the package's when enabled for every user.
func unitFile() (string, bool) {
	if unit, _, err := paths(); err == nil {
		if _, err := os.Stat(unit); err == nil {
			return unit, true
		}
	}
	if _, err := os.Stat(globalEnabled); err != nil {
		return "", false
	}
	for _, u := range systemUnits {
		if _, err := os.Stat(u); err == nil {
			return u, true
		}
	}
	return "", false
}

func autostartEntry(exe string) string {
	return fmt.Sprintf(`[Desktop Entry]
Type=Application
Name=PoliNetwork Sign Agent
Comment=CIE signing for the PoliNetwork dashboard
Exec=%s serve
Terminal=false
NoDisplay=true
X-GNOME-Autostart-enabled=true
`, DesktopQuote(exe))
}

func hasSystemd() bool {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return false
	}
	return exec.Command("systemctl", "--user", "show-environment").Run() == nil
}

func systemctl(args ...string) error {
	if out, err := exec.Command("systemctl", append([]string{"--user"}, args...)...).CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl --user %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Install registers a systemd user service when systemd is available, else an XDG autostart entry, and starts the
// agent now (restarting a running service, so an updated executable takes over).
func Install(exe string) error {
	unit, desktop, err := paths()
	if err != nil {
		return err
	}
	if hasSystemd() {
		if err := os.MkdirAll(filepath.Dir(unit), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(unit, []byte(SystemdUnit(exe)), 0o644); err != nil {
			return err
		}
		_ = os.Remove(desktop)
		if err := systemctl("daemon-reload"); err != nil {
			return err
		}
		if err := systemctl("enable", UnitName); err != nil {
			return err
		}
		return systemctl("restart", UnitName)
	}
	if err := os.MkdirAll(filepath.Dir(desktop), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(desktop, []byte(autostartEntry(exe)), 0o644); err != nil {
		return err
	}
	return launch.SpawnDetached(exe, "serve")
}

// Stop stops the service. An agent started from the XDG entry is not tracked; the installer stops it by path.
func Stop() {
	if _, ok := unitFile(); ok && hasSystemd() {
		_ = systemctl("stop", UnitName)
	}
}

// Start starts the installed agent now.
func Start() error {
	exe, ok := Installed()
	if !ok {
		return ErrNotInstalled
	}
	if _, ok := unitFile(); ok && hasSystemd() {
		return systemctl("start", UnitName)
	}
	return launch.SpawnDetached(exe, "serve")
}

var (
	execStartPattern = regexp.MustCompile(`(?m)^ExecStart="((?:[^"\\]|\\.)*)" serve$`)
	desktopPattern   = regexp.MustCompile(`(?m)^Exec="((?:[^"\\]|\\.)*)" serve$`)
)

// Installed returns the executable registered to start at login.
func Installed() (string, bool) {
	_, desktop, err := paths()
	if err != nil {
		return "", false
	}
	if unit, ok := unitFile(); ok {
		data, err := os.ReadFile(unit)
		if err != nil {
			return "", false
		}
		if m := execStartPattern.FindSubmatch(data); m != nil {
			return strings.NewReplacer(`\\`, `\`, `\"`, `"`, "%%", "%").Replace(string(m[1])), true
		}
		return "", false
	}
	if data, err := os.ReadFile(desktop); err == nil {
		if m := desktopPattern.FindSubmatch(data); m != nil {
			return strings.NewReplacer(`\\\\`, `\`, `\"`, `"`, "\\`", "`", `\$`, "$", "%%", "%").Replace(string(m[1])), true
		}
	}
	return "", false
}

// Describe names the registration, for diagnostics.
func Describe() string {
	if unit, ok := unitFile(); ok {
		return "systemd user service " + unit
	}
	if hasSystemd() {
		unit, _, _ := paths()
		return "systemd user service " + unit
	}
	_, desktop, _ := paths()
	return "XDG autostart entry " + desktop
}

// Uninstall stops and removes the service or autostart entry.
func Uninstall() error {
	unit, desktop, err := paths()
	if err != nil {
		return err
	}
	if _, err := os.Stat(unit); err == nil && hasSystemd() {
		_ = systemctl("disable", "--now", UnitName)
	}
	for _, p := range []string{unit, desktop} {
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	if hasSystemd() {
		_ = systemctl("daemon-reload")
	}
	return nil
}
