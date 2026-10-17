//go:build linux || freebsd

package autostart

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const unitName = "polinetwork-sign-agent.service"

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

// systemdQuote quotes an argument for a unit's ExecStart.
func systemdQuote(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`, "%", "%%").Replace(s) + `"`
}

// desktopQuote quotes an argument for a desktop entry's Exec key.
func desktopQuote(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\\\`, `"`, `\"`, "`", "\\`", "$", `\$`, "%", "%%").Replace(s) + `"`
}

// Install registers a systemd user service when systemd is available, else an XDG autostart entry, and starts it.
func Install(exe string) error {
	cfg, err := configHome()
	if err != nil {
		return err
	}
	if _, err := exec.LookPath("systemctl"); err == nil && exec.Command("systemctl", "--user", "show-environment").Run() == nil {
		unit := fmt.Sprintf(`[Unit]
Description=PoliNetwork Sign Agent (CIE signing for the PoliNetwork dashboard)
After=graphical-session.target pcscd.socket

[Service]
ExecStart=%s serve
Restart=on-failure
RestartSec=3

[Install]
WantedBy=default.target
`, systemdQuote(exe))
		path := filepath.Join(cfg, "systemd", "user", unitName)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(path, []byte(unit), 0o644); err != nil {
			return err
		}
		if out, err := exec.Command("systemctl", "--user", "daemon-reload").CombinedOutput(); err != nil {
			return fmt.Errorf("systemctl daemon-reload: %v: %s", err, out)
		}
		if out, err := exec.Command("systemctl", "--user", "enable", "--now", unitName).CombinedOutput(); err != nil {
			return fmt.Errorf("systemctl enable: %v: %s", err, out)
		}
		return nil
	}
	entry := fmt.Sprintf(`[Desktop Entry]
Type=Application
Name=PoliNetwork Sign Agent
Exec=%s serve
X-GNOME-Autostart-enabled=true
NoDisplay=true
`, desktopQuote(exe))
	path := filepath.Join(cfg, "autostart", "polinetwork-sign-agent.desktop")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(path, []byte(entry), 0o644); err != nil {
		return err
	}
	return exec.Command(exe, "serve").Start()
}

// Uninstall removes the service or autostart entry.
func Uninstall() error {
	cfg, err := configHome()
	if err != nil {
		return err
	}
	if _, err := exec.LookPath("systemctl"); err == nil {
		_ = exec.Command("systemctl", "--user", "disable", "--now", unitName).Run()
	}
	for _, p := range []string{
		filepath.Join(cfg, "systemd", "user", unitName),
		filepath.Join(cfg, "autostart", "polinetwork-sign-agent.desktop"),
	} {
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}
