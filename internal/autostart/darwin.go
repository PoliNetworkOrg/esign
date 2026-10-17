//go:build darwin

package autostart

import (
	"fmt"
	"html"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

func plistPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "Library", "LaunchAgents", Label+".plist"), nil
}

// LogPath is where the agent started at login writes its log.
func LogPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "Library", "Logs", "PoliNetwork eSign.log")
}

func xmlEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

func domain() string { return "gui/" + strconv.Itoa(os.Getuid()) }

// plist is the LaunchAgent. KeepAlive restarts the agent only after a failure: an agent that exits cleanly, because
// another one already serves the port, stays stopped. AssociatedBundleIdentifiers names the app, rather than an
// unidentified developer, in System Settings > General > Login Items.
func plist(exe string) string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key><string>%s</string>
	<key>ProgramArguments</key>
	<array><string>%s</string><string>serve</string></array>
	<key>AssociatedBundleIdentifiers</key><string>%s</string>
	<key>RunAtLoad</key><true/>
	<key>KeepAlive</key>
	<dict><key>SuccessfulExit</key><false/></dict>
	<key>ThrottleInterval</key><integer>10</integer>
	<key>LimitLoadToSessionType</key><string>Aqua</string>
	<key>ProcessType</key><string>Interactive</string>
	<key>StandardErrorPath</key><string>%s</string>
	<key>StandardOutPath</key><string>%s</string>
</dict>
</plist>
`, Label, xmlEscape(exe), Label, xmlEscape(LogPath()), xmlEscape(LogPath()))
}

// Install writes a per-user LaunchAgent that runs exe at login and after failures, and starts it now, replacing a
// running agent.
func Install(exe string) error {
	path, err := plistPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(LogPath()), 0o755); err != nil {
		return err
	}
	Stop()
	if err := os.WriteFile(path, []byte(plist(exe)), 0o644); err != nil {
		return err
	}
	// A user who disabled the agent in Login Items has it marked disabled; installing again is an explicit opt-in.
	_ = exec.Command("launchctl", "enable", domain()+"/"+Label).Run()
	return bootstrap(path)
}

// bootstrap loads the LaunchAgent. Right after a bootout, launchd may still be tearing the old job down and refuse
// with an I/O error, so it retries for a few seconds.
func bootstrap(path string) error {
	var out []byte
	var err error
	for range 10 {
		if out, err = exec.Command("launchctl", "bootstrap", domain(), path).CombinedOutput(); err == nil {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("launchctl bootstrap: %v: %s", err, strings.TrimSpace(string(out)))
}

// Stop unloads the LaunchAgent, stopping the agent it started.
func Stop() {
	_ = exec.Command("launchctl", "bootout", domain()+"/"+Label).Run()
}

// Start starts the installed agent now.
func Start() error {
	path, err := plistPath()
	if err != nil {
		return err
	}
	if _, err := os.Stat(path); err != nil {
		return ErrNotInstalled
	}
	if exec.Command("launchctl", "kickstart", domain()+"/"+Label).Run() == nil {
		return nil
	}
	return bootstrap(path)
}

var programPattern = regexp.MustCompile(`<key>ProgramArguments</key>\s*<array>\s*<string>([^<]*)</string>`)

// Installed returns the executable the LaunchAgent runs.
func Installed() (string, bool) {
	path, err := plistPath()
	if err != nil {
		return "", false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	m := programPattern.FindSubmatch(data)
	if m == nil {
		return "", false
	}
	return html.UnescapeString(string(m[1])), true
}

// Describe names the registration, for diagnostics.
func Describe() string {
	path, _ := plistPath()
	return "LaunchAgent " + path
}

// Uninstall stops the agent and removes the LaunchAgent.
func Uninstall() error {
	path, err := plistPath()
	if err != nil {
		return err
	}
	Stop()
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
