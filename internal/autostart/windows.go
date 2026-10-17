//go:build windows

package autostart

import (
	"errors"
	"strings"

	"golang.org/x/sys/windows/registry"

	"github.com/PoliNetworkOrg/sign-agent/internal/launch"
)

const (
	runKey    = `Software\Microsoft\Windows\CurrentVersion\Run`
	valueName = "PoliNetworkSignAgent"
)

// Install adds the agent to the current user's Run key and starts it now.
func Install(exe string) error {
	k, _, err := registry.CreateKey(registry.CURRENT_USER, runKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	if err := k.SetStringValue(valueName, `"`+exe+`" serve`); err != nil {
		return err
	}
	return launch.SpawnDetached(exe, "serve")
}

// Stop does nothing: the Run key does not track the process; the installer stops it by path.
func Stop() {}

// Start starts the installed agent now.
func Start() error {
	exe, ok := Installed()
	if !ok {
		return ErrNotInstalled
	}
	return launch.SpawnDetached(exe, "serve")
}

// Installed returns the executable registered to start at login.
func Installed() (string, bool) {
	k, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.QUERY_VALUE)
	if err != nil {
		return "", false
	}
	defer k.Close()
	v, _, err := k.GetStringValue(valueName)
	if err != nil {
		return "", false
	}
	exe, ok := strings.CutPrefix(v, `"`)
	if !ok {
		return "", false
	}
	exe, _, ok = strings.Cut(exe, `"`)
	return exe, ok
}

// Describe names the registration, for diagnostics.
func Describe() string { return `HKCU\` + runKey + `\` + valueName }

// Uninstall removes the Run entry. A running agent is stopped by the installer.
func Uninstall() error {
	k, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.SET_VALUE)
	if err != nil {
		return nil
	}
	defer k.Close()
	if err := k.DeleteValue(valueName); err != nil && !errors.Is(err, registry.ErrNotExist) {
		return err
	}
	return nil
}
