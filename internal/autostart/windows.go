//go:build windows

package autostart

import (
	"os/exec"
	"syscall"

	"golang.org/x/sys/windows/registry"
)

const (
	runKey    = `Software\Microsoft\Windows\CurrentVersion\Run`
	valueName = "PoliNetworkSignAgent"
	// createNoWindow keeps a console window from appearing for the background agent.
	createNoWindow = 0x08000000
	detached       = 0x00000008
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
	cmd := exec.Command(exe, "serve")
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: createNoWindow | detached, HideWindow: true}
	return cmd.Start()
}

// Uninstall removes the Run entry. A running agent keeps running until the user logs out.
func Uninstall() error {
	k, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.SET_VALUE)
	if err != nil {
		return nil
	}
	defer k.Close()
	if err := k.DeleteValue(valueName); err != nil && err != registry.ErrNotExist {
		return err
	}
	return nil
}
