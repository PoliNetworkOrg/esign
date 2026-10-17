// Package autostart registers the agent to start when the user logs in, without administrator rights: a LaunchAgent
// on macOS, a systemd user service (or an XDG autostart entry without systemd) on Linux, the Run key on Windows.
package autostart

import "errors"

// Label identifies the agent in the platform's service manager.
const Label = "org.polinetwork.sign-agent"

// ErrNotInstalled is returned by Start when the agent is not registered.
var ErrNotInstalled = errors.New("the agent is not set to start at login")
