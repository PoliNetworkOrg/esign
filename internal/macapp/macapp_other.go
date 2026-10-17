//go:build !darwin

package macapp

import "time"

// Wait returns an empty Launch: only macOS delivers links as Apple Events.
func Wait(time.Duration) Launch { return Launch{} }
