//go:build !windows

package worker

import "os/exec"

func hideWindow(*exec.Cmd) {}
