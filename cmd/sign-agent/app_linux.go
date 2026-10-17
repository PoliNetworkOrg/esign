package main

import (
	"bufio"
	"io"
	"os"
	"strings"
)

// openedAsApp is false: on Linux the agent is a command, and links run `open-url`.
func openedAsApp() bool { return false }

// attachConsole reports whether output reaches the user: systemd and terminals capture stderr.
func attachConsole() bool { return true }

func serviceLog(string) io.Writer { return os.Stderr }

func osVersion() string {
	f, err := os.Open("/etc/os-release")
	if err != nil {
		return "Linux"
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "PRETTY_NAME="); ok {
			return strings.Trim(v, `"`)
		}
	}
	return "Linux"
}

// systemNotes reports whether pcscd, which every provider reads cards through, is reachable.
func systemNotes() []string {
	for _, sock := range []string{"/run/pcscd/pcscd.comm", "/var/run/pcscd/pcscd.comm"} {
		if _, err := os.Stat(sock); err == nil {
			return []string{"pcscd: socket " + sock}
		}
	}
	return []string{"pcscd: no socket found; install and start it (Debian/Ubuntu: sudo apt install pcscd)"}
}
