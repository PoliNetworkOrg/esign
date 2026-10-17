package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/PoliNetworkOrg/esign/internal/install"
)

// AppKit, which reads the launch's Apple Event, must run on the main thread.
func init() { runtime.LockOSThread() }

// openedAsApp reports whether Launch Services started the app bundle: from Finder, the Dock or a link.
func openedAsApp() bool {
	_, ok := install.BundleOf(executable())
	return ok
}

// attachConsole reports whether output reaches the user: the LaunchAgent and terminals capture stderr.
func attachConsole() bool { return true }

func serviceLog(string) io.Writer { return os.Stderr }

func osVersion() string {
	out, err := exec.Command("/usr/bin/sw_vers", "-productVersion").Output()
	if err != nil {
		return "macOS"
	}
	return "macOS " + strings.TrimSpace(string(out))
}

func plistString(path, key string) string {
	out, err := exec.Command("/usr/bin/plutil", "-extract", key, "raw", "-o", "-", path).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// systemNotes reports the Software CIE app and its paired cards.
func systemNotes() []string {
	var notes []string
	app := "/Applications/CIE ID.app"
	if _, err := os.Stat(app); err == nil {
		info := filepath.Join(app, "Contents", "Info.plist")
		notes = append(notes, fmt.Sprintf("Software CIE: %s %s (%s)", app, plistString(info, "CFBundleShortVersionString"), plistString(info, "CFBundleIdentifier")))
	} else {
		notes = append(notes, "Software CIE: not installed (Mac App Store, \"Software CIE\")")
	}
	home, _ := os.UserHomeDir()
	cache := filepath.Join(home, "Library", "Group Containers", "group.it.ipzs.SoftwareCIE", "Library", "Caches", "CIEPKI")
	entries, err := os.ReadDir(cache)
	switch {
	case err == nil:
		n := 0
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".cache") {
				n++
			}
		}
		notes = append(notes, fmt.Sprintf("paired cards: %d in %s", n, cache))
	case os.IsPermission(err):
		notes = append(notes, "paired cards: unknown, macOS did not let this program read "+cache)
	default:
		notes = append(notes, "paired cards: none ("+cache+" is absent)")
	}
	return notes
}
