//go:build linux

package autostart

import (
	"os"
	"path/filepath"
	"testing"
)

// isolate keeps the tests away from the machine's own registration: a user config directory and package unit paths
// in a temporary directory, so an agent installed on the machine running the tests does not count.
func isolate(t *testing.T) {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	system := t.TempDir()
	units, enabled := systemUnits, globalEnabled
	t.Cleanup(func() { systemUnits, globalEnabled = units, enabled })
	systemUnits = []string{filepath.Join(system, "lib", UnitName), filepath.Join(system, "etc", UnitName)}
	globalEnabled = filepath.Join(system, "etc", "default.target.wants", UnitName)
}

func TestInstalledParsesEntries(t *testing.T) {
	isolate(t)
	unit, desktop, err := paths()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := Installed(); ok {
		t.Fatal("installed with no entries")
	}
	exe := `/home/a b/50%/"x"/$y\z`
	if err := os.MkdirAll(filepath.Dir(desktop), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(desktop, []byte(autostartEntry(exe)), 0o644); err != nil {
		t.Fatal(err)
	}
	if got, ok := Installed(); !ok || got != exe {
		t.Fatalf("XDG entry: %q, %v", got, ok)
	}
	if err := os.MkdirAll(filepath.Dir(unit), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(unit, []byte(SystemdUnit(exe)), 0o644); err != nil {
		t.Fatal(err)
	}
	if got, ok := Installed(); !ok || got != exe {
		t.Fatalf("systemd unit: %q, %v", got, ok)
	}
}

// TestInstalledPackageUnit: the package's unit counts only once enabled for every user.
func TestInstalledPackageUnit(t *testing.T) {
	isolate(t)
	exe := "/usr/bin/polinetwork-esign"
	if err := os.MkdirAll(filepath.Dir(systemUnits[0]), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(systemUnits[0], []byte(SystemdUnit(exe)), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, ok := Installed(); ok {
		t.Fatal("installed while the package unit is not enabled")
	}
	if err := os.MkdirAll(filepath.Dir(globalEnabled), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(systemUnits[0], globalEnabled); err != nil {
		t.Fatal(err)
	}
	if got, ok := Installed(); !ok || got != exe {
		t.Fatalf("package unit: %q, %v", got, ok)
	}
}
