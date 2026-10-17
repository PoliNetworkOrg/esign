//go:build linux

package autostart

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInstalledParsesEntries(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
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
