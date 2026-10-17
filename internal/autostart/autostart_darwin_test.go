package autostart

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestPlist(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	exe := "/Users/a & b/Applications/PoliNetwork Sign Agent.app/Contents/MacOS/sign-agent"
	path, err := plistPath()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := Installed(); ok {
		t.Fatal("installed before writing the LaunchAgent")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(plist(exe)), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("/usr/bin/plutil", "-lint", path).CombinedOutput(); err != nil {
		t.Fatalf("plutil: %v: %s", err, out)
	}
	if got, ok := Installed(); !ok || got != exe {
		t.Fatalf("Installed() = %q, %v", got, ok)
	}
}
