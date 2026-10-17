package install

import (
	"encoding/xml"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/PoliNetworkOrg/sign-agent/internal/autostart"
)

// packagedExe is where the Linux package installs the agent.
const packagedExe = "/usr/bin/polinetwork-sign-agent"

// TestPackagingFiles checks that the Linux package ships the same service and link handler that `install` writes.
// SIGN_AGENT_UPDATE_PACKAGING=1 rewrites them.
func TestPackagingFiles(t *testing.T) {
	files := map[string]string{
		"polinetwork-sign-agent.desktop": DesktopEntry(packagedExe),
		"polinetwork-sign-agent.service": autostart.SystemdUnit(packagedExe),
	}
	for name, want := range files {
		path := filepath.Join("..", "..", "packaging", "linux", name)
		if os.Getenv("SIGN_AGENT_UPDATE_PACKAGING") == "1" {
			if err := os.WriteFile(path, []byte(want), 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != want {
			t.Errorf("%s differs from the template; run SIGN_AGENT_UPDATE_PACKAGING=1 go test ./internal/install", path)
		}
	}
}

func TestDesktopEntry(t *testing.T) {
	e := DesktopEntry(`/home/a b/$x/"q"/bin`)
	for _, want := range []string{
		`Exec="/home/a b/\$x/\"q\"/bin" open-url %u`,
		"MimeType=x-scheme-handler/polinetwork-sign;",
		"NoDisplay=true",
	} {
		if !strings.Contains(e, want) {
			t.Errorf("missing %q in\n%s", want, e)
		}
	}
}

func TestInfoPlist(t *testing.T) {
	p := InfoPlist("v1.4.2-rc.1")
	d := xml.NewDecoder(strings.NewReader(p))
	d.Strict = true
	for {
		_, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("Info.plist is not XML: %v", err)
		}
	}
	for _, want := range []string{
		"<string>org.polinetwork.sign-agent</string>",
		"<array><string>polinetwork-sign</string></array>",
		"<key>LSUIElement</key><true/>",
		"<key>CFBundleShortVersionString</key><string>1.4.2</string>",
		"<key>CFBundleExecutable</key><string>sign-agent</string>",
	} {
		if !strings.Contains(p, want) {
			t.Errorf("missing %s", want)
		}
	}
}

func TestBundleVersion(t *testing.T) {
	for in, want := range map[string]string{"v1.2.3": "1.2.3", "1.2.3": "1.2.3", "v0.1.0-rc.2": "0.1.0", "dev": "0.0.0", "": "0.0.0"} {
		if got := bundleVersion(in); got != want {
			t.Errorf("bundleVersion(%q) = %q", in, got)
		}
	}
}

func TestBundleOf(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("macOS paths")
	}
	for exe, want := range map[string]string{
		"/Users/a/Applications/PoliNetwork Sign Agent.app/Contents/MacOS/sign-agent": "/Users/a/Applications/PoliNetwork Sign Agent.app",
		"/Users/a/Downloads/sign-agent":                                              "",
		"/Users/a/X.app/Contents/Resources/agent":                                    "",
	} {
		got, ok := BundleOf(exe)
		if got != want || ok != (want != "") {
			t.Errorf("BundleOf(%q) = %q, %v", exe, got, ok)
		}
	}
}

func TestMakeBundleAndCopy(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "bin")
	if err := os.WriteFile(exe, []byte("binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	app := filepath.Join(dir, AppName)
	if err := MakeBundle(exe, app, "v2.0.0"); err != nil {
		t.Fatal(err)
	}
	// Making it again replaces it.
	if err := MakeBundle(exe, app, "v2.0.1"); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(app, "Contents", "MacOS", BundleExec))
	if err != nil || string(got) != "binary" {
		t.Fatalf("executable: %q %v", got, err)
	}
	plist, _ := os.ReadFile(filepath.Join(app, "Contents", "Info.plist"))
	if !strings.Contains(string(plist), "2.0.1") {
		t.Fatal("Info.plist not replaced")
	}
	if err := MakeBundle(exe, filepath.Join(dir, "NoSuffix"), "v1"); err == nil {
		t.Fatal("a bundle without .app was made")
	}
	if !sameFile(exe, exe) || sameFile(exe, app) {
		t.Fatal("sameFile")
	}
}
