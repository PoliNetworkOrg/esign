package install

import (
	"encoding/xml"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/PoliNetworkOrg/esign/internal/autostart"
)

// packagedExe is where the Linux package installs the agent.
const packagedExe = "/usr/bin/polinetwork-esign"

// TestPackagingFiles checks that the Linux package ships the same service and link handler that `install` writes.
// ESIGN_UPDATE_PACKAGING=1 rewrites them.
func TestPackagingFiles(t *testing.T) {
	files := map[string]string{
		"polinetwork-esign.desktop": DesktopEntry(packagedExe),
		"polinetwork-esign.service": autostart.SystemdUnit(packagedExe),
	}
	for name, want := range files {
		path := filepath.Join("..", "..", "packaging", "linux", name)
		if os.Getenv("ESIGN_UPDATE_PACKAGING") == "1" {
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
			t.Errorf("%s differs from the template; run ESIGN_UPDATE_PACKAGING=1 go test ./internal/install", path)
		}
	}
}

func TestDesktopEntry(t *testing.T) {
	e := DesktopEntry(`/home/a b/$x/"q"/bin`)
	for _, want := range []string{
		`Exec="/home/a b/\$x/\"q\"/bin" open-url %u`,
		"MimeType=x-scheme-handler/polinetwork-esign;",
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
		"<string>org.polinetwork.esign</string>",
		"<array><string>polinetwork-esign</string></array>",
		"<key>LSUIElement</key><true/>",
		"<key>CFBundleShortVersionString</key><string>1.4.2</string>",
		"<key>CFBundleExecutable</key><string>esign</string>",
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
		"/Users/a/Applications/PoliNetwork eSign.app/Contents/MacOS/esign": "/Users/a/Applications/PoliNetwork eSign.app",
		"/Users/a/Downloads/esign":                "",
		"/Users/a/X.app/Contents/Resources/agent": "",
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
