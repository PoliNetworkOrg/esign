// Package install copies the agent to a stable per-user location, starts it at login and registers the
// polinetwork-esign:// link, all without administrator rights:
//
//   - macOS: ~/Applications/PoliNetwork eSign.app, a LaunchAgent, and the bundle's CFBundleURLTypes registered
//     with Launch Services.
//   - Windows: %LOCALAPPDATA%\PoliNetwork\eSign\esign.exe, the HKCU Run key, HKCU\Software\Classes and an
//     "Installed apps" entry.
//   - Linux: ~/.local/bin/polinetwork-esign (kept in place when a package installed it under /usr), a systemd user
//     service or XDG autostart entry, and a desktop entry handling x-scheme-handler/polinetwork-esign.
//
// Install and Uninstall also remove what versions up to v0.1.x, named PoliNetwork Sign Agent, registered.
package install

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"

	"github.com/PoliNetworkOrg/esign/internal/autostart"
	"github.com/PoliNetworkOrg/esign/internal/launch"
)

// Result describes an installation.
type Result struct {
	// Exe is the installed executable, which starts at login.
	Exe string
	// App is the installed macOS app bundle.
	App string
}

// URLHandlerArg is the subcommand the link handler runs, followed by the URL.
const URLHandlerArg = "open-url"

// sameFile reports whether a and b are the same file.
func sameFile(a, b string) bool {
	sa, err := os.Stat(a)
	if err != nil {
		return false
	}
	sb, err := os.Stat(b)
	if err != nil {
		return false
	}
	return os.SameFile(sa, sb)
}

// copyFile copies src to dst through a temporary file in dst's directory, renamed into place: a running copy of dst
// keeps its (now unlinked) file on Unix.
func copyFile(src, dst string, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp, err := os.CreateTemp(filepath.Dir(dst), ".esign-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := io.Copy(tmp, in); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := replace(tmp.Name(), dst); err != nil {
		return fmt.Errorf("install %s: %w", dst, err)
	}
	return nil
}

var versionPattern = regexp.MustCompile(`^v?(\d+)\.(\d+)\.(\d+)`)

// bundleVersion turns a release tag ("v1.2.3", "v1.2.3-rc.1") into a CFBundleShortVersionString / DisplayVersion.
func bundleVersion(version string) string {
	m := versionPattern.FindStringSubmatch(version)
	if m == nil {
		return "0.0.0"
	}
	return m[1] + "." + m[2] + "." + m[3]
}

// DesktopEntry is the hidden Linux application entry that handles polinetwork-esign:// links with exe.
func DesktopEntry(exe string) string {
	return fmt.Sprintf(`[Desktop Entry]
Type=Application
Name=PoliNetwork eSign
Comment=Starts the agent that signs PDFs with your CIE for the PoliNetwork dashboard
Exec=%s %s %%u
Terminal=false
NoDisplay=true
MimeType=x-scheme-handler/%s;
`, autostart.DesktopQuote(exe), URLHandlerArg, launch.Scheme)
}
