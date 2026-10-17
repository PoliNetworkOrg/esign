package install

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/PoliNetworkOrg/sign-agent/internal/launch"
)

// macOS bundle identity.
const (
	AppName    = "PoliNetwork Sign Agent.app"
	BundleID   = "org.polinetwork.sign-agent"
	BundleExec = "sign-agent"
)

// InfoPlist is the app bundle's Info.plist: a background app (LSUIElement, no Dock icon) that handles
// polinetwork-sign:// links. The universal binary runs natively; its x86_64 half serves the Intel-only CIE middleware
// through Rosetta.
func InfoPlist(version string) string {
	v := bundleVersion(version)
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleDevelopmentRegion</key><string>en</string>
	<key>CFBundleDisplayName</key><string>PoliNetwork Sign Agent</string>
	<key>CFBundleExecutable</key><string>%s</string>
	<key>CFBundleIconFile</key><string>AppIcon</string>
	<key>CFBundleIdentifier</key><string>%s</string>
	<key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
	<key>CFBundleName</key><string>PoliNetwork Sign Agent</string>
	<key>CFBundlePackageType</key><string>APPL</string>
	<key>CFBundleShortVersionString</key><string>%s</string>
	<key>CFBundleVersion</key><string>%s</string>
	<key>CFBundleURLTypes</key>
	<array>
		<dict>
			<key>CFBundleURLName</key><string>%s</string>
			<key>CFBundleURLSchemes</key>
			<array><string>%s</string></array>
		</dict>
	</array>
	<key>LSApplicationCategoryType</key><string>public.app-category.utilities</string>
	<key>LSMinimumSystemVersion</key><string>11.0</string>
	<key>LSUIElement</key><true/>
	<key>NSHighResolutionCapable</key><true/>
	<key>NSHumanReadableCopyright</key><string>PoliNetwork APS</string>
</dict>
</plist>
`, BundleExec, BundleID, v, v, BundleID, launch.Scheme)
}

// MakeBundle creates the app bundle app around the executable exe. An existing bundle there is replaced.
func MakeBundle(exe, app, version string) error {
	if !strings.HasSuffix(app, ".app") {
		return fmt.Errorf("%s: an app bundle name ends in .app", app)
	}
	if err := os.RemoveAll(app); err != nil {
		return err
	}
	contents := filepath.Join(app, "Contents")
	if err := os.MkdirAll(filepath.Join(contents, "Resources"), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(contents, "Info.plist"), []byte(InfoPlist(version)), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(contents, "PkgInfo"), []byte("APPL????"), 0o644); err != nil {
		return err
	}
	return copyFile(exe, filepath.Join(contents, "MacOS", BundleExec), 0o755)
}

// BundleOf returns the app bundle containing exe, when exe is a bundle's executable (X.app/Contents/MacOS/exe).
func BundleOf(exe string) (string, bool) {
	macos := filepath.Dir(exe)
	contents := filepath.Dir(macos)
	app := filepath.Dir(contents)
	if filepath.Base(macos) != "MacOS" || filepath.Base(contents) != "Contents" || !strings.HasSuffix(app, ".app") {
		return "", false
	}
	return app, true
}
