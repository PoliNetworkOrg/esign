package install

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/PoliNetworkOrg/sign-agent/internal/autostart"
)

const lsregister = "/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister"

// Location returns the installed app bundle and its executable.
func Location() (exe, app string, err error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", "", err
	}
	app = filepath.Join(home, "Applications", AppName)
	return filepath.Join(app, "Contents", "MacOS", BundleExec), app, nil
}

// IsInstalled reports whether exe is the installed copy and starts at login.
func IsInstalled(exe string) bool {
	dest, _, err := Location()
	if err != nil || !sameFile(exe, dest) {
		return false
	}
	registered, ok := autostart.Installed()
	return ok && sameFile(registered, dest)
}

// Install copies the app containing src (or a new bundle around a bare src executable) to ~/Applications, registers
// its link scheme and starts it at login.
func Install(src, version string) (Result, error) {
	exe, app, err := Location()
	if err != nil {
		return Result{}, err
	}
	res := Result{Exe: exe, App: app}
	srcApp, inBundle := BundleOf(src)
	autostart.Stop()
	if !inBundle || !sameFile(srcApp, app) {
		if err := os.MkdirAll(filepath.Dir(app), 0o755); err != nil {
			return res, err
		}
		tmp := strings.TrimSuffix(app, ".app") + ".installing.app"
		if err := os.RemoveAll(tmp); err != nil {
			return res, err
		}
		if inBundle {
			if out, err := exec.Command("/usr/bin/ditto", srcApp, tmp).CombinedOutput(); err != nil {
				return res, fmt.Errorf("copy %s: %v: %s", srcApp, err, out)
			}
		} else {
			if err := MakeBundle(src, tmp, version); err != nil {
				return res, err
			}
			// Seal Info.plist into the ad-hoc signature, like the released bundle.
			_ = exec.Command("/usr/bin/codesign", "--force", "--sign", "-", tmp).Run()
		}
		// The user opened this copy, so Gatekeeper already let it run; launchd would not ask again.
		_ = exec.Command("/usr/bin/xattr", "-dr", "com.apple.quarantine", tmp).Run()
		if _, err := os.Stat(app); err == nil {
			_ = exec.Command(lsregister, "-u", app).Run()
			if err := os.RemoveAll(app); err != nil {
				return res, err
			}
		}
		if err := os.Rename(tmp, app); err != nil {
			return res, err
		}
	}
	if out, err := exec.Command(lsregister, "-f", app).CombinedOutput(); err != nil {
		return res, fmt.Errorf("register %s with Launch Services: %v: %s", app, err, out)
	}
	return res, autostart.Install(exe)
}

// Uninstall stops the agent, removes it from login items and Launch Services, and deletes the installed app.
func Uninstall(self string) ([]string, error) {
	_, app, err := Location()
	if err != nil {
		return nil, err
	}
	if err := autostart.Uninstall(); err != nil {
		return nil, err
	}
	if _, err := os.Stat(app); err != nil {
		return nil, nil
	}
	_ = exec.Command(lsregister, "-u", app).Run()
	if err := os.RemoveAll(app); err != nil {
		return nil, err
	}
	return []string{"Removed " + app}, nil
}

// Describe lists what Install registers, for diagnostics.
func Describe() []string {
	_, app, _ := Location()
	return []string{"app " + app, autostart.Describe(), "link handler: CFBundleURLTypes of the app (Launch Services)"}
}
