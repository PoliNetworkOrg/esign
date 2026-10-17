package install

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/windows/registry"
)

// removeLegacy removes what versions up to v0.1.x, named PoliNetwork Sign Agent, installed: their Run entry, which
// would start the old agent on the same port, link handler, "Installed apps" entry and copy.
func removeLegacy() {
	exe, _, err := Location()
	if err != nil {
		return
	}
	if k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Run`, registry.SET_VALUE); err == nil {
		_ = k.DeleteValue("PoliNetworkSignAgent")
		k.Close()
	}
	dir := filepath.Join(filepath.Dir(filepath.Dir(exe)), "SignAgent")
	old := filepath.Join(dir, "sign-agent.exe")
	stopRunning(old)
	_ = deleteTree(`Software\Classes\polinetwork-sign`)
	_ = deleteTree(`Software\Microsoft\Windows\CurrentVersion\Uninstall\PoliNetworkSignAgent`)
	_ = os.Remove(old)
	_ = os.Remove(dir)
}
