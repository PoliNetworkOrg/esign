package install

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
)

// removeLegacy removes what versions up to v0.1.x, named PoliNetwork Sign Agent, installed: their LaunchAgent, which
// would start the old agent on the same port, and their app.
func removeLegacy() {
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}
	const label = "org.polinetwork.sign-agent"
	_ = exec.Command("launchctl", "bootout", "gui/"+strconv.Itoa(os.Getuid())+"/"+label).Run()
	_ = os.Remove(filepath.Join(home, "Library", "LaunchAgents", label+".plist"))
	app := filepath.Join(home, "Applications", "PoliNetwork Sign Agent.app")
	if _, err := os.Stat(app); err == nil {
		_ = exec.Command(lsregister, "-u", app).Run()
		_ = os.RemoveAll(app)
	}
}
