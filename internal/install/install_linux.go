package install

import (
	"bufio"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/PoliNetworkOrg/sign-agent/internal/autostart"
	"github.com/PoliNetworkOrg/sign-agent/internal/launch"
)

const desktopName = "polinetwork-sign-agent.desktop"

func home() string {
	h, _ := os.UserHomeDir()
	return h
}

func dataHome() string {
	if d := os.Getenv("XDG_DATA_HOME"); d != "" {
		return d
	}
	return filepath.Join(home(), ".local", "share")
}

func configHome() string {
	if d := os.Getenv("XDG_CONFIG_HOME"); d != "" {
		return d
	}
	return filepath.Join(home(), ".config")
}

// Location returns where Install copies the agent.
func Location() (exe, app string, err error) {
	h, err := os.UserHomeDir()
	if err != nil {
		return "", "", err
	}
	return filepath.Join(h, ".local", "bin", "polinetwork-sign-agent"), "", nil
}

// packaged reports whether exe was installed by a system package, which owns its location and updates.
func packaged(exe string) bool {
	return strings.HasPrefix(exe, "/usr/") || strings.HasPrefix(exe, "/opt/")
}

// IsInstalled reports whether exe is the installed copy and starts at login.
func IsInstalled(exe string) bool {
	dest, _, err := Location()
	if err != nil {
		return false
	}
	if packaged(exe) {
		dest = exe
	}
	registered, ok := autostart.Installed()
	return sameFile(exe, dest) && ok && sameFile(registered, dest)
}

// stopRunning terminates agents running from path, other than this process.
func stopRunning(path string) {
	entries, _ := os.ReadDir("/proc")
	var stopped []int
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == os.Getpid() {
			continue
		}
		target, err := os.Readlink(filepath.Join("/proc", e.Name(), "exe"))
		if err != nil || strings.TrimSuffix(target, " (deleted)") != path {
			continue
		}
		if syscall.Kill(pid, syscall.SIGTERM) == nil {
			stopped = append(stopped, pid)
		}
	}
	for range 20 {
		alive := false
		for _, pid := range stopped {
			if syscall.Kill(pid, 0) == nil {
				alive = true
			}
		}
		if !alive {
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// Install copies src to ~/.local/bin (unless a package installed it), registers the polinetwork-sign:// handler and
// starts the agent at login.
func Install(src, version string) (Result, error) {
	exe, _, err := Location()
	if err != nil {
		return Result{}, err
	}
	if packaged(src) {
		exe = src
	}
	autostart.Stop()
	stopRunning(exe)
	if !sameFile(src, exe) {
		if err := copyFile(src, exe, 0o755); err != nil {
			return Result{Exe: exe}, err
		}
	}
	if err := registerScheme(exe); err != nil {
		return Result{Exe: exe}, err
	}
	return Result{Exe: exe}, autostart.Install(exe)
}

func registerScheme(exe string) error {
	apps := filepath.Join(dataHome(), "applications")
	if err := os.MkdirAll(apps, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(apps, desktopName), []byte(DesktopEntry(exe)), 0o644); err != nil {
		return err
	}
	mime := "x-scheme-handler/" + launch.Scheme
	if path, err := exec.LookPath("xdg-mime"); err == nil && exec.Command(path, "default", desktopName, mime).Run() == nil {
		// xdg-mime wrote mimeapps.list.
	} else if err := setDefault(filepath.Join(configHome(), "mimeapps.list"), mime, desktopName); err != nil {
		return err
	}
	if path, err := exec.LookPath("update-desktop-database"); err == nil {
		_ = exec.Command(path, apps).Run()
	}
	return nil
}

// setDefault sets "mime=desktop" in the [Default Applications] group of a mimeapps.list, keeping everything else.
func setDefault(path, mime, desktop string) error {
	var lines []string
	if f, err := os.Open(path); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			lines = append(lines, sc.Text())
		}
		f.Close()
		if err := sc.Err(); err != nil {
			return err
		}
	}
	entry := mime + "=" + desktop
	var out []string
	group, done := "", false
	for _, l := range lines {
		t := strings.TrimSpace(l)
		if strings.HasPrefix(t, "[") {
			if group == "[Default Applications]" && !done {
				out = append(out, entry)
				done = true
			}
			group = t
		} else if group == "[Default Applications]" && strings.HasPrefix(t, mime+"=") {
			if !done {
				out = append(out, entry)
				done = true
			}
			continue
		}
		out = append(out, l)
	}
	if !done {
		if group != "[Default Applications]" {
			out = append(out, "[Default Applications]")
		}
		out = append(out, entry)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(strings.Join(out, "\n")+"\n"), 0o644)
}

// Uninstall stops the agent, removes its login entry and link handler, and deletes the copy Install made.
func Uninstall(self string) ([]string, error) {
	exe, _, err := Location()
	if err != nil {
		return nil, err
	}
	if err := autostart.Uninstall(); err != nil {
		return nil, err
	}
	stopRunning(exe)
	var notes []string
	apps := filepath.Join(dataHome(), "applications")
	if err := os.Remove(filepath.Join(apps, desktopName)); err == nil {
		if path, err := exec.LookPath("update-desktop-database"); err == nil {
			_ = exec.Command(path, apps).Run()
		}
	}
	if err := os.Remove(exe); err == nil {
		notes = append(notes, "Removed "+exe)
	} else if !os.IsNotExist(err) {
		return notes, err
	}
	if packaged(self) {
		notes = append(notes, "The package manager installed "+self+"; remove the package to delete it.")
	}
	return notes, nil
}

// Describe lists what Install registers, for diagnostics.
func Describe() []string {
	return []string{autostart.Describe(), "link handler " + filepath.Join(dataHome(), "applications", desktopName)}
}
