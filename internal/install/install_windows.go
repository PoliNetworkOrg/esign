package install

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/PoliNetworkOrg/sign-agent/internal/autostart"
	"github.com/PoliNetworkOrg/sign-agent/internal/launch"
)

const (
	schemeKey    = `Software\Classes\` + launch.Scheme
	uninstallKey = `Software\Microsoft\Windows\CurrentVersion\Uninstall\PoliNetworkSignAgent`
)

// Location returns where Install copies the agent.
func Location() (exe, app string, err error) {
	dir := os.Getenv("LOCALAPPDATA")
	if dir == "" {
		if dir, err = os.UserCacheDir(); err != nil {
			return "", "", err
		}
	}
	return filepath.Join(dir, "PoliNetwork", "SignAgent", "sign-agent.exe"), "", nil
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

// stopRunning terminates the processes running path (the agent and its workers), other than this one.
func stopRunning(path string) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return
	}
	defer windows.CloseHandle(snap)
	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	self := uint32(os.Getpid())
	for err = windows.Process32First(snap, &pe); err == nil; err = windows.Process32Next(snap, &pe) {
		if pe.ProcessID == self || !strings.EqualFold(windows.UTF16ToString(pe.ExeFile[:]), filepath.Base(path)) {
			continue
		}
		h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_TERMINATE|windows.SYNCHRONIZE, false, pe.ProcessID)
		if err != nil {
			continue
		}
		buf := make([]uint16, windows.MAX_LONG_PATH)
		n := uint32(len(buf))
		if windows.QueryFullProcessImageName(h, 0, &buf[0], &n) == nil && strings.EqualFold(windows.UTF16ToString(buf[:n]), path) {
			if windows.TerminateProcess(h, 0) == nil {
				_, _ = windows.WaitForSingleObject(h, 5000)
			}
		}
		windows.CloseHandle(h)
	}
}

func setValues(path string, values map[string]any) error {
	k, _, err := registry.CreateKey(registry.CURRENT_USER, path, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	for name, v := range values {
		switch v := v.(type) {
		case string:
			err = k.SetStringValue(name, v)
		case uint32:
			err = k.SetDWordValue(name, v)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// deleteTree deletes a key of HKCU and its subkeys.
func deleteTree(path string) error {
	k, err := registry.OpenKey(registry.CURRENT_USER, path, registry.ENUMERATE_SUB_KEYS)
	if errors.Is(err, registry.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	names, err := k.ReadSubKeyNames(-1)
	k.Close()
	if err != nil {
		return err
	}
	for _, n := range names {
		if err := deleteTree(path + `\` + n); err != nil {
			return err
		}
	}
	if err := registry.DeleteKey(registry.CURRENT_USER, path); err != nil && !errors.Is(err, registry.ErrNotExist) {
		return err
	}
	return nil
}

// Install copies src to %LOCALAPPDATA%\PoliNetwork\SignAgent, registers the polinetwork-sign:// handler and an
// "Installed apps" entry, and starts the agent at login.
func Install(src, version string) (Result, error) {
	exe, _, err := Location()
	if err != nil {
		return Result{}, err
	}
	res := Result{Exe: exe}
	stopRunning(exe)
	if !sameFile(src, exe) {
		if err := copyFile(src, exe, 0o755); err != nil {
			return res, err
		}
	}
	quoted := `"` + exe + `"`
	if err := setValues(schemeKey, map[string]any{"": "URL:PoliNetwork Sign Agent", "URL Protocol": ""}); err != nil {
		return res, err
	}
	if err := setValues(schemeKey+`\DefaultIcon`, map[string]any{"": quoted + ",0"}); err != nil {
		return res, err
	}
	if err := setValues(schemeKey+`\shell\open\command`, map[string]any{"": quoted + " " + URLHandlerArg + ` "%1"`}); err != nil {
		return res, err
	}
	if err := setValues(uninstallKey, map[string]any{
		"DisplayName":     "PoliNetwork Sign Agent",
		"DisplayVersion":  bundleVersion(version),
		"Publisher":       "PoliNetwork APS",
		"DisplayIcon":     quoted + ",0",
		"InstallLocation": filepath.Dir(exe),
		"UninstallString": quoted + " uninstall",
		"NoModify":        uint32(1),
		"NoRepair":        uint32(1),
	}); err != nil {
		return res, err
	}
	return res, autostart.Install(exe)
}

// Uninstall stops the agent, removes its login entry, link handler and "Installed apps" entry, and deletes the
// installed copy (after this process exits, when it is that copy).
func Uninstall(self string) ([]string, error) {
	exe, _, err := Location()
	if err != nil {
		return nil, err
	}
	if err := autostart.Uninstall(); err != nil {
		return nil, err
	}
	stopRunning(exe)
	for _, k := range []string{schemeKey, uninstallKey} {
		if err := deleteTree(k); err != nil {
			return nil, err
		}
	}
	if _, err := os.Stat(exe); err != nil {
		return nil, nil
	}
	if sameFile(self, exe) {
		// A running executable cannot delete itself: a hidden shell removes it once this process has exited.
		dir := filepath.Dir(exe)
		comspec := os.Getenv("ComSpec")
		if comspec == "" {
			comspec = `C:\Windows\System32\cmd.exe`
		}
		cmd := exec.Command(comspec)
		cmd.SysProcAttr = &syscall.SysProcAttr{
			// The whole command line, program included.
			CmdLine:       `"` + comspec + `" /d /c ping -n 3 127.0.0.1 >nul & del /f /q "` + exe + `" & rmdir "` + dir + `"`,
			CreationFlags: 0x08000000 | 0x00000008, // CREATE_NO_WINDOW | DETACHED_PROCESS
			HideWindow:    true,
		}
		if err := cmd.Start(); err != nil {
			return nil, err
		}
		return []string{"Removing " + exe}, nil
	}
	if err := os.Remove(exe); err != nil {
		return nil, err
	}
	_ = os.Remove(filepath.Dir(exe))
	return []string{"Removed " + exe}, nil
}

// Describe lists what Install registers, for diagnostics.
func Describe() []string {
	return []string{autostart.Describe(), `link handler HKCU\` + schemeKey, `HKCU\` + uninstallKey}
}
