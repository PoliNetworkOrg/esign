package p11

import (
	"os"
	"path/filepath"
	"runtime"
)

// CIEModules lists where the official CIE middleware ("CIE ID") installs its PKCS#11 module on this platform.
func CIEModules() []string {
	switch runtime.GOOS {
	case "windows":
		root := os.Getenv("SystemRoot")
		if root == "" {
			root = `C:\Windows`
		}
		return []string{filepath.Join(root, "System32", "CIEPKI.dll")}
	case "darwin":
		home, _ := os.UserHomeDir()
		return []string{
			// Mac App Store "Software CIE": the app copies its module into its group container.
			filepath.Join(home, "Library", "Group Containers", "group.it.ipzs.SoftwareCIE", "Library", "Caches", "libcie-pkcs11.dylib"),
			"/Library/ipzs/libcie-pkcs11.dylib",
			"/usr/local/lib/libcie-pkcs11.dylib",
		}
	default:
		return []string{
			"/usr/local/lib/libcie-pkcs11.so",
			"/usr/lib/libcie-pkcs11.so",
			"/usr/lib/x86_64-linux-gnu/libcie-pkcs11.so",
			"/usr/lib/aarch64-linux-gnu/libcie-pkcs11.so",
			"/usr/lib64/libcie-pkcs11.so",
			"/opt/CIEID/libcie-pkcs11.so",
		}
	}
}

// OpenCIEModules lists where OpenCIE's PKCS#11 module may be: next to the agent, in the agent's data directory, or
// installed system-wide.
func OpenCIEModules(dataDir string) []string {
	var names []string
	switch runtime.GOOS {
	case "windows":
		names = []string{"libopencie-pkcs11.dll"}
	case "darwin":
		names = []string{"libopencie-pkcs11.dylib"}
	default:
		names = []string{"libopencie-pkcs11.so"}
	}
	var dirs []string
	if exe, err := os.Executable(); err == nil {
		dirs = append(dirs, filepath.Dir(exe))
	}
	dirs = append(dirs, dataDir)
	switch runtime.GOOS {
	case "darwin":
		dirs = append(dirs, "/opt/homebrew/lib", "/usr/local/lib")
	case "windows":
		dirs = append(dirs, filepath.Join(os.Getenv("ProgramFiles"), "OpenCIE"))
	default:
		dirs = append(dirs, "/usr/lib", "/usr/local/lib", "/usr/lib/x86_64-linux-gnu", "/usr/lib/aarch64-linux-gnu", "/usr/lib64")
	}
	var out []string
	for _, d := range dirs {
		for _, n := range names {
			out = append(out, filepath.Join(d, n))
		}
	}
	return out
}
