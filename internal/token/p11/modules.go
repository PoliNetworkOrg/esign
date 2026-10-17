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
		return []string{
			filepath.Join(root, "System32", "ciepki.dll"),
			filepath.Join(os.Getenv("ProgramFiles"), "CIEPKI", "ciepki.dll"),
		}
	case "darwin":
		return []string{
			"/usr/local/lib/libcie-pkcs11.dylib",
			"/Library/Application Support/CIEID/libcie-pkcs11.dylib",
			"/Applications/CIE ID.app/Contents/Frameworks/libcie-pkcs11.dylib",
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
