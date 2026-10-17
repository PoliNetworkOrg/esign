package autostart

import (
	"fmt"
	"strings"
)

// systemdQuote quotes an argument for a unit's ExecStart.
func systemdQuote(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`, "%", "%%").Replace(s) + `"`
}

// DesktopQuote quotes an argument for a desktop entry's Exec key: the Exec quoting rules, then the escaping of
// string values (a literal backslash becomes four).
func DesktopQuote(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\\\`, `"`, `\"`, "`", "\\`", "$", `\$`, "%", "%%").Replace(s) + `"`
}

// SystemdUnit is the user service running exe.
func SystemdUnit(exe string) string {
	return fmt.Sprintf(`[Unit]
Description=PoliNetwork eSign (CIE signing for the PoliNetwork dashboard)
After=graphical-session.target pcscd.socket

[Service]
ExecStart=%s serve
Restart=on-failure
RestartSec=3

[Install]
WantedBy=default.target
`, systemdQuote(exe))
}
