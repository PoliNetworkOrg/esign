// Package config reads the agent's settings from its JSON file and the platform defaults.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// DefaultPort is the loopback port the dashboard looks for.
const DefaultPort = 47321

// DefaultOrigins are the dashboards allowed by default.
var DefaultOrigins = []string{"https://admin.polinetwork.org"}

// DevOrigins are added with --dev: dashboards run locally on any port.
var DevOrigins = []string{"http://localhost:*", "http://127.0.0.1:*"}

// Config is the agent configuration file, `config.json` in Dir().
type Config struct {
	Port int `json:"port,omitempty"`
	// AllowedOrigins replaces DefaultOrigins when set.
	AllowedOrigins []string `json:"allowedOrigins,omitempty"`
	// PKCS11Module overrides the discovered official CIE middleware module.
	PKCS11Module string `json:"pkcs11Module,omitempty"`
	// OpenCIEModule overrides the discovered OpenCIE module.
	OpenCIEModule string `json:"openCieModule,omitempty"`
	// Providers in order of preference: "cie-mw" (official middleware), "opencie", "cie" (built-in PC/SC), "soft".
	Providers []string `json:"providers,omitempty"`
	// Worker says when PKCS#11 modules run in a child process: WorkerAuto (default), WorkerAlways or WorkerNever.
	Worker string `json:"worker,omitempty"`
}

// Worker modes. Auto uses a child process when the module needs one: another CPU architecture (the official macOS
// middleware is x86_64 only), or a different environment (the macOS App Store middleware); Always also isolates
// modules that could be loaded in-process, so a crashing middleware cannot take the agent down.
const (
	WorkerAuto   = "auto"
	WorkerAlways = "always"
	WorkerNever  = "never"
)

// Dir is the agent's per-user configuration directory. Until v0.1.x it was "PoliNetwork Sign Agent": the first call
// after an update moves that directory, with the configuration and pairing caches, here.
func Dir() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(base, "PoliNetwork eSign")
	if _, err := os.Stat(dir); errors.Is(err, os.ErrNotExist) {
		_ = os.Rename(filepath.Join(base, "PoliNetwork Sign Agent"), dir)
	}
	return dir, nil
}

// Load reads the configuration file, if any, and applies defaults.
func Load(path string) (Config, error) {
	var c Config
	data, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return c, err
	default:
		if err := json.Unmarshal(data, &c); err != nil {
			return c, fmt.Errorf("%s: %w", path, err)
		}
	}
	if c.Port == 0 {
		c.Port = DefaultPort
	}
	if len(c.AllowedOrigins) == 0 {
		c.AllowedOrigins = append([]string{}, DefaultOrigins...)
	}
	switch c.Worker {
	case "":
		c.Worker = WorkerAuto
	case WorkerAuto, WorkerAlways, WorkerNever:
	default:
		return c, fmt.Errorf("%s: worker must be %q, %q or %q", path, WorkerAuto, WorkerAlways, WorkerNever)
	}
	if len(c.Providers) == 0 {
		c.Providers = []string{"cie-mw", "opencie", "cie"}
	}
	return c, nil
}
