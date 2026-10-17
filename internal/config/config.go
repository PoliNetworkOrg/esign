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
	// PKCS11Module overrides the discovered CIE middleware module.
	PKCS11Module string `json:"pkcs11Module,omitempty"`
	// Providers enables providers in order of preference: "cie" (direct PC/SC), "pkcs11" (CIE middleware), "soft".
	Providers []string `json:"providers,omitempty"`
}

// Dir is the agent's per-user configuration directory.
func Dir() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "PoliNetwork Sign Agent"), nil
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
	if len(c.Providers) == 0 {
		c.Providers = []string{"cie", "pkcs11"}
	}
	return c, nil
}
