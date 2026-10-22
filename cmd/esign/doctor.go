package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/PoliNetworkOrg/esign/internal/autostart"
	"github.com/PoliNetworkOrg/esign/internal/config"
	"github.com/PoliNetworkOrg/esign/internal/install"
	"github.com/PoliNetworkOrg/esign/internal/launch"
	"github.com/PoliNetworkOrg/esign/internal/token"
	"github.com/PoliNetworkOrg/esign/internal/token/worker"
)

// providerNames name each provider as users know it, so the report names the app to install.
var providerNames = map[string]string{
	"cie-mw":  "CIE ID",
	"opencie": "OpenCIE",
	"cie":     "built in",
	"soft":    "development key",
}

// doctor prints what support needs to know: the build, installation, configuration, running agent, every
// provider's module and architecture, and the readers and card each provider sees. It never asks for the PIN.
func doctor(ctx context.Context, w io.Writer, cfg config.Config, configPath, dir string, specs []providerSpec) {
	exe := executable()
	selfArchs, err := worker.Archs(exe)
	archs := strings.Join(selfArchs, "+")
	if err != nil {
		archs = "unknown: " + err.Error()
	}
	fmt.Fprintf(w, "PoliNetwork eSign %s\n", version)
	fmt.Fprintf(w, "  system:      %s/%s, %s\n", runtime.GOOS, runtime.GOARCH, osVersion())
	fmt.Fprintf(w, "  executable:  %s (%s)\n", exe, archs)

	fmt.Fprintln(w, "\nInstallation")
	dest, app, _ := install.Location()
	fmt.Fprintf(w, "  installed:   %v (location %s)\n", install.IsInstalled(exe), firstNonEmpty(app, dest))
	if registered, ok := autostart.Installed(); ok {
		fmt.Fprintf(w, "  at login:    %s\n", registered)
	} else {
		fmt.Fprintln(w, "  at login:    not registered (run `esign install`)")
	}
	for _, d := range install.Describe() {
		fmt.Fprintf(w, "  registers:   %s\n", d)
	}

	fmt.Fprintln(w, "\nConfiguration")
	fmt.Fprintf(w, "  directory:   %s\n", dir)
	if _, err := os.Stat(configPath); err == nil {
		fmt.Fprintf(w, "  file:        %s\n", configPath)
	} else {
		fmt.Fprintf(w, "  file:        %s (absent, defaults apply)\n", configPath)
	}
	fmt.Fprintf(w, "  port:        %d\n", cfg.Port)
	fmt.Fprintf(w, "  origins:     %s\n", strings.Join(cfg.AllowedOrigins, ", "))
	fmt.Fprintf(w, "  providers:   %s\n", strings.Join(cfg.Providers, ", "))
	fmt.Fprintf(w, "  worker:      %s\n", cfg.Worker)
	if v, ok := launch.Probe(ctx, cfg.Port); ok {
		fmt.Fprintf(w, "  agent:       running on 127.0.0.1:%d, version %s\n", cfg.Port, v)
	} else if launch.PortInUse(cfg.Port) {
		fmt.Fprintf(w, "  agent:       NOT running; another program uses port %d\n", cfg.Port)
	} else {
		fmt.Fprintf(w, "  agent:       not running\n")
	}

	fmt.Fprintln(w, "\nProviders")
	for _, s := range specs {
		fmt.Fprintf(w, "  %s (%s)\n", s.Name, providerNames[s.Name])
		switch {
		case s.Module != "":
			marchs := strings.Join(s.Archs, "+")
			if s.ArchsErr != nil {
				marchs = "unreadable: " + s.ArchsErr.Error()
			}
			fmt.Fprintf(w, "    module:    %s (%s)\n", s.Module, marchs)
			if s.PlanErr != nil {
				fmt.Fprintf(w, "    loading:   impossible: %v\n", s.PlanErr)
			} else {
				fmt.Fprintf(w, "    loading:   %s\n", s.Plan)
			}
			if s.Home != "" {
				fmt.Fprintf(w, "    HOME:      %s (for the middleware's pairing cache)\n", s.Home)
			}
		case len(s.Candidates) > 0:
			fmt.Fprintln(w, "    module:    not found; searched:")
			for _, c := range s.Candidates {
				fmt.Fprintf(w, "               %s\n", c)
			}
		}
		sctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		st, err := token.SafeStatus(sctx, s.Provider)
		cancel()
		fmt.Fprintf(w, "    available: %v\n", st.Available)
		if st.Detail != "" {
			fmt.Fprintf(w, "    detail:    %s\n", st.Detail)
		}
		if err != nil {
			fmt.Fprintf(w, "    error:     %v\n", err)
		}
		if st.Available && len(st.Readers) == 0 {
			fmt.Fprintln(w, "    readers:   none")
		}
		for _, r := range st.Readers {
			fmt.Fprintf(w, "    reader:    %s\n", r)
		}
		if st.CardPresent != nil {
			fmt.Fprintf(w, "    card:      %v\n", *st.CardPresent)
		}
	}

	if notes := systemNotes(); len(notes) > 0 {
		fmt.Fprintln(w, "\nSystem")
		for _, n := range notes {
			fmt.Fprintf(w, "  %s\n", n)
		}
	}
}
