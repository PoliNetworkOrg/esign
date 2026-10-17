package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/PoliNetworkOrg/sign-agent/internal/config"
	"github.com/PoliNetworkOrg/sign-agent/internal/token"
	"github.com/PoliNetworkOrg/sign-agent/internal/token/cie"
	"github.com/PoliNetworkOrg/sign-agent/internal/token/p11"
	"github.com/PoliNetworkOrg/sign-agent/internal/token/soft"
	"github.com/PoliNetworkOrg/sign-agent/internal/token/worker"
)

// providerSpec is a configured provider and how it is loaded, for the server and for `doctor`.
type providerSpec struct {
	Name string
	// Module is the PKCS#11 module in use, "" when none was found; Candidates were searched.
	Module     string
	Candidates []string
	// Archs are the module's CPU architectures, when it could be read.
	Archs    []string
	ArchsErr error
	// Plan says whether the module runs in a worker; PlanErr why it cannot be loaded at all.
	Plan    worker.Plan
	PlanErr error
	// Home is the HOME given to the worker, when it differs from the agent's.
	Home     string
	Provider token.Provider
}

// p11Options are the PKCS#11 settings of a provider, shared by the agent and its workers.
func p11Options(name, path string) p11.Options {
	switch name {
	case "cie-mw":
		// The middleware caches the PIN's first four digits when the card is paired, and takes the last four.
		return p11.Options{Name: name, Path: path, PIN: p11.LastFour, PINLength: 8}
	default:
		return p11.Options{Name: name, Path: path, PINLength: 8}
	}
}

// cieModules are the official middleware's locations: on macOS, the "Software CIE" app bundle is read first because,
// unlike the copy in the app's group container, it is not protected by the system's "data from other apps" consent.
func cieModules() []string {
	var out []string
	if runtime.GOOS == "darwin" {
		const inBundle = "CIE ID.app/Contents/Resources/libcie-pkcs11.dylib"
		out = append(out, filepath.Join("/Applications", inBundle))
		if home, err := os.UserHomeDir(); err == nil {
			out = append(out, filepath.Join(home, "Applications", inBundle))
		}
	}
	return append(out, p11.CIEModules()...)
}

func firstExisting(paths []string) string {
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// isSoftwareCIE reports whether module belongs to the Mac App Store "Software CIE" app, which expects a sandbox HOME.
func isSoftwareCIE(module string) bool {
	return strings.Contains(module, "/CIE ID.app/") || strings.Contains(module, "group.it.ipzs.SoftwareCIE")
}

// cardDirPrefix is what the macOS middleware's GetCardDir() (cie-pkcs11/Util/CacheLib.cpp) keeps of HOME before
// appending "/Group Containers/group.it.ipzs.SoftwareCIE/Library/Caches/CIEPKI/": everything before its fourth "/".
func cardDirPrefix(home string) string {
	n := 0
	for i, r := range home {
		if r == '/' {
			if n == 3 {
				return home[:i]
			}
			n++
		}
	}
	return home
}

// softwareCIEHome returns a HOME with which the App Store middleware finds the pairing cache that the Software CIE app
// wrote. The middleware expects the app's sandbox HOME, /Users/<user>/Library/Containers/it.ipzs.SoftwareCIE/Data,
// and only keeps "/Users/<user>/Library" of it; an unsandboxed process has HOME=/Users/<user> and would look in
// /Users/<user>/Group Containers. Any directory below ~/Library works, so the agent uses one of its own: the middleware
// also writes logs and reads settings in $HOME/.CIEPKI, which stay out of the app's container.
func softwareCIEHome(home, dataDir string) (string, error) {
	want := filepath.Join(home, "Library")
	for _, c := range []string{
		filepath.Join(dataDir, "cie-mw-home"),
		filepath.Join(home, "Library", "Containers", "it.ipzs.SoftwareCIE", "Data"),
	} {
		if cardDirPrefix(c) == want {
			return c, nil
		}
	}
	return "", fmt.Errorf("the CIE middleware cannot find its pairing cache with the home directory %s (it expects /Users/<name>)", home)
}

func withEnv(env []string, key, value string) []string {
	out := make([]string, 0, len(env)+1)
	for _, kv := range env {
		if !strings.HasPrefix(kv, key+"=") {
			out = append(out, kv)
		}
	}
	return append(out, key+"="+value)
}

// unavailable is a provider that cannot be loaded on this computer, with the reason.
type unavailable struct{ name, detail string }

func (u unavailable) Name() string { return u.name }
func (u unavailable) Status(context.Context) token.Status {
	return token.Status{Provider: u.name, Detail: u.detail}
}
func (u unavailable) Open(context.Context, string) (token.Session, error) {
	return nil, token.Errorf(token.CodeMiddlewareMissing, "%s", u.detail)
}

// pkcs11Spec resolves a PKCS#11 provider and decides whether it runs in-process or in a worker.
func pkcs11Spec(cfg config.Config, dir, name, override string, candidates []string) providerSpec {
	spec := providerSpec{Name: name, Candidates: candidates, Module: override}
	if spec.Module == "" {
		spec.Module = firstExisting(candidates)
	}
	if spec.Module == "" {
		spec.Provider = p11.New(p11Options(name, ""))
		return spec
	}
	exe, err := os.Executable()
	if err != nil {
		spec.PlanErr = err
		spec.Provider = unavailable{name, err.Error()}
		return spec
	}
	selfArchs, _ := worker.Archs(exe)
	spec.Archs, spec.ArchsErr = worker.Archs(spec.Module)

	env := os.Environ()
	needsEnv := false
	if runtime.GOOS == "darwin" && name == "cie-mw" && isSoftwareCIE(spec.Module) {
		home, _ := os.UserHomeDir()
		if h, err := softwareCIEHome(home, dir); err == nil {
			spec.Home, env, needsEnv = h, withEnv(env, "HOME", h), true
		}
	}

	assumed := spec.ArchsErr != nil
	switch {
	case assumed && needsEnv:
		// macOS can refuse to let the agent read Software CIE's group container until the user allows it: the
		// published module is x86_64 only.
		spec.Archs = []string{"amd64"}
	case assumed:
		// Unreadable here, so unloadable too: let the provider report why.
		spec.Archs = []string{runtime.GOARCH}
	}
	spec.Plan, spec.PlanErr = worker.Choose(runtime.GOOS, runtime.GOARCH, spec.Archs, selfArchs, cfg.Worker == config.WorkerAlways || needsEnv)
	if assumed {
		spec.Archs = nil
	}
	if spec.PlanErr == nil && cfg.Worker == config.WorkerNever && spec.Plan.Worker {
		if spec.Plan.Arch != "" {
			spec.PlanErr = fmt.Errorf("the module is %s only and the configuration disables workers", strings.Join(spec.Archs, "+"))
		} else {
			spec.Plan, spec.Home = worker.Plan{}, ""
		}
	}
	switch {
	case spec.PlanErr != nil:
		spec.Provider = unavailable{name, fmt.Sprintf("%s: %v", spec.Module, spec.PlanErr)}
	case spec.Plan.Worker:
		spec.Provider = worker.New(worker.Options{
			Name:    name,
			Command: worker.Command(spec.Plan, exe, "worker", "--provider", name, "--module", spec.Module),
			Env:     env,
			Note:    spec.Plan.String(),
			Prepare: func() error {
				if spec.Home == "" {
					return nil
				}
				// The middleware creates $HOME/.CIEPKI, but not HOME itself.
				return os.MkdirAll(spec.Home, 0o700)
			},
		})
	default:
		spec.Provider = p11.New(p11Options(name, spec.Module))
	}
	return spec
}

func buildProviders(cfg config.Config, dir string, useSoft bool) ([]providerSpec, error) {
	var specs []providerSpec
	for _, name := range cfg.Providers {
		switch name {
		case "cie-mw":
			specs = append(specs, pkcs11Spec(cfg, dir, name, cfg.PKCS11Module, cieModules()))
		case "opencie":
			specs = append(specs, pkcs11Spec(cfg, dir, name, cfg.OpenCIEModule, p11.OpenCIEModules(dir)))
		case "cie":
			specs = append(specs, providerSpec{Name: name, Provider: cie.New()})
		case "soft":
			useSoft = true
		default:
			return nil, fmt.Errorf("unknown provider %q", name)
		}
	}
	if useSoft {
		p, err := soft.Open(filepath.Join(dir, "soft-token"), "")
		if err != nil {
			return nil, err
		}
		specs = append(specs, providerSpec{Name: "soft", Provider: p})
	}
	return specs, nil
}

func providersOf(specs []providerSpec) []token.Provider {
	out := make([]token.Provider, len(specs))
	for i, s := range specs {
		out[i] = s.Provider
	}
	return out
}

func closeProviders(specs []providerSpec) {
	for _, s := range specs {
		if c, ok := s.Provider.(interface{ Close() }); ok {
			c.Close()
		}
	}
}

// runWorker is `sign-agent worker`: it serves one provider to the agent over stdin and stdout.
func runWorker(args []string) error {
	fs := flag.NewFlagSet("worker", flag.ContinueOnError)
	name := fs.String("provider", "", "provider: cie-mw, opencie or soft")
	module := fs.String("module", "", "PKCS#11 module")
	softDir := fs.String("soft-dir", "", "software token directory (in memory when empty)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	return worker.Main(func() (token.Provider, error) {
		switch *name {
		case "cie-mw", "opencie":
			if *module == "" {
				return nil, fmt.Errorf("--module is required")
			}
			return p11.New(p11Options(*name, *module)), nil
		case "soft":
			if *softDir == "" {
				return soft.New(soft.DefaultPIN)
			}
			return soft.Open(*softDir, "")
		}
		return nil, fmt.Errorf("unknown provider %q", *name)
	})
}
