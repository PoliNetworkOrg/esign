// Command sign-agent lets the PoliNetwork dashboard sign documents with the Italian CIE on this computer.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/PoliNetworkOrg/sign-agent/internal/autostart"
	"github.com/PoliNetworkOrg/sign-agent/internal/config"
	"github.com/PoliNetworkOrg/sign-agent/internal/server"
	"github.com/PoliNetworkOrg/sign-agent/internal/token"
	"github.com/PoliNetworkOrg/sign-agent/internal/token/cie"
	"github.com/PoliNetworkOrg/sign-agent/internal/token/p11"
	"github.com/PoliNetworkOrg/sign-agent/internal/token/soft"
)

// version is set at build time with -ldflags "-X main.version=…".
var version = "dev"

const usage = `PoliNetwork Sign Agent %s

Lets the PoliNetwork dashboard sign PDFs with your CIE (Carta d'Identità Elettronica).

Usage:
  sign-agent [serve] [flags]   run the agent (default)
  sign-agent status [flags]    show readers, cards and certificates, then exit
  sign-agent install           start the agent automatically when you log in
  sign-agent uninstall         stop starting the agent automatically
  sign-agent version           print the version

Flags:
`

func main() {
	args := os.Args[1:]
	cmd := "serve"
	if len(args) > 0 && args[0] != "" && args[0][0] != '-' {
		cmd, args = args[0], args[1:]
	}

	fs := flag.NewFlagSet("sign-agent", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), usage, version)
		fs.PrintDefaults()
	}
	dir, err := config.Dir()
	if err != nil {
		fatal(err)
	}
	configPath := fs.String("config", filepath.Join(dir, "config.json"), "configuration file")
	port := fs.Int("port", 0, "loopback port (default 47321)")
	dev := fs.Bool("dev", false, "also allow dashboards on http://localhost:<any port>")
	useSoft := fs.Bool("soft", false, "add a software development token (PIN "+soft.DefaultPIN+"); its signatures are not valid")
	module := fs.String("pkcs11", "", "PKCS#11 module to use instead of the CIE middleware (implies --providers cie-mw)")
	verbose := fs.Bool("v", false, "verbose logging")
	_ = fs.Parse(args)

	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(logger)

	switch cmd {
	case "version":
		fmt.Println(version)
		return
	case "install":
		exe, err := os.Executable()
		if err != nil {
			fatal(err)
		}
		if err := autostart.Install(exe); err != nil {
			fatal(err)
		}
		fmt.Println("The agent now starts when you log in. It is running in the background.")
		return
	case "uninstall":
		if err := autostart.Uninstall(); err != nil {
			fatal(err)
		}
		fmt.Println("The agent no longer starts when you log in.")
		return
	case "serve", "status":
	default:
		fs.Usage()
		os.Exit(2)
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fatal(err)
	}
	if *port != 0 {
		cfg.Port = *port
	}
	if *module != "" {
		cfg.PKCS11Module = *module
		cfg.Providers = []string{"cie-mw"}
	}
	if *dev {
		cfg.AllowedOrigins = append(cfg.AllowedOrigins, config.DevOrigins...)
	}

	providers, err := buildProviders(cfg, dir, *useSoft)
	if err != nil {
		fatal(err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if cmd == "status" {
		printStatus(ctx, providers)
		return
	}

	srv := server.New(server.Options{
		Port:           cfg.Port,
		AllowedOrigins: cfg.AllowedOrigins,
		Providers:      providers,
		Version:        version,
		Logger:         logger,
	})
	logger.Info("PoliNetwork Sign Agent listening", "address", fmt.Sprintf("http://127.0.0.1:%d", cfg.Port), "origins", cfg.AllowedOrigins, "version", version)
	if err := srv.ListenAndServe(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fatal(fmt.Errorf("%w (is another agent already running?)", err))
	}
}

func buildProviders(cfg config.Config, dir string, useSoft bool) ([]token.Provider, error) {
	var providers []token.Provider
	for _, name := range cfg.Providers {
		switch name {
		case "cie-mw":
			providers = append(providers, p11.New(p11.Options{
				Name:       "cie-mw",
				Path:       cfg.PKCS11Module,
				Candidates: p11.CIEModules(),
				PIN:        p11.LastFour,
				PINLength:  8,
			}))
		case "opencie":
			providers = append(providers, p11.New(p11.Options{
				Name:       "opencie",
				Path:       cfg.OpenCIEModule,
				Candidates: p11.OpenCIEModules(dir),
				PINLength:  8,
			}))
		case "cie":
			providers = append(providers, cie.New())
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
		providers = append(providers, p)
	}
	return providers, nil
}

func printStatus(ctx context.Context, providers []token.Provider) {
	for _, p := range providers {
		st := p.Status(ctx)
		fmt.Printf("%s: available=%v %s\n", st.Provider, st.Available, st.Detail)
		for _, r := range st.Readers {
			fmt.Printf("  reader: %s\n", r)
		}
		if st.CardPresent != nil {
			fmt.Printf("  card present: %v\n", *st.CardPresent)
		}
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "sign-agent:", err)
	os.Exit(1)
}
