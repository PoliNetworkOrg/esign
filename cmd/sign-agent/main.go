// Command sign-agent lets the PoliNetwork dashboard sign documents with the Italian CIE on this computer.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/PoliNetworkOrg/sign-agent/internal/autostart"
	"github.com/PoliNetworkOrg/sign-agent/internal/config"
	"github.com/PoliNetworkOrg/sign-agent/internal/install"
	"github.com/PoliNetworkOrg/sign-agent/internal/launch"
	"github.com/PoliNetworkOrg/sign-agent/internal/macapp"
	"github.com/PoliNetworkOrg/sign-agent/internal/server"
	"github.com/PoliNetworkOrg/sign-agent/internal/token/soft"
)

// version is set at build time with -ldflags "-X main.version=…".
var version = "dev"

const usage = `PoliNetwork Sign Agent %s

Lets the PoliNetwork dashboard sign PDFs with your CIE (Carta d'Identità Elettronica).

Usage:
  sign-agent [serve] [flags]   run the agent (default)
  sign-agent install           install for this user: copy the agent to a stable place, start it at login,
                               and let the dashboard start it with polinetwork-sign:// links
  sign-agent uninstall         undo install
  sign-agent status [flags]    show readers, cards and certificates, then exit
  sign-agent doctor [flags]    print a diagnostic report for support
  sign-agent version           print the version

Flags:
`

func main() {
	args := os.Args[1:]
	// macOS before 10.9 passed a process serial number to apps started by Launch Services.
	if len(args) == 1 && strings.HasPrefix(args[0], "-psn_") {
		args = nil
	}
	if len(args) == 0 && openedAsApp() {
		os.Exit(runApp())
	}
	cmd := "serve"
	if len(args) > 0 && args[0] != "" && args[0][0] != '-' {
		cmd, args = args[0], args[1:]
	}

	switch cmd {
	case "worker":
		// Talks to the agent on stdin and stdout; reads no configuration.
		if err := runWorker(args); err != nil {
			fatal(err)
		}
		return
	case install.URLHandlerArg:
		// Started by the browser: only ever looks at its single argument.
		var url string
		if len(args) == 1 {
			url = args[0]
		}
		os.Exit(handleURL(url))
	}

	hasConsole := attachConsole()

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
	out := fs.String("out", "", "bundle: the app bundle to create")
	verbose := fs.Bool("v", false, "verbose logging")
	_ = fs.Parse(args)

	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}
	var logOut io.Writer = os.Stderr
	if cmd == "serve" && !hasConsole {
		logOut = serviceLog(dir)
	}
	logger := slog.New(slog.NewTextHandler(logOut, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(logger)

	switch cmd {
	case "version":
		fmt.Println(version)
		return
	case "install":
		exe := executable()
		res, err := install.Install(exe, version)
		if err != nil {
			fatal(err)
		}
		fmt.Printf("Installed %s.\n", firstNonEmpty(res.App, res.Exe))
		fmt.Println("The agent starts when you log in and is running now; the dashboard can start it with polinetwork-sign://open links.")
		return
	case "uninstall":
		notes, err := install.Uninstall(executable())
		if err != nil {
			fatal(err)
		}
		msg := strings.Join(append(notes, "The agent no longer starts when you log in."), "\n")
		if runtime.GOOS == "windows" && !hasConsole {
			launch.Message(msg, false)
		}
		fmt.Println(msg)
		return
	case "bundle":
		if *out == "" {
			fatal(errors.New("bundle needs --out <name>.app"))
		}
		if err := install.MakeBundle(executable(), *out, version); err != nil {
			fatal(err)
		}
		return
	case "serve", "status", "doctor":
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

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if cmd == "serve" {
		// Started at login, by a link or by hand while another agent runs: one is enough.
		if v, ok := launch.Probe(ctx, cfg.Port); ok {
			logger.Info("another agent is already running", "port", cfg.Port, "version", v)
			return
		}
	}

	specs, err := buildProviders(cfg, dir, *useSoft)
	if err != nil {
		fatal(err)
	}
	defer closeProviders(specs)

	switch cmd {
	case "status":
		printStatus(ctx, specs)
		return
	case "doctor":
		doctor(ctx, os.Stdout, cfg, *configPath, dir, specs)
		return
	}

	srv := server.New(server.Options{
		Port:           cfg.Port,
		AllowedOrigins: cfg.AllowedOrigins,
		Providers:      providersOf(specs),
		Version:        version,
		Logger:         logger,
	})
	logger.Info("PoliNetwork Sign Agent listening", "address", fmt.Sprintf("http://127.0.0.1:%d", cfg.Port), "origins", cfg.AllowedOrigins, "version", version)
	if err := srv.ListenAndServe(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		if _, ok := launch.Probe(context.Background(), cfg.Port); ok {
			logger.Info("another agent is already running", "port", cfg.Port)
			return
		}
		closeProviders(specs)
		fatal(fmt.Errorf("%w (is another program using port %d?)", err, cfg.Port))
	}
}

// runApp handles a launch without arguments from the desktop: opening the app (or double-clicking the Windows
// executable) installs it when needed, makes sure the agent runs and shows its page; a polinetwork-sign:// link only
// makes sure the agent runs.
func runApp() int {
	how := macapp.Wait(2 * time.Second)
	if how.URL != "" {
		return handleURL(how.URL)
	}
	port := configuredPort()
	exe := executable()
	if !install.IsInstalled(exe) {
		res, err := install.Install(exe, version)
		if err != nil {
			launch.Message("The agent could not be installed: "+err.Error(), true)
			return 1
		}
		exe = res.Exe
	}
	ctx := context.Background()
	if err := launch.EnsureRunning(ctx, port, exe, autostart.Start); err != nil {
		launch.Message("The agent could not start: "+err.Error(), true)
		return 1
	}
	if err := launch.OpenBrowser(fmt.Sprintf("http://127.0.0.1:%d/", port)); err != nil {
		fmt.Fprintln(os.Stderr, "sign-agent:", err)
	}
	return 0
}

// handleURL starts the agent for a polinetwork-sign:// link. Anything but launch.OpenURL is ignored: a link cannot
// pass arguments to the agent.
func handleURL(url string) int {
	if !launch.ValidURL(url) {
		fmt.Fprintf(os.Stderr, "sign-agent: ignoring the link %q: only %s is accepted\n", url, launch.OpenURL)
		return 0
	}
	if err := launch.EnsureRunning(context.Background(), configuredPort(), executable(), autostart.Start); err != nil {
		fmt.Fprintln(os.Stderr, "sign-agent:", err)
		return 1
	}
	return 0
}

// configuredPort reads the port from the default configuration file.
func configuredPort() int {
	dir, err := config.Dir()
	if err != nil {
		return config.DefaultPort
	}
	cfg, err := config.Load(filepath.Join(dir, "config.json"))
	if err != nil {
		return config.DefaultPort
	}
	return cfg.Port
}

func executable() string {
	exe, err := os.Executable()
	if err != nil {
		fatal(err)
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	return exe
}

func printStatus(ctx context.Context, specs []providerSpec) {
	for _, s := range specs {
		st := s.Provider.Status(ctx)
		fmt.Printf("%s: available=%v %s\n", st.Provider, st.Available, st.Detail)
		for _, r := range st.Readers {
			fmt.Printf("  reader: %s\n", r)
		}
		if st.CardPresent != nil {
			fmt.Printf("  card present: %v\n", *st.CardPresent)
		}
	}
}

func firstNonEmpty(s ...string) string {
	for _, v := range s {
		if v != "" {
			return v
		}
	}
	return ""
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "sign-agent:", err)
	os.Exit(1)
}
