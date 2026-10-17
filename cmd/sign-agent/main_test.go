package main

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/PoliNetworkOrg/sign-agent/internal/install"
	"github.com/PoliNetworkOrg/sign-agent/internal/launch"
	"github.com/PoliNetworkOrg/sign-agent/internal/token"
	"github.com/PoliNetworkOrg/sign-agent/internal/token/soft"
	"github.com/PoliNetworkOrg/sign-agent/internal/token/worker"
)

const mainEnv = "SIGN_AGENT_TEST_MAIN"

// TestMain lets the test binary run as the sign-agent command: tests start it again with mainEnv set.
func TestMain(m *testing.M) {
	if os.Getenv(mainEnv) == "1" {
		main()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// agent runs the command with args in an isolated home directory.
func agent(t *testing.T, home string, args ...string) *exec.Cmd {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, args...)
	cmd.Env = append(os.Environ(), mainEnv+"=1", "HOME="+home, "XDG_CONFIG_HOME="+filepath.Join(home, ".config"), "APPDATA="+filepath.Join(home, "AppData"), "LOCALAPPDATA="+filepath.Join(home, "Local"))
	return cmd
}

func TestWorkerCommandWithSoftToken(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	p := worker.New(worker.Options{
		Name:    "soft",
		Command: worker.Command(worker.Plan{Worker: true}, exe, "worker", "--provider", "soft", "--soft-dir", filepath.Join(dir, "soft")),
		Env:     append(os.Environ(), mainEnv+"=1"),
	})
	defer p.Close()
	ctx := t.Context()
	if st := p.Status(ctx); !st.Available {
		t.Fatalf("status: %+v", st)
	}
	if _, err := p.Open(ctx, "87654321"); token.CodeOf(err) != token.CodePinIncorrect {
		t.Fatalf("wrong PIN: %v", err)
	}
	s, err := p.Open(ctx, soft.DefaultPIN)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	digest := sha256.Sum256([]byte("attributes"))
	sig, err := s.SignDigest(ctx, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	if err := rsa.VerifyPKCS1v15(s.Certificate().PublicKey.(*rsa.PublicKey), crypto.SHA256, digest[:], sig); err != nil {
		t.Fatal(err)
	}
	// The worker created the token where it was told to.
	if _, err := os.Stat(filepath.Join(dir, "soft", "cert.pem")); err != nil {
		t.Fatal(err)
	}
}

// TestWorkerWithPKCS11Module signs with a real PKCS#11 module loaded by the worker: set SIGN_AGENT_TEST_PKCS11 and
// SIGN_AGENT_TEST_PIN as for the p11 tests (scripts/softhsm-tests.sh does).
func TestWorkerWithPKCS11Module(t *testing.T) {
	module, pin := os.Getenv("SIGN_AGENT_TEST_PKCS11"), os.Getenv("SIGN_AGENT_TEST_PIN")
	if module == "" || pin == "" {
		t.Skip("SIGN_AGENT_TEST_PKCS11 and SIGN_AGENT_TEST_PIN are not set")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	// opencie passes the 8-digit PIN unchanged, like SoftHSM expects it.
	p := worker.New(worker.Options{
		Name:    "opencie",
		Command: []string{exe, "worker", "--provider", "opencie", "--module", module},
		Env:     append(os.Environ(), mainEnv+"=1"),
	})
	defer p.Close()
	ctx := t.Context()
	if st := p.Status(ctx); !st.Available || st.CardPresent == nil || !*st.CardPresent {
		t.Fatalf("status: %+v", st)
	}
	if _, err := p.Open(ctx, "99999999"); token.CodeOf(err) != token.CodePinIncorrect {
		t.Fatalf("wrong PIN: %v", err)
	}
	s, err := p.Open(ctx, pin)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	digest := sha256.Sum256([]byte("attributes"))
	sig, err := s.SignDigest(ctx, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	if err := rsa.VerifyPKCS1v15(s.Certificate().PublicKey.(*rsa.PublicKey), crypto.SHA256, digest[:], sig); err != nil {
		t.Fatal(err)
	}
}

func TestOpenURLIgnoresOtherLinks(t *testing.T) {
	home := t.TempDir()
	for _, args := range [][]string{
		{"open-url", "polinetwork-sign://open/../install"},
		{"open-url", "polinetwork-sign://open?pkcs11=/tmp/evil.so"},
		{"open-url", "polinetwork-sign://open", "--pkcs11", "/tmp/evil.so"},
		{"open-url"},
	} {
		var stderr bytes.Buffer
		cmd := agent(t, home, args...)
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			t.Errorf("%v: %v", args, err)
		}
		if !strings.Contains(stderr.String(), "ignoring the link") {
			t.Errorf("%v: %s", args, stderr.String())
		}
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func TestServeAndSecondInstance(t *testing.T) {
	home := t.TempDir()
	port := freePort(t)
	cfg := filepath.Join(home, "config.json")
	data, _ := json.Marshal(map[string]any{"port": port, "providers": []string{"soft"}})
	if err := os.WriteFile(cfg, data, 0o600); err != nil {
		t.Fatal(err)
	}
	first := agent(t, home, "serve", "--config", cfg)
	if err := first.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = first.Process.Kill()
		_ = first.Wait()
	})
	if !launch.WaitRunning(t.Context(), port, 15*time.Second) {
		t.Fatal("the agent did not start")
	}
	// A second agent finds the first and exits successfully, as the link handler does.
	second := agent(t, home, "serve", "--config", cfg)
	done := make(chan error, 1)
	go func() { done <- second.Run() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("second agent: %v", err)
		}
	case <-time.After(15 * time.Second):
		_ = second.Process.Kill()
		t.Fatal("second agent kept running")
	}
}

func TestSoftwareCIEHome(t *testing.T) {
	tests := []struct{ home, want string }{
		{"/Users/rossi/Library/Containers/it.ipzs.SoftwareCIE/Data", "/Users/rossi/Library"},
		{"/Users/rossi/Library/Application Support/PoliNetwork Sign Agent/cie-mw-home", "/Users/rossi/Library"},
		{"/Users/rossi", "/Users/rossi"},
	}
	for _, tt := range tests {
		if got := cardDirPrefix(tt.home); got != tt.want {
			t.Errorf("cardDirPrefix(%q) = %q, want %q", tt.home, got, tt.want)
		}
	}
	h, err := softwareCIEHome("/Users/rossi", "/Users/rossi/Library/Application Support/PoliNetwork Sign Agent")
	if err != nil || h != "/Users/rossi/Library/Application Support/PoliNetwork Sign Agent/cie-mw-home" {
		t.Errorf("softwareCIEHome: %q, %v", h, err)
	}
	// A data directory elsewhere falls back to the sandbox HOME the app itself has.
	h, err = softwareCIEHome("/Users/rossi", "/opt/data")
	if err != nil || h != "/Users/rossi/Library/Containers/it.ipzs.SoftwareCIE/Data" {
		t.Errorf("softwareCIEHome fallback: %q, %v", h, err)
	}
	if _, err := softwareCIEHome("/Volumes/Home/rossi", "/Volumes/Home/rossi/Library/Application Support/X"); err == nil {
		t.Error("a home the middleware cannot handle was accepted")
	}
	if !isSoftwareCIE("/Applications/CIE ID.app/Contents/Resources/libcie-pkcs11.dylib") ||
		!isSoftwareCIE("/Users/rossi/Library/Group Containers/group.it.ipzs.SoftwareCIE/Library/Caches/libcie-pkcs11.dylib") ||
		isSoftwareCIE("/usr/local/lib/libcie-pkcs11.dylib") {
		t.Error("isSoftwareCIE")
	}
}

func TestBundleCommand(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS app bundles")
	}
	home := t.TempDir()
	app := filepath.Join(home, install.AppName)
	if out, err := agent(t, home, "bundle", "--out", app).CombinedOutput(); err != nil {
		t.Fatalf("bundle: %v: %s", err, out)
	}
	if out, err := exec.Command("/usr/bin/plutil", "-lint", filepath.Join(app, "Contents", "Info.plist")).CombinedOutput(); err != nil {
		t.Fatalf("plutil: %v: %s", err, out)
	}
	if bundle, ok := install.BundleOf(filepath.Join(app, "Contents", "MacOS", install.BundleExec)); !ok || bundle != app {
		t.Fatalf("BundleOf: %q %v", bundle, ok)
	}
}
