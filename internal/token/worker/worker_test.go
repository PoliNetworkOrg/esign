package worker

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"os"
	"runtime"
	"slices"
	"testing"
	"time"

	"github.com/PoliNetworkOrg/esign/internal/token"
	"github.com/PoliNetworkOrg/esign/internal/token/soft"
)

const helperEnv = "ESIGN_WORKER_HELPER"

// TestMain lets the test binary act as the worker child: the parent tests run it again with helperEnv set.
func TestMain(m *testing.M) {
	mode := os.Getenv(helperEnv)
	if mode == "" {
		os.Exit(m.Run())
	}
	err := Main(func() (token.Provider, error) {
		p, err := soft.New(soft.DefaultPIN)
		if err != nil {
			return nil, err
		}
		return &helper{Provider: p, mode: mode}, nil
	})
	if err != nil {
		os.Stderr.WriteString(err.Error() + "\n")
		os.Exit(1)
	}
	os.Exit(0)
}

// helper is the soft token with misbehaviours of real middleware.
type helper struct {
	*soft.Provider
	mode string
}

func (h *helper) Status(ctx context.Context) token.Status {
	if h.mode == "noisy" {
		// Like the CIE middleware's printf: straight to file descriptor 1.
		os.NewFile(1, "fd1").WriteString("Card Dir: /somewhere\n")
	}
	return h.Provider.Status(ctx)
}

func (h *helper) Open(ctx context.Context, pin string) (token.Session, error) {
	if h.mode == "crash" {
		os.Exit(3)
	}
	s, err := h.Provider.Open(ctx, pin)
	if err != nil || h.mode != "slow" {
		return s, err
	}
	return slowSession{s}, nil
}

type slowSession struct{ token.Session }

func (s slowSession) SignDigest(ctx context.Context, digest []byte) ([]byte, error) {
	time.Sleep(time.Minute)
	return s.Session.SignDigest(ctx, digest)
}

func newHelper(t *testing.T, mode string) *Provider {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	p := New(Options{
		Name:    "soft",
		Command: []string{exe, "-test.run=^$"},
		Env:     append(os.Environ(), helperEnv+"="+mode),
		Note:    "test worker",
	})
	t.Cleanup(p.Close)
	return p
}

func TestSignThroughWorker(t *testing.T) {
	p := newHelper(t, "normal")
	ctx := t.Context()

	st := p.Status(ctx)
	if !st.Available || st.Provider != "soft" || st.CardPresent == nil || !*st.CardPresent {
		t.Fatalf("status: %+v", st)
	}
	if !bytes.HasSuffix([]byte(st.Detail), []byte("(test worker)")) {
		t.Fatalf("detail: %q", st.Detail)
	}

	_, err := p.Open(ctx, "00000000")
	var te *token.Error
	if token.CodeOf(err) != token.CodePinIncorrect || !asError(err, &te) || te.RetriesLeft != 2 {
		t.Fatalf("wrong PIN: %v", err)
	}
	if _, err := p.Open(ctx, "1234"); token.CodeOf(err) != token.CodePinInvalid {
		t.Fatalf("malformed PIN: %v", err)
	}

	s, err := p.Open(ctx, soft.DefaultPIN)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if len(s.Chain()) != 1 || s.Certificate().Subject.CommonName != "SVLPRV80A01F205X/041001234567" {
		t.Fatalf("certificate %v, chain %d", s.Certificate().Subject, len(s.Chain()))
	}
	if st := p.Status(ctx); st.Available {
		t.Fatalf("status during a session: %+v", st)
	}
	if _, err := p.Open(ctx, soft.DefaultPIN); token.CodeOf(err) != token.CodeBusy {
		t.Fatalf("second open: %v", err)
	}
	digest := sha256.Sum256([]byte("signed attributes"))
	sig, err := s.SignDigest(ctx, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := rsa.VerifyPKCS1v15(s.Certificate().PublicKey.(*rsa.PublicKey), crypto.SHA256, digest[:], sig); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if _, err := s.SignDigest(ctx, []byte("short")); token.CodeOf(err) != token.CodeDevice {
		t.Fatalf("short digest: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if _, err := s.SignDigest(ctx, digest[:]); token.CodeOf(err) != token.CodeDevice {
		t.Fatalf("sign after close: %v", err)
	}
	s, err = p.Open(ctx, soft.DefaultPIN)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	_ = s.Close()
}

func TestStdoutNoise(t *testing.T) {
	p := newHelper(t, "noisy")
	for range 3 {
		if st := p.Status(t.Context()); !st.Available {
			t.Fatalf("status: %+v", st)
		}
	}
}

func TestCrashIsADeviceErrorAndNotRetried(t *testing.T) {
	p := newHelper(t, "crash")
	if st := p.Status(t.Context()); !st.Available {
		t.Fatalf("status: %+v", st)
	}
	first := p.proc
	if _, err := p.Open(t.Context(), soft.DefaultPIN); token.CodeOf(err) != token.CodeDevice {
		t.Fatalf("open: %v", err)
	}
	if !first.exited() {
		t.Fatal("the crashed worker is still running")
	}
	// The next request starts a new worker.
	if st := p.Status(t.Context()); !st.Available {
		t.Fatalf("status after crash: %+v", st)
	}
	if p.proc == first {
		t.Fatal("worker not restarted")
	}
}

func TestCancelKillsWorker(t *testing.T) {
	p := newHelper(t, "slow")
	s, err := p.Open(t.Context(), soft.DefaultPIN)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 500*time.Millisecond)
	defer cancel()
	digest := sha256.Sum256(nil)
	if _, err := s.SignDigest(ctx, digest[:]); token.CodeOf(err) != token.CodeDevice {
		t.Fatalf("sign: %v", err)
	}
	if _, err := s.SignDigest(t.Context(), digest[:]); token.CodeOf(err) != token.CodeDevice {
		t.Fatalf("sign on a dead worker: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

func TestMissingWorker(t *testing.T) {
	p := New(Options{Name: "cie-mw", Command: []string{"/nonexistent/esign", "worker"}})
	if st := p.Status(t.Context()); st.Available || st.Provider != "cie-mw" {
		t.Fatalf("status: %+v", st)
	}
	if _, err := p.Open(t.Context(), soft.DefaultPIN); token.CodeOf(err) != token.CodeMiddlewareMissing {
		t.Fatalf("open: %v", err)
	}
}

func TestFrameLimit(t *testing.T) {
	var buf bytes.Buffer
	buf.Write([]byte{0x7f, 0xff, 0xff, 0xff})
	var res response
	if err := readFrame(&buf, &res); err == nil {
		t.Fatal("oversized frame accepted")
	}
}

func TestArchsOfSelf(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	archs, err := Archs(exe)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(archs, runtime.GOARCH) {
		t.Fatalf("archs %v, running %s", archs, runtime.GOARCH)
	}
	if _, err := Archs("worker_test.go"); err == nil {
		t.Fatal("a Go file is not a binary")
	}
}

func TestChoose(t *testing.T) {
	both := []string{"amd64", "arm64"}
	tests := []struct {
		goos, goarch  string
		module, self  []string
		isolate       bool
		want          Plan
		wantErr       bool
		wantArgv0     string
		wantArgsCount int
	}{
		{"darwin", "arm64", []string{"amd64"}, both, false, Plan{Worker: true, Arch: "amd64"}, false, "/usr/bin/arch", 4},
		{"darwin", "arm64", []string{"amd64"}, []string{"arm64"}, false, Plan{}, true, "", 0},
		{"darwin", "arm64", both, both, false, Plan{}, false, "agent", 2},
		{"darwin", "arm64", both, both, true, Plan{Worker: true}, false, "agent", 2},
		{"darwin", "amd64", []string{"arm64"}, both, false, Plan{Worker: true, Arch: "arm64"}, false, "/usr/bin/arch", 4},
		{"linux", "arm64", []string{"amd64"}, []string{"arm64"}, false, Plan{}, true, "", 0},
		{"windows", "amd64", []string{"amd64"}, []string{"amd64"}, false, Plan{}, false, "agent", 2},
	}
	for _, tt := range tests {
		got, err := Choose(tt.goos, tt.goarch, tt.module, tt.self, tt.isolate)
		if (err != nil) != tt.wantErr || got != tt.want {
			t.Errorf("Choose(%s/%s, %v, %v, %v) = %+v, %v", tt.goos, tt.goarch, tt.module, tt.self, tt.isolate, got, err)
			continue
		}
		if err == nil {
			argv := Command(got, "agent", "worker")
			if argv[0] != tt.wantArgv0 || len(argv) != tt.wantArgsCount {
				t.Errorf("Command(%+v) = %v", got, argv)
			}
		}
	}
}

func asError(err error, target **token.Error) bool {
	e, ok := err.(*token.Error)
	if ok {
		*target = e
	}
	return ok
}
