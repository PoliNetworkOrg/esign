package p11

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PoliNetworkOrg/sign-agent/internal/token"
)

// These tests run a CIE PKCS#11 module against the simulated card of scripts/interop/run.sh (cmd/cie-vcard behind
// pcsc-lite and vpcd): SIGN_AGENT_TEST_CIEMW is the official middleware, SIGN_AGENT_TEST_OPENCIE is OpenCIE, and
// SIGN_AGENT_TEST_PIN the card's full PIN. They start unpaired, so Open must pair through the module.

func TestOfficialMiddlewareInterop(t *testing.T) {
	path := os.Getenv("SIGN_AGENT_TEST_CIEMW")
	if path == "" {
		t.Skip("SIGN_AGENT_TEST_CIEMW is not set")
	}
	runModule(t, Options{Name: "cie-mw", Path: path, PIN: LastFour, PINLength: 8, Pair: OfficialPairing()})
}

func TestOpenCIEInterop(t *testing.T) {
	path := os.Getenv("SIGN_AGENT_TEST_OPENCIE")
	if path == "" {
		t.Skip("SIGN_AGENT_TEST_OPENCIE is not set")
	}
	runModule(t, Options{Name: "opencie", Path: path, PINLength: 8, Pair: OpenCIEPairing()})
}

// cacheFiles are the pairing caches both modules write on Linux.
func cacheFiles(t *testing.T) []string {
	home, _ := os.UserHomeDir()
	files, _ := filepath.Glob(filepath.Join(home, ".CIEPKI", "*.cache"))
	return files
}

func runModule(t *testing.T, opts Options) {
	pin := os.Getenv("SIGN_AGENT_TEST_PIN")
	if pin == "" {
		t.Fatal("SIGN_AGENT_TEST_PIN is not set")
	}
	for _, f := range cacheFiles(t) {
		if err := os.Remove(f); err != nil {
			t.Fatal(err)
		}
	}
	p := New(opts)
	defer p.Close()
	st := p.Status(t.Context())
	t.Logf("status: %+v", st)
	if !st.Available || st.CardPresent == nil || !*st.CardPresent {
		t.Fatalf("status: %+v", st)
	}

	// Unpaired, wrong PIN: the pairing attempt reports the card's counter and is not repeated.
	wrong := strings.Repeat("0", 8)
	if wrong == pin {
		wrong = strings.Repeat("1", 8)
	}
	_, err := p.Open(t.Context(), wrong)
	var te *token.Error
	if !errors.As(err, &te) || te.Code != token.CodePinIncorrect || te.RetriesLeft != 2 {
		t.Fatalf("unpaired, wrong PIN: %v", err)
	}
	if len(cacheFiles(t)) != 0 {
		t.Fatal("a wrong PIN paired the card")
	}
	t.Logf("unpaired, wrong PIN: %v (retries left %d)", err, te.RetriesLeft)

	// Unpaired, right PIN: Open pairs the card and signs.
	s, err := p.Open(t.Context(), pin)
	if err != nil {
		t.Fatalf("open with pairing: %v", err)
	}
	t.Logf("paired: cache %v", cacheFiles(t))
	signVerify(t, s)
	_ = s.Close()
	if len(cacheFiles(t)) != 1 {
		t.Fatalf("pairing cache: %v", cacheFiles(t))
	}

	// Paired: a plain open.
	s, err = p.Open(t.Context(), pin)
	if err != nil {
		t.Fatalf("open when paired: %v", err)
	}
	signVerify(t, s)
	_ = s.Close()

	// Paired, wrong PIN: C_Login fails; the counter is not visible through PKCS#11.
	wrongEnd := "0000"
	if pin[4:] == wrongEnd {
		wrongEnd = "1111"
	}
	_, err = p.Open(t.Context(), pin[:4]+wrongEnd)
	if token.CodeOf(err) != token.CodePinIncorrect {
		t.Fatalf("paired, wrong PIN: %v", err)
	}
	t.Logf("paired, wrong PIN: %v", err)
	// A right PIN resets the counter for the next test.
	s, err = p.Open(t.Context(), pin)
	if err != nil {
		t.Fatalf("open after a wrong PIN: %v", err)
	}
	_ = s.Close()
}

func signVerify(t *testing.T, s token.Session) {
	t.Helper()
	digest := sha256.Sum256([]byte("CMS signed attributes"))
	sig, err := s.SignDigest(t.Context(), digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := rsa.VerifyPKCS1v15(s.Certificate().PublicKey.(*rsa.PublicKey), crypto.SHA256, digest[:], sig); err != nil {
		t.Fatalf("verify: %v", err)
	}
	t.Logf("signed as %s, verified", s.Certificate().Subject.CommonName)
}
