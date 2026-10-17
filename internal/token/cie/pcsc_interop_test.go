package cie_test

import (
	"crypto"
	"crypto/rsa"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/PoliNetworkOrg/sign-agent/internal/token"
	"github.com/PoliNetworkOrg/sign-agent/internal/token/cie"
)

// TestPCSCInterop runs the provider through the real PC/SC stack. scripts/interop/run.sh sets it up: pcsc-lite with
// the vpcd virtual reader, served by cmd/cie-vcard (SIGN_AGENT_TEST_VCARD is its control endpoint) with a card
// whose PIN is SIGN_AGENT_TEST_PIN and whose counter is full.
func TestPCSCInterop(t *testing.T) {
	pin := os.Getenv("SIGN_AGENT_TEST_PIN")
	control := os.Getenv("SIGN_AGENT_TEST_VCARD")
	if os.Getenv("SIGN_AGENT_TEST_PCSC") == "" || pin == "" || control == "" {
		t.Skip("SIGN_AGENT_TEST_PCSC, SIGN_AGENT_TEST_PIN and SIGN_AGENT_TEST_VCARD are not set")
	}
	p := cie.New()

	st := p.Status(t.Context())
	t.Logf("status: %+v", st)
	if !st.Available || st.CardPresent == nil || !*st.CardPresent || !strings.Contains(st.Detail, "NXP") {
		t.Fatalf("status: %+v", st)
	}

	wrong := strings.Repeat("0", 8)
	if wrong == pin {
		wrong = strings.Repeat("1", 8)
	}
	_, err := p.Open(t.Context(), wrong)
	var te *token.Error
	if !asTokenError(err, &te) || te.Code != token.CodePinIncorrect || te.RetriesLeft != 2 || !te.PINSent {
		t.Fatalf("wrong PIN: %v", err)
	}
	t.Logf("wrong PIN: %v (retries left %d)", err, te.RetriesLeft)

	s, err := p.Open(t.Context(), pin)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Logf("certificate: %s", s.Certificate().Subject)
	sig, err := s.SignDigest(t.Context(), digest())
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := rsa.VerifyPKCS1v15(s.Certificate().PublicKey.(*rsa.PublicKey), crypto.SHA256, digest(), sig); err != nil {
		t.Fatal(err)
	}
	t.Logf("signed and verified a %d-byte signature", len(sig))

	// Pull the card out in the middle of the session.
	post(t, control+"/remove")
	if _, err := s.SignDigest(t.Context(), digest()); token.CodeOf(err) != token.CodeCardRemoved {
		t.Fatalf("sign after removal: %v", err)
	}
	_ = s.Close()
	t.Logf("card removed mid-session: %v", token.CodeCardRemoved)
	waitPresent(t, p, false)
	if _, err := p.Open(t.Context(), pin); token.CodeOf(err) != token.CodeNoCard {
		t.Fatalf("open without a card: %v", err)
	}
	post(t, control+"/insert")
	waitPresent(t, p, true)
	s, err = p.Open(t.Context(), pin)
	if err != nil {
		t.Fatalf("open after reinsertion: %v", err)
	}
	if _, err := s.SignDigest(t.Context(), digest()); err != nil {
		t.Fatalf("sign after reinsertion: %v", err)
	}
	_ = s.Close()
}

func post(t *testing.T, url string) {
	t.Helper()
	resp, err := http.Post(url, "text/plain", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
}

func waitPresent(t *testing.T, p *cie.Provider, want bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	var st token.Status
	for time.Now().Before(deadline) {
		st = p.Status(t.Context())
		if st.CardPresent != nil && *st.CardPresent == want {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("card present never became %v: %+v", want, st)
}
