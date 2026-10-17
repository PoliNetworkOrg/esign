package p11

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"os"
	"testing"

	"github.com/PoliNetworkOrg/esign/internal/token"
)

// TestModule runs against a real module: set ESIGN_TEST_PKCS11 to its path and ESIGN_TEST_PIN to the user
// PIN of a token holding an RSA key and its certificate (scripts/test-softhsm.sh prepares SoftHSM2 this way).
func TestModule(t *testing.T) {
	path := os.Getenv("ESIGN_TEST_PKCS11")
	pin := os.Getenv("ESIGN_TEST_PIN")
	if path == "" || pin == "" {
		t.Skip("ESIGN_TEST_PKCS11 and ESIGN_TEST_PIN are not set")
	}
	p := New(Options{Name: "pkcs11", Path: path})
	defer p.Close()

	st := p.Status(t.Context())
	if !st.Available || st.CardPresent == nil || !*st.CardPresent {
		t.Fatalf("status: %+v", st)
	}
	if _, err := p.Open(t.Context(), "99999999"); token.CodeOf(err) != token.CodePinIncorrect {
		t.Fatalf("wrong PIN: %v", err)
	}
	session, err := p.Open(t.Context(), pin)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer session.Close()
	digest := sha256.Sum256([]byte("to be signed"))
	sig, err := session.SignDigest(t.Context(), digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := rsa.VerifyPKCS1v15(session.Certificate().PublicKey.(*rsa.PublicKey), crypto.SHA256, digest[:], sig); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestLastFour(t *testing.T) {
	if LastFour("12345678") != "5678" || LastFour("5678") != "5678" {
		t.Fatal("LastFour")
	}
}

func TestMissingModule(t *testing.T) {
	p := New(Options{Candidates: []string{"/nonexistent/module.so"}})
	if st := p.Status(t.Context()); st.Available {
		t.Fatal("available without a module")
	}
	if _, err := p.Open(t.Context(), "12345678"); token.CodeOf(err) != token.CodeMiddlewareMissing {
		t.Fatalf("got %v", err)
	}
}
