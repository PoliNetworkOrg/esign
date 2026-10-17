package p11

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"os"
	"testing"

	"github.com/PoliNetworkOrg/sign-agent/internal/token"
)

// TestModule runs against a real module: set SIGN_AGENT_TEST_PKCS11 to its path and SIGN_AGENT_TEST_PIN to the user
// PIN of a token holding an RSA key and its certificate (scripts/test-softhsm.sh prepares SoftHSM2 this way).
func TestModule(t *testing.T) {
	path := os.Getenv("SIGN_AGENT_TEST_PKCS11")
	pin := os.Getenv("SIGN_AGENT_TEST_PIN")
	if path == "" || pin == "" {
		t.Skip("SIGN_AGENT_TEST_PKCS11 and SIGN_AGENT_TEST_PIN are not set")
	}
	p := New(Options{Name: "pkcs11", Path: path})
	defer p.Close()

	st := p.Status(t.Context())
	if !st.Available || st.CardPresent == nil || !*st.CardPresent {
		t.Fatalf("status: %+v", st)
	}
	certs, err := p.Certificates(t.Context())
	if err != nil || len(certs) != 1 {
		t.Fatalf("certificates: %v %v", certs, err)
	}
	digest := sha256.Sum256([]byte("to be signed"))

	_, err = p.SignDigest(t.Context(), certs[0].ID, digest[:], "99999999")
	if token.CodeOf(err) != token.CodePinIncorrect {
		t.Fatalf("wrong PIN: %v", err)
	}
	sig, err := p.SignDigest(t.Context(), certs[0].ID, digest[:], pin)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := rsa.VerifyPKCS1v15(certs[0].Cert.PublicKey.(*rsa.PublicKey), crypto.SHA256, digest[:], sig); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if _, err := p.SignDigest(t.Context(), "pkcs11:00", digest[:], pin); token.CodeOf(err) != token.CodeNotFound {
		t.Fatalf("unknown certificate: %v", err)
	}
}

func TestMissingModule(t *testing.T) {
	p := New(Options{Candidates: []string{"/nonexistent/module.so"}})
	if st := p.Status(t.Context()); st.Available {
		t.Fatal("available without a module")
	}
	if _, err := p.Certificates(t.Context()); token.CodeOf(err) != token.CodeMiddlewareMissing {
		t.Fatalf("got %v", err)
	}
}
