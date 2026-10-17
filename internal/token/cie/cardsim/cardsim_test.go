package cardsim_test

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/PoliNetworkOrg/sign-agent/internal/token"
	"github.com/PoliNetworkOrg/sign-agent/internal/token/cie/cardsim"
	"github.com/PoliNetworkOrg/sign-agent/internal/token/cie/ias"
)

var (
	keysOnce sync.Once
	keys     *cardsim.Keys
	keysErr  error
)

func newCard(t *testing.T, opts cardsim.Options) *cardsim.Card {
	t.Helper()
	keysOnce.Do(func() { keys, keysErr = cardsim.GenerateKeys() })
	if keysErr != nil {
		t.Fatal(keysErr)
	}
	opts.Keys = keys
	c, err := cardsim.New(opts)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// recorder is a Transport that logs the APDUs and can pull the card out or tamper with responses.
type recorder struct {
	card     *cardsim.Card
	cmds     [][]byte
	removeAt int // remove the card before this command (1-based); 0 never
	tamper   func(cmd, resp []byte) []byte
	// intercept answers a command instead of the card when it returns true.
	intercept func(cmd []byte) ([]byte, bool)
}

func (r *recorder) Transmit(cmd []byte) ([]byte, error) {
	r.cmds = append(r.cmds, append([]byte{}, cmd...))
	if r.removeAt > 0 && len(r.cmds) >= r.removeAt {
		return nil, ias.ErrCardRemoved
	}
	if r.intercept != nil {
		if resp, ok := r.intercept(cmd); ok {
			return resp, nil
		}
	}
	resp, err := r.card.Transmit(cmd)
	if err == nil && r.tamper != nil {
		resp = r.tamper(cmd, resp)
	}
	return resp, err
}

func (r *recorder) count(match func([]byte) bool) int {
	n := 0
	for _, c := range r.cmds {
		if match(c) {
			n++
		}
	}
	return n
}

// client connects the IAS client to the simulated card through t, trusting the simulator's test CSCA.
func client(t ias.Transport, sim *cardsim.Card) *ias.Card {
	c := ias.NewCard(t, sim.ATR())
	c.TrustAnchors = []*x509.Certificate{sim.CSCACertificate()}
	return c
}

func signAndVerify(t *testing.T, c *ias.Card) {
	t.Helper()
	digest := sha256.Sum256([]byte("signed attributes"))
	di, _ := token.DigestInfoSHA256(digest[:])
	sig, err := c.Sign(di)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := rsa.VerifyPKCS1v15(c.Certificate().PublicKey.(*rsa.PublicKey), crypto.SHA256, digest[:], sig); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts cardsim.Options
	}{
		{"nxp", cardsim.Options{}},
		{"gemalto", cardsim.Options{Variant: cardsim.Gemalto}},
		{"unlisted ATR", cardsim.Options{Variant: cardsim.Unlisted}},
		{"unprotected errors", cardsim.Options{UnprotectedErrors: true}},
		{"6Cxx short reads and padded certificate file", cardsim.Options{ShortReadsWith6C: true, CertificateFileSize: 2048}},
		{"padded certificate file ending on a chunk", cardsim.Options{CertificateFileSize: 1536}},
		{"DH public value with a leading zero", cardsim.Options{PublicValueLeadingZero: true}},
		{"DH public value sent in 255 bytes", cardsim.Options{PublicValueLeadingZero: true, MinimalPublicValue: true}},
		{"SOD and Document Signer with RSA-PSS and SHA-512", cardsim.Options{SODWithPSS: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sim := newCard(t, tc.opts)
			r := &recorder{card: sim}
			c := client(r, sim)
			if err := c.Authenticate("12345678"); err != nil {
				t.Fatalf("authenticate: %v", err)
			}
			if !bytes.Equal(c.Certificate().Raw, sim.Certificate().Raw) {
				t.Fatal("certificate differs")
			}
			signAndVerify(t, c)
			signAndVerify(t, c) // the session stays usable
			// The DH MSE SET (266 bytes) and the terminal certificate and EXTERNAL AUTHENTICATE (over 0xE7 bytes)
			// are chained; DH p and the DAPP and signature answers come through GET RESPONSE.
			if n := r.count(func(c []byte) bool { return c[0]&0x10 != 0 }); n < 3 {
				t.Errorf("%d chained commands", n)
			}
			if n := r.count(func(c []byte) bool { return c[1] == 0xC0 }); n < 3 {
				t.Errorf("%d GET RESPONSE", n)
			}
		})
	}
}

func TestWrongPIN(t *testing.T) {
	sim := newCard(t, cardsim.Options{})
	for i, want := range []int{2, 1, 0} {
		c := client(sim, sim)
		err := c.Authenticate("00000000")
		var pe *ias.PINError
		if !errors.As(err, &pe) || pe.Retries() != want || pe.Locked() {
			t.Fatalf("attempt %d: %v", i+1, err)
		}
		sim.Reset()
	}
	err := client(sim, sim).Authenticate("12345678")
	var pe *ias.PINError
	if !errors.As(err, &pe) || !pe.Locked() {
		t.Fatalf("after three wrong PINs: %v", err)
	}
}

func TestWrongPINThenRight(t *testing.T) {
	sim := newCard(t, cardsim.Options{UnprotectedErrors: true})
	err := client(sim, sim).Authenticate("11111111")
	var pe *ias.PINError
	if !errors.As(err, &pe) || pe.Retries() != 2 {
		t.Fatalf("wrong PIN: %v", err)
	}
	sim.Reset()
	if err := client(sim, sim).Authenticate("12345678"); err != nil {
		t.Fatal(err)
	}
	if sim.PINTriesLeft() != 3 {
		t.Fatalf("counter not reset: %d", sim.PINTriesLeft())
	}
}

func TestCardRemoved(t *testing.T) {
	sim := newCard(t, cardsim.Options{})
	r := &recorder{card: sim}
	c := client(r, sim)
	if err := c.Authenticate("12345678"); err != nil {
		t.Fatal(err)
	}
	r.removeAt = len(r.cmds) + 1
	digest := sha256.Sum256([]byte("x"))
	di, _ := token.DigestInfoSHA256(digest[:])
	if _, err := c.Sign(di); !errors.Is(err, ias.ErrCardRemoved) {
		t.Fatalf("got %v", err)
	}
	// Removal in the middle of DAPP.
	sim.Reset()
	r = &recorder{card: sim, removeAt: 20}
	if err := client(r, sim).Authenticate("12345678"); !errors.Is(err, ias.ErrCardRemoved) {
		t.Fatalf("got %v", err)
	}
}

func TestTamperedResponse(t *testing.T) {
	sim := newCard(t, cardsim.Options{})
	r := &recorder{card: sim}
	// Flip a bit in the first protected response that carries data.
	done := false
	r.tamper = func(cmd, resp []byte) []byte {
		if !done && cmd[0]&0x0C == 0x0C && len(resp) > 20 {
			done = true
			resp[3] ^= 1
		}
		return resp
	}
	err := client(r, sim).Authenticate("12345678")
	var pe *ias.ProtocolError
	if !errors.As(err, &pe) {
		t.Fatalf("got %v", err)
	}
}

// TestSubstitutedChipKey replaces EF 1004, read before the secure channel, with another key: the SOD check must reject
// the card before any PIN is sent.
func TestSubstitutedChipKey(t *testing.T) {
	sim := newCard(t, cardsim.Options{})
	fake, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	r := &recorder{card: sim}
	selected := false
	r.tamper = func(cmd, resp []byte) []byte {
		switch {
		case bytes.Equal(cmd, []byte{0x00, 0xA4, 0x02, 0x04, 0x02, 0x10, 0x04}):
			selected = true
		case selected && cmd[1] == 0xB0 && cmd[0] == 0x00:
			selected = false
			return append(ias.EncodeTLV(0x30, append(ias.EncodeTLV(0x02, append([]byte{0}, fake.N.Bytes()...)), ias.EncodeTLV(0x02, []byte{1, 0, 1})...)), 0x90, 0x00)
		}
		return resp
	}
	err = client(r, sim).Authenticate("12345678")
	var te *ias.TrustError
	if !errors.As(err, &te) {
		t.Fatalf("got %v", err)
	}
	if n := r.count(func(c []byte) bool { return c[1] == 0x20 }); n != 0 {
		t.Fatal("PIN sent to an unauthenticated chip")
	}
	if sim.PINTriesLeft() != 3 {
		t.Fatal("PIN counter changed")
	}
}

func verifies(cmd []byte) bool { return len(cmd) > 1 && cmd[1] == 0x20 }

// untrusted runs Authenticate and requires a TrustError with no VERIFY sent and the PIN counter untouched.
func untrusted(t *testing.T, sim *cardsim.Card, c *ias.Card, r *recorder) {
	t.Helper()
	err := c.Authenticate("12345678")
	var te *ias.TrustError
	if !errors.As(err, &te) {
		t.Fatalf("got %v", err)
	}
	if n := r.count(verifies); n != 0 {
		t.Fatalf("%d VERIFY sent to an unverified card", n)
	}
	if sim.PINTriesLeft() != 3 || c.PINSent() {
		t.Fatal("PIN used")
	}
	t.Logf("rejected: %v", err)
}

// TestSODChecks: before the PIN, the SOD must chain to a trusted CSCA and cover EF 1004 and EF.DH as read.
func TestSODChecks(t *testing.T) {
	sim := newCard(t, cardsim.Options{})
	match := func(fid uint16) func(cmd []byte) bool {
		return func(cmd []byte) bool {
			return bytes.Equal(cmd, []byte{0x00, 0xA4, 0x02, 0x04, 0x02, byte(fid >> 8), byte(fid)})
		}
	}
	// replaceRead rewrites the data of the first READ BINARY after selecting fid.
	replaceRead := func(fid uint16, edit func([]byte) []byte) func(cmd, resp []byte) []byte {
		selected := false
		return func(cmd, resp []byte) []byte {
			switch {
			case match(fid)(cmd):
				selected = true
			case selected && cmd[1] == 0xB0 && cmd[0] == 0x00:
				selected = false
				n := len(resp) - 2
				return append(edit(append([]byte{}, resp[:n]...)), resp[n:]...)
			}
			return resp
		}
	}

	t.Run("valid", func(t *testing.T) {
		r := &recorder{card: sim}
		if err := client(r, sim).Authenticate("12345678"); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("tampered EF 1004", func(t *testing.T) {
		sim.Reset()
		r := &recorder{card: sim, tamper: replaceRead(ias.FileIntAuthKey, func(b []byte) []byte { b[20] ^= 1; return b })}
		untrusted(t, sim, client(r, sim), r)
	})
	t.Run("tampered EF.DH", func(t *testing.T) {
		sim.Reset()
		r := &recorder{card: sim, tamper: replaceRead(ias.FileDH, func(b []byte) []byte { b[30] ^= 1; return b })}
		untrusted(t, sim, client(r, sim), r)
	})
	t.Run("missing SOD", func(t *testing.T) {
		sim.Reset()
		r := &recorder{card: sim, tamper: func(cmd, resp []byte) []byte {
			if match(ias.FileSOD)(cmd) {
				return []byte{0x6A, 0x82}
			}
			return resp
		}}
		untrusted(t, sim, client(r, sim), r)
	})
	t.Run("Document Signer from another CSCA", func(t *testing.T) {
		sim.Reset()
		r := &recorder{card: sim}
		c := client(r, sim)
		c.TrustAnchors = []*x509.Certificate{otherCSCA(t, sim)}
		untrusted(t, sim, c, r)
	})
	t.Run("official Italian anchors", func(t *testing.T) {
		sim.Reset()
		r := &recorder{card: sim}
		untrusted(t, sim, ias.NewCard(r, sim.ATR()), r)
	})
}

// otherCSCA is a self-signed CA with the same name as the simulator's CSCA but another key.
func otherCSCA(t *testing.T, sim *cardsim.Card) *x509.Certificate {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	real := sim.CSCACertificate()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(99), Subject: pkix.Name{CommonName: real.Subject.CommonName, Country: real.Subject.Country, Organization: real.Subject.Organization},
		NotBefore: time.Now().Add(-72 * time.Hour), NotAfter: time.Now().AddDate(10, 0, 0),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c
}

// TestNoRetryOfVERIFYOn6C: a 6Cxx answer to VERIFY must not make the client send the PIN again.
func TestNoRetryOfVERIFYOn6C(t *testing.T) {
	sim := newCard(t, cardsim.Options{})
	r := &recorder{card: sim}
	r.intercept = func(cmd []byte) ([]byte, bool) {
		if verifies(cmd) {
			return []byte{0x6C, 0x08}, true
		}
		return nil, false
	}
	c := client(r, sim)
	err := c.Authenticate("12345678")
	if err == nil {
		t.Fatal("authenticated")
	}
	if n := r.count(verifies); n != 1 {
		t.Fatalf("%d VERIFY sent", n)
	}
	t.Logf("6C08 to VERIFY: %v", err)
}
