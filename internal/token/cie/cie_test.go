package cie_test

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"strings"
	"sync"
	"testing"

	"github.com/PoliNetworkOrg/esign/internal/token"
	"github.com/PoliNetworkOrg/esign/internal/token/cie"
	"github.com/PoliNetworkOrg/esign/internal/token/cie/cardsim"
	"github.com/PoliNetworkOrg/esign/internal/token/cie/ias"
)

var (
	keysOnce sync.Once
	keys     *cardsim.Keys
)

func simCard(t *testing.T, opts cardsim.Options) *cardsim.Card {
	t.Helper()
	keysOnce.Do(func() {
		var err error
		if keys, err = cardsim.GenerateKeys(); err != nil {
			panic(err)
		}
	})
	opts.Keys = keys
	c, err := cardsim.New(opts)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// card is what a simulated reader holds: the CIE simulator or another card.
type card interface {
	ATR() []byte
	Transmit([]byte) ([]byte, error)
	Reset()
}

type reader struct {
	name    string
	card    card // nil when empty
	removed bool
}

// connector is a cie.Connector over simulated readers.
type connector struct {
	mu      sync.Mutex
	readers []*reader
}

func (c *connector) Readers() ([]cie.Reader, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []cie.Reader
	for _, r := range c.readers {
		cr := cie.Reader{Name: r.name}
		if r.card != nil && !r.removed {
			cr.ATR = r.card.ATR()
		}
		out = append(out, cr)
	}
	return out, nil
}

func (c *connector) find(name string) *reader {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, r := range c.readers {
		if r.name == name {
			return r
		}
	}
	return nil
}

func (c *connector) Connect(name string) (cie.Conn, error) {
	r := c.find(name)
	if r == nil || r.card == nil || r.removed {
		return nil, ias.ErrCardRemoved
	}
	r.card.Reset()
	return &conn{c: c, r: r}, nil
}

func (c *connector) Probe(name string, apdu []byte) ([]byte, error) {
	r := c.find(name)
	if r == nil || r.card == nil {
		return nil, ias.ErrCardRemoved
	}
	return r.card.Transmit(apdu)
}

type conn struct {
	c *connector
	r *reader
}

func (s *conn) Transmit(cmd []byte) ([]byte, error) {
	s.c.mu.Lock()
	gone := s.r.removed
	s.c.mu.Unlock()
	if gone {
		return nil, ias.ErrCardRemoved
	}
	return s.r.card.Transmit(cmd)
}

func (s *conn) Close() error {
	s.r.card.Reset()
	return nil
}

// otherCard answers 6A82 to everything, like a payment or transport card.
type otherCard struct{ transmits int }

func (o *otherCard) ATR() []byte {
	return []byte{0x3B, 0x8F, 0x80, 0x01, 0x80, 0x4F, 0x0C, 0xA0, 0x00, 0x00, 0x03, 0x06, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x6A}
}
func (o *otherCard) Transmit([]byte) ([]byte, error) {
	o.transmits++
	return []byte{0x6A, 0x82}, nil
}
func (o *otherCard) Reset() {}

// trusting makes p accept the simulator's test CSCA instead of the Italian ones.
func trusting(p *cie.Provider, sim *cardsim.Card) *cie.Provider {
	p.TrustAnchors = []*x509.Certificate{sim.CSCACertificate()}
	return p
}

func digest() []byte {
	d := sha256.Sum256([]byte("CMS signed attributes"))
	return d[:]
}

// TestStatusNoReader: without a reader the provider is available with no card, and signing asks for the reader.
func TestStatusNoReader(t *testing.T) {
	p := cie.NewWithConnector(&connector{})
	st := p.Status(t.Context())
	if !st.Available || st.CardPresent == nil || *st.CardPresent || len(st.Readers) != 0 || st.Detail != "no smart-card reader" {
		t.Fatalf("no readers: %+v", st)
	}
	if _, err := p.Open(t.Context(), "12345678"); token.CodeOf(err) != token.CodeNoReader {
		t.Fatalf("open without a reader: %v", err)
	}
}

func TestStatus(t *testing.T) {
	empty := &connector{readers: []*reader{{name: "ACS ACR1252"}}}
	st := cie.NewWithConnector(empty).Status(t.Context())
	if !st.Available || st.CardPresent == nil || *st.CardPresent || len(st.Readers) != 1 {
		t.Fatalf("empty reader: %+v", st)
	}
	other := &otherCard{}
	c := &connector{readers: []*reader{{name: "A", card: other}, {name: "B", card: simCard(t, cardsim.Options{})}}}
	p := cie.NewWithConnector(c)
	st = p.Status(t.Context())
	if !st.Available || !*st.CardPresent || !strings.Contains(st.Detail, "NXP") || !strings.Contains(st.Detail, "on B") {
		t.Fatalf("CIE present: %+v", st)
	}
	p.Status(t.Context())
	if other.transmits != 1 {
		t.Fatalf("the unknown card was probed %d times", other.transmits)
	}
	c.readers = c.readers[:1]
	st = p.Status(t.Context())
	if *st.CardPresent || !strings.Contains(st.Detail, "not a CIE") {
		t.Fatalf("other card: %+v", st)
	}
	unlisted := &connector{readers: []*reader{{name: "R", card: simCard(t, cardsim.Options{Variant: cardsim.Unlisted})}}}
	if st := cie.NewWithConnector(unlisted).Status(t.Context()); !*st.CardPresent {
		t.Fatalf("unlisted ATR: %+v", st)
	}
}

func TestOpenSign(t *testing.T) {
	for _, v := range []cardsim.Variant{cardsim.NXP, cardsim.Gemalto, cardsim.Unlisted} {
		sim := simCard(t, cardsim.Options{Variant: v})
		p := trusting(cie.NewWithConnector(&connector{readers: []*reader{{name: "R", card: sim}}}), sim)
		s, err := p.Open(t.Context(), "12345678")
		if err != nil {
			t.Fatalf("variant %d: open: %v", v, err)
		}
		if s.Certificate().Subject.CommonName != "RSSMRA80A01F205X/123456789012" {
			t.Fatalf("certificate %s", s.Certificate().Subject)
		}
		sig, err := s.SignDigest(t.Context(), digest())
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		if err := rsa.VerifyPKCS1v15(s.Certificate().PublicKey.(*rsa.PublicKey), crypto.SHA256, digest(), sig); err != nil {
			t.Fatal(err)
		}
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestPINErrors(t *testing.T) {
	sim := simCard(t, cardsim.Options{})
	p := trusting(cie.NewWithConnector(&connector{readers: []*reader{{name: "R", card: sim}}}), sim)
	before, _ := sim.Stats()
	if _, err := p.Open(t.Context(), "1234"); token.CodeOf(err) != token.CodePinInvalid {
		t.Fatalf("short PIN: %v", err)
	}
	if after, _ := sim.Stats(); after != before {
		t.Fatal("a malformed PIN reached the card")
	}
	for _, want := range []int{2, 1, 0} {
		_, err := p.Open(t.Context(), "00000000")
		var te *token.Error
		if token.CodeOf(err) != token.CodePinIncorrect || !asTokenError(err, &te) || te.RetriesLeft != want || !te.PINSent {
			t.Fatalf("want %d retries: %v", want, err)
		}
	}
	if _, err := p.Open(t.Context(), "12345678"); token.CodeOf(err) != token.CodePinLocked || !token.PINSent(err) {
		t.Fatalf("locked: %v", err)
	}
}

func asTokenError(err error, out **token.Error) bool {
	te, ok := err.(*token.Error)
	*out = te
	return ok
}

func TestCardRemovedMidSession(t *testing.T) {
	sim := simCard(t, cardsim.Options{})
	r := &reader{name: "R", card: sim}
	c := &connector{readers: []*reader{r}}
	p := trusting(cie.NewWithConnector(c), sim)
	s, err := p.Open(t.Context(), "12345678")
	if err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	r.removed = true
	c.mu.Unlock()
	if _, err := s.SignDigest(t.Context(), digest()); token.CodeOf(err) != token.CodeCardRemoved {
		t.Fatalf("got %v", err)
	}
	_ = s.Close()
	if _, err := p.Open(t.Context(), "12345678"); token.CodeOf(err) != token.CodeNoCard {
		t.Fatalf("after removal: %v", err)
	}
}

func TestNotACIE(t *testing.T) {
	p := cie.NewWithConnector(&connector{readers: []*reader{{name: "R", card: &otherCard{}}}})
	if _, err := p.Open(t.Context(), "12345678"); token.CodeOf(err) != token.CodeCardUnsupported || token.PINSent(err) {
		t.Fatalf("got %v", err)
	}
	if _, err := cie.NewWithConnector(&connector{}).Open(t.Context(), "12345678"); token.CodeOf(err) != token.CodeNoReader {
		t.Fatalf("no reader: %v", err)
	}
}

// TestUntrustedCard: with the production anchors the simulator's SOD does not verify, so the provider refuses the
// card with card_untrusted before sending the PIN.
func TestUntrustedCard(t *testing.T) {
	sim := simCard(t, cardsim.Options{})
	p := cie.NewWithConnector(&connector{readers: []*reader{{name: "R", card: sim}}})
	_, err := p.Open(t.Context(), "12345678")
	if token.CodeOf(err) != token.CodeCardUntrusted || token.PINSent(err) || sim.PINTriesLeft() != 3 {
		t.Fatalf("got %v (PIN sent %v, tries %d)", err, token.PINSent(err), sim.PINTriesLeft())
	}
}
