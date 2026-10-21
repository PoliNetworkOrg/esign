// Package cie speaks to the CIE directly over PC/SC, without any middleware, with the IAS protocol of package ias.
// It needs no pairing: every session authenticates with the full eight-digit PIN and reads the certificate from the
// card.
package cie

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/PoliNetworkOrg/esign/internal/token"
	"github.com/PoliNetworkOrg/esign/internal/token/cie/ias"
)

// Reader is a card reader and the ATR of the card on it, nil when it is empty.
type Reader struct {
	Name string
	ATR  []byte
}

// Connector reaches the readers. PC/SC is the default; tests plug in the card simulator.
type Connector interface {
	Readers() ([]Reader, error)
	// Connect resets the card on reader and opens a transaction with it.
	Connect(reader string) (Conn, error)
	// Probe sends one APDU to the card on reader, without resetting it, and returns the response.
	Probe(reader string, apdu []byte) ([]byte, error)
}

// Conn is a connection to one card.
type Conn interface {
	ias.Transport
	// Close ends the transaction and resets the card, which drops the PIN status and the secure channel.
	Close() error
}

// ErrNoService is wrapped by connectors when the smart-card service is not running.
var ErrNoService = errors.New("smart-card service unavailable")

// Provider is the direct CIE provider.
type Provider struct {
	conn Connector
	// TrustAnchors replace the pinned Italian CSCA certificates (ias.ItalianCSCAs) that the card's document security
	// object must chain to. Only tests set them.
	TrustAnchors []*x509.Certificate

	mu sync.Mutex // held from Open to Close: one card session at a time

	probeMu sync.Mutex
	probed  map[string]bool // reader + ATR → answered the CIE AID
}

// New returns the provider on PC/SC.
func New() *Provider { return NewWithConnector(pcscConnector{}) }

// NewWithConnector returns the provider on another connector.
func NewWithConnector(c Connector) *Provider { return &Provider{conn: c, probed: map[string]bool{}} }

func (p *Provider) Name() string { return "cie" }

// selectCIE is SELECT of the CIE DF, without secure messaging: harmless, and answered 9000 only by a CIE.
var selectCIE = append([]byte{0x00, 0xA4, 0x04, 0x0C, byte(len(ias.CIEAID))}, ias.CIEAID...)

// isCIE recognizes the card by its ATR, or for an unlisted ATR by selecting the CIE application once.
func (p *Provider) isCIE(r Reader) (bool, string) {
	if f, name := ias.Identify(r.ATR); f != ias.FamilyUnknown {
		return true, name
	}
	key := r.Name + "/" + hex.EncodeToString(r.ATR)
	p.probeMu.Lock()
	defer p.probeMu.Unlock()
	ok, done := p.probed[key]
	if !done {
		resp, err := p.conn.Probe(r.Name, selectCIE)
		ok = err == nil && len(resp) >= 2 && resp[len(resp)-2] == 0x90 && resp[len(resp)-1] == 0x00
		if err == nil {
			p.probed[key] = ok
		}
	}
	return ok, "unlisted ATR " + strings.ToUpper(hex.EncodeToString(r.ATR))
}

func (p *Provider) Status(context.Context) token.Status {
	st := token.Status{Provider: p.Name()}
	readers, err := p.conn.Readers()
	if err != nil {
		st.Detail = err.Error()
		return st
	}
	present := false
	var notCIE []string
	for _, r := range readers {
		st.Readers = append(st.Readers, r.Name)
		if r.ATR == nil {
			continue
		}
		if ok, name := p.isCIE(r); ok {
			if !present {
				st.Detail = fmt.Sprintf("CIE (%s) on %s", name, r.Name)
			}
			present = true
		} else {
			notCIE = append(notCIE, r.Name)
		}
	}
	// Without a reader the provider still works once one is connected: only a PC/SC failure makes it unavailable.
	st.Available = true
	st.CardPresent = &present
	if len(readers) == 0 {
		st.Detail = "no smart-card reader"
	} else if !present && len(notCIE) > 0 {
		st.Detail = "the card on " + strings.Join(notCIE, ", ") + " is not a CIE"
	}
	return st
}

// pick finds the one reader holding a CIE.
func (p *Provider) pick() (Reader, error) {
	readers, err := p.conn.Readers()
	if err != nil {
		if errors.Is(err, ErrNoService) {
			return Reader{}, token.Errorf(token.CodeNoReader, "%v", err)
		}
		return Reader{}, token.Errorf(token.CodeDevice, "%v", err)
	}
	if len(readers) == 0 {
		return Reader{}, token.Errorf(token.CodeNoReader, "no smart-card reader")
	}
	var cies []Reader
	cards := 0
	for _, r := range readers {
		if r.ATR == nil {
			continue
		}
		cards++
		if ok, _ := p.isCIE(r); ok {
			cies = append(cies, r)
		}
	}
	switch {
	case len(cies) == 1:
		return cies[0], nil
	case len(cies) > 1:
		return Reader{}, token.Errorf(token.CodeDevice, "%d CIEs are present; keep only one on the readers", len(cies))
	case cards > 0:
		return Reader{}, token.Errorf(token.CodeCardUnsupported, "the card on the reader is not a CIE")
	}
	return Reader{}, token.Errorf(token.CodeNoCard, "no card on the reader")
}

func (p *Provider) Open(_ context.Context, pin string) (token.Session, error) {
	if !token.ValidPIN(pin, 8) {
		return nil, token.Errorf(token.CodePinInvalid, "the CIE PIN has 8 digits")
	}
	p.mu.Lock()
	r, err := p.pick()
	if err != nil {
		p.mu.Unlock()
		return nil, err
	}
	conn, err := p.conn.Connect(r.Name)
	if err != nil {
		p.mu.Unlock()
		return nil, classify(err, false)
	}
	card := ias.NewCard(conn, r.ATR)
	card.TrustAnchors = p.TrustAnchors
	if err := card.Authenticate(pin); err != nil {
		_ = conn.Close()
		p.mu.Unlock()
		return nil, classify(err, card.PINSent())
	}
	return &session{p: p, conn: conn, card: card}, nil
}

// classify maps protocol errors to token errors. Failures before the PIN reached the card mean the card does not
// behave like a CIE, which lets the agent try another provider; failures after it are marked token.PINSent.
func classify(err error, pinSent bool) error {
	out := classifyCode(err, pinSent)
	if pinSent {
		return token.AfterPIN(out)
	}
	return out
}

func classifyCode(err error, pinSent bool) error {
	var pe *ias.PINError
	var se *ias.StatusError
	var proto *ias.ProtocolError
	var trust *ias.TrustError
	switch {
	case errors.As(err, &trust):
		return token.Errorf(token.CodeCardUntrusted, "%v", err)
	case errors.Is(err, ias.ErrCardRemoved):
		return token.Errorf(token.CodeCardRemoved, "%v", err)
	case errors.As(err, &pe):
		switch {
		case pe.Locked():
			return token.Errorf(token.CodePinLocked, "%v", err)
		case pe.SW == ias.SWWrongLength:
			return token.Errorf(token.CodePinInvalid, "%v", err)
		}
		return &token.Error{Code: token.CodePinIncorrect, RetriesLeft: pe.Retries(), Err: err}
	case errors.Is(err, ErrNoService):
		return token.Errorf(token.CodeNoReader, "%v", err)
	case !pinSent && (errors.As(err, &se) || errors.As(err, &proto)):
		return token.Errorf(token.CodeCardUnsupported, "%v", err)
	}
	return token.Errorf(token.CodeDevice, "%v", err)
}

// session holds p.mu until Close.
type session struct {
	p      *Provider
	conn   Conn
	card   *ias.Card
	closed bool
}

func (s *session) Certificate() *x509.Certificate { return s.card.Certificate() }
func (s *session) Chain() []*x509.Certificate     { return nil }

func (s *session) SignDigest(_ context.Context, digest []byte) ([]byte, error) {
	input, err := token.DigestInfoSHA256(digest)
	if err != nil {
		return nil, token.Errorf(token.CodeDevice, "%v", err)
	}
	sig, err := s.card.Sign(input)
	if err != nil {
		return nil, classify(err, true)
	}
	pub, ok := s.card.Certificate().PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, token.Errorf(token.CodeDevice, "the certificate key is not RSA")
	}
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest, sig); err != nil {
		return nil, token.Errorf(token.CodeDevice, "the card's signature does not verify with its certificate: %v", err)
	}
	return sig, nil
}

func (s *session) Close() error {
	if s.closed {
		return nil
	}
	s.closed = true
	err := s.conn.Close()
	s.p.mu.Unlock()
	return err
}
