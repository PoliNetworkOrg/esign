// Package p11 signs through a PKCS#11 module: the official CIE middleware ("CIE ID" / "Software CIE"), OpenCIE, or
// any other module such as SoftHSM2 in tests.
package p11

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"os"
	"sync"

	"github.com/miekg/pkcs11"

	"github.com/PoliNetworkOrg/sign-agent/internal/token"
)

// Provider is a PKCS#11 module.
type Provider struct {
	opts Options
	path string

	mu  sync.Mutex
	ctx *pkcs11.Ctx
}

// Options configures a provider.
type Options struct {
	// Name of the provider; "pkcs11" by default.
	Name string
	// Path of the module; the first existing entry of Candidates when empty.
	Path       string
	Candidates []string
	// PIN turns the PIN the user typed into what C_Login expects, e.g. the last four digits for the official CIE
	// middleware after pairing. Nil passes it unchanged.
	PIN func(string) string
	// PINLength the user's PIN must have; 0 accepts 4–16 digits.
	PINLength int
	// Pair lists the module's exported pairing functions, tried in order (see OfficialPairing, OpenCIEPairing).
	// When set and the card turns out not to be paired, Open pairs it with the full PIN and opens again, once.
	Pair []string
}

// LastFour is the official CIE middleware's login PIN: it keeps the first four digits from pairing.
func LastFour(pin string) string {
	if len(pin) == 8 {
		return pin[4:]
	}
	return pin
}

// New returns a provider. It does not load the module until first use.
func New(opts Options) *Provider {
	if opts.Name == "" {
		opts.Name = "pkcs11"
	}
	path := opts.Path
	if path == "" {
		for _, c := range opts.Candidates {
			if _, err := os.Stat(c); err == nil {
				path = c
				break
			}
		}
	}
	return &Provider{opts: opts, path: path}
}

func (p *Provider) Name() string { return p.opts.Name }

// Path is the module in use, or "" when none was found.
func (p *Provider) Path() string { return p.path }

// load initializes the module once. Callers hold p.mu.
func (p *Provider) load() (*pkcs11.Ctx, error) {
	if p.ctx != nil {
		return p.ctx, nil
	}
	if p.path == "" {
		return nil, token.Errorf(token.CodeMiddlewareMissing, "PKCS#11 module not found")
	}
	ctx := pkcs11.New(p.path)
	if ctx == nil {
		return nil, token.Errorf(token.CodeMiddlewareMissing, "cannot load %s", p.path)
	}
	if err := ctx.Initialize(); err != nil && !isCode(err, pkcs11.CKR_CRYPTOKI_ALREADY_INITIALIZED) {
		ctx.Destroy()
		return nil, token.Errorf(token.CodeMiddlewareMissing, "initialize %s: %v", p.path, err)
	}
	p.ctx = ctx
	return ctx, nil
}

// reset drops the module after a device error, so readers plugged in later are seen. Callers hold p.mu.
func (p *Provider) reset() {
	if p.ctx == nil {
		return
	}
	_ = p.ctx.Finalize()
	p.ctx.Destroy()
	p.ctx = nil
}

// Close finalizes the module.
func (p *Provider) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.reset()
}

func (p *Provider) Status(context.Context) token.Status {
	p.mu.Lock()
	defer p.mu.Unlock()
	st := token.Status{Provider: p.opts.Name}
	ctx, err := p.load()
	if err != nil {
		st.Detail = err.Error()
		return st
	}
	all, err := ctx.GetSlotList(false)
	if err != nil {
		p.reset()
		st.Detail = err.Error()
		return st
	}
	present := false
	for _, slot := range all {
		if info, err := ctx.GetSlotInfo(slot); err == nil {
			st.Readers = append(st.Readers, trim(info.SlotDescription))
			if info.Flags&pkcs11.CKF_TOKEN_PRESENT != 0 {
				present = true
			}
		}
	}
	st.CardPresent = &present
	st.Available = true
	st.Detail = p.path
	return st
}

// slot returns the single slot holding an initialized token.
func (p *Provider) slot(ctx *pkcs11.Ctx) (uint, error) {
	slots, err := ctx.GetSlotList(true)
	if err != nil {
		p.reset()
		return 0, classify(err)
	}
	var usable []uint
	for _, slot := range slots {
		if info, err := ctx.GetTokenInfo(slot); err == nil && info.Flags&pkcs11.CKF_TOKEN_INITIALIZED == 0 {
			continue
		}
		usable = append(usable, slot)
	}
	switch len(usable) {
	case 0:
		if all, _ := ctx.GetSlotList(false); len(all) == 0 {
			return 0, token.Errorf(token.CodeNoReader, "no reader")
		}
		return 0, token.Errorf(token.CodeNoCard, "no card")
	case 1:
		return usable[0], nil
	default:
		return 0, token.Errorf(token.CodeDevice, "%d cards are present; keep only one on the readers", len(usable))
	}
}

func (p *Provider) Open(_ context.Context, pin string) (token.Session, error) {
	if !token.ValidPIN(pin, p.opts.PINLength) {
		return nil, token.Errorf(token.CodePinInvalid, "malformed PIN")
	}
	p.mu.Lock()
	s, err := p.open(pin)
	var unpaired *unpairedError
	if errors.As(err, &unpaired) {
		s, err = p.pairAndOpen(pin, unpaired)
	}
	if err != nil {
		p.mu.Unlock()
		return nil, err
	}
	return s, nil
}

// unpairedError is a failure that a missing pairing explains: the official middleware fails C_OpenSession (its
// session setup reads the certificate from the pairing cache), and OpenCIE likewise; a module could also show a
// token without a certificate. No PIN has reached the card.
type unpairedError struct {
	err error // classified
}

func (e *unpairedError) Error() string { return e.err.Error() }
func (e *unpairedError) Unwrap() error { return e.err }

// open logs in and finds the key. Callers hold p.mu; it stays held when a session is returned.
func (p *Provider) open(pin string) (*session11, error) {
	ctx, err := p.load()
	if err != nil {
		return nil, err
	}
	slot, err := p.slot(ctx)
	if err != nil {
		return nil, err
	}
	session, err := ctx.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION)
	if err != nil {
		if isCode(err, pkcs11.CKR_GENERAL_ERROR) || isCode(err, pkcs11.CKR_FUNCTION_FAILED) || isCode(err, pkcs11.CKR_TOKEN_NOT_RECOGNIZED) {
			return nil, &unpairedError{err: classify(err)}
		}
		return nil, classify(err)
	}
	s := &session11{p: p, ctx: ctx, session: session}
	login := pin
	if p.opts.PIN != nil {
		login = p.opts.PIN(pin)
	}
	// From C_Login on, the PIN has reached the module: every failure is marked so that no other provider is tried.
	if err := ctx.Login(session, pkcs11.CKU_USER, login); err != nil && !isCode(err, pkcs11.CKR_USER_ALREADY_LOGGED_IN) {
		s.release()
		return nil, token.AfterPIN(pinError(err))
	}
	s.loggedIn = true
	certs, err := certificates(ctx, session)
	if err != nil {
		s.release()
		return nil, token.AfterPIN(err)
	}
	if len(certs) == 0 {
		s.release()
		return nil, token.AfterPIN(token.Errorf(token.CodeNotFound, "no signing certificate on the card"))
	}
	s.cert = certs[0].cert
	if s.key, err = privateKey(ctx, session, certs[0].id); err != nil {
		s.release()
		return nil, token.AfterPIN(err)
	}
	return s, nil
}

// session11 holds p.mu from Open until Close: the module and the card serve one operation at a time.
type session11 struct {
	p        *Provider
	ctx      *pkcs11.Ctx
	session  pkcs11.SessionHandle
	loggedIn bool
	cert     *x509.Certificate
	key      pkcs11.ObjectHandle
	closed   bool
}

func (s *session11) Certificate() *x509.Certificate { return s.cert }
func (s *session11) Chain() []*x509.Certificate     { return nil }

func (s *session11) SignDigest(_ context.Context, digest []byte) ([]byte, error) {
	input, err := token.DigestInfoSHA256(digest)
	if err != nil {
		return nil, token.Errorf(token.CodeDevice, "%v", err)
	}
	if err := s.ctx.SignInit(s.session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)}, s.key); err != nil {
		return nil, classify(err)
	}
	sig, err := s.ctx.Sign(s.session, input)
	if err != nil {
		// The official middleware re-verifies the PIN while signing and reports any failure as CKR_PIN_INCORRECT.
		return nil, pinError(err)
	}
	return sig, nil
}

func (s *session11) Close() error {
	if s.closed {
		return nil
	}
	s.release()
	s.p.mu.Unlock()
	return nil
}

// release logs out and closes the PKCS#11 session, keeping p.mu.
func (s *session11) release() {
	s.closed = true
	if s.loggedIn {
		_ = s.ctx.Logout(s.session)
	}
	_ = s.ctx.CloseSession(s.session)
}

type found struct {
	id   []byte
	cert *x509.Certificate
}

func certificates(ctx *pkcs11.Ctx, session pkcs11.SessionHandle) ([]found, error) {
	objects, err := findAll(ctx, session, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE),
		pkcs11.NewAttribute(pkcs11.CKA_CERTIFICATE_TYPE, pkcs11.CKC_X_509),
	})
	if err != nil {
		return nil, err
	}
	var out []found
	for _, obj := range objects {
		attrs, err := ctx.GetAttributeValue(session, obj, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil),
			pkcs11.NewAttribute(pkcs11.CKA_ID, nil),
		})
		if err != nil {
			continue
		}
		cert, err := x509.ParseCertificate(attrs[0].Value)
		if err != nil || cert.IsCA {
			continue
		}
		out = append(out, found{id: attrs[1].Value, cert: cert})
	}
	return out, nil
}

// privateKey finds the private key paired with the certificate's CKA_ID, or the only private key on the token.
func privateKey(ctx *pkcs11.Ctx, session pkcs11.SessionHandle, id []byte) (pkcs11.ObjectHandle, error) {
	keys, err := findAll(ctx, session, []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY)})
	if err != nil {
		return 0, err
	}
	if len(keys) == 1 {
		return keys[0], nil
	}
	for _, k := range keys {
		attrs, err := ctx.GetAttributeValue(session, k, []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_ID, nil)})
		if err == nil && len(id) > 0 && bytes.Equal(attrs[0].Value, id) {
			return k, nil
		}
	}
	return 0, token.Errorf(token.CodeNotFound, "no private key for the certificate (%d keys)", len(keys))
}

func findAll(ctx *pkcs11.Ctx, session pkcs11.SessionHandle, template []*pkcs11.Attribute) ([]pkcs11.ObjectHandle, error) {
	if err := ctx.FindObjectsInit(session, template); err != nil {
		return nil, classify(err)
	}
	defer ctx.FindObjectsFinal(session)
	var out []pkcs11.ObjectHandle
	for {
		objs, _, err := ctx.FindObjects(session, 16)
		if err != nil {
			return nil, classify(err)
		}
		if len(objs) == 0 {
			return out, nil
		}
		out = append(out, objs...)
	}
}

// pinError classifies a failed login. The CIE middleware's token flags are static, so remaining attempts are unknown.
func pinError(err error) error {
	switch {
	case isCode(err, pkcs11.CKR_PIN_INCORRECT):
		return &token.Error{Code: token.CodePinIncorrect, RetriesLeft: -1, Err: err}
	case isCode(err, pkcs11.CKR_PIN_LOCKED):
		return token.Errorf(token.CodePinLocked, "%v", err)
	case isCode(err, pkcs11.CKR_PIN_LEN_RANGE), isCode(err, pkcs11.CKR_PIN_INVALID):
		return token.Errorf(token.CodePinInvalid, "%v", err)
	}
	return classify(err)
}

func classify(err error) error {
	switch {
	case isCode(err, pkcs11.CKR_TOKEN_NOT_PRESENT), isCode(err, pkcs11.CKR_DEVICE_REMOVED), isCode(err, pkcs11.CKR_SESSION_HANDLE_INVALID), isCode(err, pkcs11.CKR_SESSION_CLOSED):
		return token.Errorf(token.CodeCardRemoved, "%v", err)
	case isCode(err, pkcs11.CKR_TOKEN_NOT_RECOGNIZED):
		return token.Errorf(token.CodeNotPaired, "%v", err)
	case isCode(err, pkcs11.CKR_PIN_LOCKED):
		return token.Errorf(token.CodePinLocked, "%v", err)
	}
	return token.Errorf(token.CodeDevice, "%v", err)
}

func isCode(err error, code uint) bool {
	var e pkcs11.Error
	return errors.As(err, &e) && uint(e) == code
}

func trim(s string) string { return string(bytes.TrimRight([]byte(s), " \x00")) }
