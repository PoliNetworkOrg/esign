// Package p11 signs through a PKCS#11 module: the official CIE middleware ("CIE ID"), or any other module such as
// SoftHSM2 in tests.
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
	name   string
	label  string
	path   string
	pinLen int

	mu  sync.Mutex
	ctx *pkcs11.Ctx
}

// Options configures a provider.
type Options struct {
	// Name in certificate IDs; "pkcs11" by default.
	Name string
	// Label shown for its certificates, e.g. "CIE (middleware)".
	Label string
	// Path of the module; the first existing entry of Candidates when empty.
	Path       string
	Candidates []string
	// PINLength the PIN must have; 0 accepts 4–16 digits.
	PINLength int
}

// New returns a provider. It does not load the module until first use.
func New(opts Options) *Provider {
	if opts.Name == "" {
		opts.Name = "pkcs11"
	}
	if opts.Label == "" {
		opts.Label = "PKCS#11 token"
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
	return &Provider{name: opts.Name, label: opts.Label, path: path, pinLen: opts.PINLength}
}

func (p *Provider) Name() string { return p.name }

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
	st := token.Status{Provider: p.name}
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

type found struct {
	slot uint
	id   []byte
	cert *x509.Certificate
}

// scan lists the certificates on every token. Callers hold p.mu.
func (p *Provider) scan() ([]found, error) {
	ctx, err := p.load()
	if err != nil {
		return nil, err
	}
	slots, err := ctx.GetSlotList(true)
	if err != nil {
		p.reset()
		return nil, classify(err)
	}
	if len(slots) == 0 {
		all, _ := ctx.GetSlotList(false)
		if len(all) == 0 {
			return nil, token.Errorf(token.CodeNoReader, "no reader")
		}
		return nil, token.Errorf(token.CodeNoCard, "no card")
	}
	var out []found
	var firstErr error
	for _, slot := range slots {
		if info, err := ctx.GetTokenInfo(slot); err == nil && info.Flags&pkcs11.CKF_TOKEN_INITIALIZED == 0 {
			continue
		}
		certs, err := p.slotCertificates(ctx, slot)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		out = append(out, certs...)
	}
	if len(out) == 0 && firstErr != nil {
		return nil, firstErr
	}
	return out, nil
}

func (p *Provider) slotCertificates(ctx *pkcs11.Ctx, slot uint) ([]found, error) {
	session, err := ctx.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION)
	if err != nil {
		return nil, classify(err)
	}
	defer ctx.CloseSession(session)
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
		out = append(out, found{slot: slot, id: attrs[1].Value, cert: cert})
	}
	return out, nil
}

func (p *Provider) Certificates(context.Context) ([]token.Certificate, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	certs, err := p.scan()
	if err != nil {
		return nil, err
	}
	out := make([]token.Certificate, 0, len(certs))
	for _, c := range certs {
		out = append(out, token.Certificate{ID: token.CertificateID(p.name, c.cert), Provider: p.name, Label: p.label, Cert: c.cert})
	}
	return out, nil
}

func (p *Provider) SignDigest(_ context.Context, certID string, digest []byte, pin string) ([]byte, error) {
	if !token.ValidPIN(pin, p.pinLen) {
		return nil, token.Errorf(token.CodePinInvalid, "malformed PIN")
	}
	input, err := token.DigestInfoSHA256(digest)
	if err != nil {
		return nil, token.Errorf(token.CodeDevice, "%v", err)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	certs, err := p.scan()
	if err != nil {
		return nil, err
	}
	var target *found
	for i := range certs {
		if token.CertificateID(p.name, certs[i].cert) == certID {
			target = &certs[i]
			break
		}
	}
	if target == nil {
		return nil, token.Errorf(token.CodeNotFound, "certificate %s is not on any card", certID)
	}
	ctx := p.ctx
	session, err := ctx.OpenSession(target.slot, pkcs11.CKF_SERIAL_SESSION)
	if err != nil {
		return nil, classify(err)
	}
	defer ctx.CloseSession(session)

	if err := ctx.Login(session, pkcs11.CKU_USER, pin); err != nil && !isCode(err, pkcs11.CKR_USER_ALREADY_LOGGED_IN) {
		return nil, p.pinError(ctx, target.slot, err)
	}
	defer ctx.Logout(session)

	key, err := privateKey(ctx, session, target.id)
	if err != nil {
		return nil, err
	}
	if err := ctx.SignInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)}, key); err != nil {
		return nil, classify(err)
	}
	sig, err := ctx.Sign(session, input)
	if err != nil {
		return nil, classify(err)
	}
	return sig, nil
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

// pinError classifies a failed login, reading the token flags for the remaining attempts.
func (p *Provider) pinError(ctx *pkcs11.Ctx, slot uint, err error) error {
	switch {
	case isCode(err, pkcs11.CKR_PIN_INCORRECT):
		left := -1
		if info, e := ctx.GetTokenInfo(slot); e == nil {
			switch {
			case info.Flags&pkcs11.CKF_USER_PIN_LOCKED != 0:
				return token.Errorf(token.CodePinLocked, "PIN locked")
			case info.Flags&pkcs11.CKF_USER_PIN_FINAL_TRY != 0:
				left = 1
			case info.Flags&pkcs11.CKF_USER_PIN_COUNT_LOW != 0:
				left = 2
			}
		}
		return &token.Error{Code: token.CodePinIncorrect, RetriesLeft: left, Err: err}
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
		return token.Errorf(token.CodeCardUnsupported, "%v", err)
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

