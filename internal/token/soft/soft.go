// Package soft is a software token for development and tests: an RSA key with a CIE-shaped certificate issued by a
// local development CA, protected by a PIN with three attempts like the CIE. Signatures it makes are not legally valid.
package soft

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/PoliNetworkOrg/sign-agent/internal/token"
)

// DefaultPIN is the PIN of a newly created software token.
const DefaultPIN = "12345678"

const maxAttempts = 3

// Provider is the software token.
type Provider struct {
	mu       sync.Mutex
	key      *rsa.PrivateKey
	cert     *x509.Certificate
	chain    []*x509.Certificate
	pin      string
	attempts int
}

// Open loads the software token from dir, creating it on first use.
func Open(dir, pin string) (*Provider, error) {
	if pin == "" {
		pin = DefaultPIN
	}
	keyPath := filepath.Join(dir, "key.pem")
	certPath := filepath.Join(dir, "cert.pem")
	caPath := filepath.Join(dir, "ca.pem")
	if _, err := os.Stat(keyPath); errors.Is(err, os.ErrNotExist) {
		if err := create(dir, keyPath, certPath, caPath); err != nil {
			return nil, fmt.Errorf("create software token: %w", err)
		}
	}
	key, err := readKey(keyPath)
	if err != nil {
		return nil, err
	}
	cert, err := readCert(certPath)
	if err != nil {
		return nil, err
	}
	ca, err := readCert(caPath)
	if err != nil {
		return nil, err
	}
	return &Provider{key: key, cert: cert, chain: []*x509.Certificate{ca}, pin: pin}, nil
}

// New builds an in-memory software token, for tests.
func New(pin string) (*Provider, error) {
	ca, key, cert, err := generate()
	if err != nil {
		return nil, err
	}
	return &Provider{key: key, cert: cert, chain: []*x509.Certificate{ca}, pin: pin}, nil
}

func (p *Provider) Name() string { return "soft" }

func (p *Provider) Status(context.Context) token.Status {
	present := true
	return token.Status{Provider: p.Name(), Available: true, CardPresent: &present, Detail: "Software development key (not a CIE)"}
}

// Certificate is the token's certificate, for tests.
func (p *Provider) Certificate() *x509.Certificate { return p.cert }

func (p *Provider) Open(_ context.Context, pin string) (token.Session, error) {
	if !token.ValidPIN(pin, 8) {
		return nil, token.Errorf(token.CodePinInvalid, "the PIN must be 8 digits")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	// From here on the PIN has reached the token.
	if p.attempts >= maxAttempts {
		return nil, token.AfterPIN(token.Errorf(token.CodePinLocked, "PIN blocked after %d wrong attempts", maxAttempts))
	}
	if pin != p.pin {
		p.attempts++
		left := maxAttempts - p.attempts
		if left == 0 {
			return nil, token.AfterPIN(token.Errorf(token.CodePinLocked, "PIN blocked after %d wrong attempts", maxAttempts))
		}
		return nil, &token.Error{Code: token.CodePinIncorrect, RetriesLeft: left, PINSent: true, Err: errors.New("wrong PIN")}
	}
	p.attempts = 0
	return &session{p: p}, nil
}

type session struct{ p *Provider }

func (s *session) Certificate() *x509.Certificate { return s.p.cert }
func (s *session) Chain() []*x509.Certificate     { return s.p.chain }
func (s *session) Close() error                   { return nil }

func (s *session) SignDigest(_ context.Context, digest []byte) ([]byte, error) {
	if len(digest) != crypto.SHA256.Size() {
		return nil, token.Errorf(token.CodeDevice, "digest must be %d bytes", crypto.SHA256.Size())
	}
	return rsa.SignPKCS1v15(rand.Reader, s.p.key, crypto.SHA256, digest)
}

var oidSerialNumber = asn1.ObjectIdentifier{2, 5, 4, 5}

func generate() (ca *x509.Certificate, key *rsa.PrivateKey, cert *x509.Certificate, err error) {
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return
	}
	now := time.Now()
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "PoliNetwork Sign Agent Development CA", Organization: []string{"PoliNetwork APS (development)"}, Country: []string{"IT"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return
	}
	if ca, err = x509.ParseCertificate(caDER); err != nil {
		return
	}

	key, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	if err != nil {
		return
	}
	// Shaped like a CIE authentication certificate: CN "SURNAME NAME", serialNumber "TINIT-<fiscal code>".
	leafTemplate := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: "SVILUPPO PROVA",
			Country:    []string{"IT"},
			ExtraNames: []pkix.AttributeTypeAndValue{
				{Type: asn1.ObjectIdentifier{2, 5, 4, 4}, Value: "SVILUPPO"},
				{Type: asn1.ObjectIdentifier{2, 5, 4, 42}, Value: "PROVA"},
				{Type: oidSerialNumber, Value: "TINIT-SVLPRV80A01F205X"},
			},
		},
		NotBefore: now.Add(-time.Hour),
		NotAfter:  now.AddDate(5, 0, 0),
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, ca, &key.PublicKey, caKey)
	if err != nil {
		return
	}
	cert, err = x509.ParseCertificate(leafDER)
	return
}

func create(dir, keyPath, certPath, caPath string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	ca, key, cert, err := generate()
	if err != nil {
		return err
	}
	keyDER := x509.MarshalPKCS1PrivateKey(key)
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0o644); err != nil {
		return err
	}
	return os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw}), 0o644)
}

func readKey(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("%s: no PEM block", path)
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func readCert(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("%s: no PEM block", path)
	}
	return x509.ParseCertificate(block.Bytes)
}
