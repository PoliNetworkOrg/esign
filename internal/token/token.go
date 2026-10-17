// Package token abstracts the devices that hold a signing key: the CIE through the official middleware (PKCS#11),
// the CIE spoken to directly over PC/SC, or a software key for development.
package token

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
)

// Certificate is a signing certificate a provider can use.
type Certificate struct {
	// ID is stable for the same certificate on the same provider: "<provider>:<sha256 of the DER, hex>".
	ID       string
	Provider string
	// Label describes the token for people, e.g. "CIE (middleware)".
	Label string
	Cert  *x509.Certificate
}

// Provider is one source of signing keys.
type Provider interface {
	// Name identifies the provider in certificate IDs and status ("pkcs11", "cie", "soft").
	Name() string
	// Status reports whether the provider can be used right now, without touching the PIN.
	Status(ctx context.Context) Status
	// Certificates lists the signing certificates currently available. It never needs the PIN.
	Certificates(ctx context.Context) ([]Certificate, error)
	// SignDigest returns the RSA PKCS#1 v1.5 signature of a SHA-256 digest with the key of the certificate.
	SignDigest(ctx context.Context, certID string, digest []byte, pin string) ([]byte, error)
}

// Status is a provider's availability.
type Status struct {
	Provider  string `json:"provider"`
	Available bool   `json:"available"`
	// Detail explains an unavailable provider or names the device in use.
	Detail string `json:"detail,omitempty"`
	// Readers lists the smart-card readers the provider sees, when it knows them.
	Readers []string `json:"readers,omitempty"`
	// CardPresent is true when a card is on a reader, when the provider can tell.
	CardPresent *bool `json:"cardPresent,omitempty"`
}

// CertificateID is the stable ID of cert on provider.
func CertificateID(provider string, cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return provider + ":" + hex.EncodeToString(sum[:])
}

// Code classifies errors so the dashboard can explain them.
type Code string

const (
	CodeNoReader          Code = "no_reader"
	CodeNoCard            Code = "no_card"
	CodeCardUnsupported   Code = "card_unsupported"
	CodeMiddlewareMissing Code = "middleware_missing"
	CodeNotFound          Code = "certificate_not_found"
	CodePinIncorrect      Code = "pin_incorrect"
	CodePinLocked         Code = "pin_locked"
	CodePinInvalid        Code = "pin_invalid"
	CodeCardRemoved       Code = "card_removed"
	CodeBusy              Code = "busy"
	CodeDevice            Code = "device_error"
)

// Error is a classified provider error.
type Error struct {
	Code Code
	// RetriesLeft is set for CodePinIncorrect when the card reports it; -1 when unknown.
	RetriesLeft int
	Err         error
}

func (e *Error) Error() string {
	if e.Err == nil {
		return string(e.Code)
	}
	return fmt.Sprintf("%s: %v", e.Code, e.Err)
}

func (e *Error) Unwrap() error { return e.Err }

// Errorf builds a classified error.
func Errorf(code Code, format string, args ...any) *Error {
	return &Error{Code: code, RetriesLeft: -1, Err: fmt.Errorf(format, args...)}
}

// CodeOf returns the code of err, or CodeDevice for unclassified errors.
func CodeOf(err error) Code {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return CodeDevice
}

// ValidPIN reports whether pin has the CIE format: 8 digits. Other tokens use the same rule loosely (4–16 digits).
func ValidPIN(pin string, exactLength int) bool {
	if exactLength > 0 && len(pin) != exactLength {
		return false
	}
	if len(pin) < 4 || len(pin) > 16 {
		return false
	}
	for _, r := range pin {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// sha256DigestInfoPrefix is the DER DigestInfo header for SHA-256 (RFC 8017 §9.2 note 1).
var sha256DigestInfoPrefix = []byte{0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20}

// DigestInfoSHA256 wraps a SHA-256 digest in its DER DigestInfo, the input of a raw PKCS#1 v1.5 (CKM_RSA_PKCS) signature.
func DigestInfoSHA256(digest []byte) ([]byte, error) {
	if len(digest) != sha256.Size {
		return nil, fmt.Errorf("digest must be %d bytes, got %d", sha256.Size, len(digest))
	}
	return append(append([]byte{}, sha256DigestInfoPrefix...), digest...), nil
}
