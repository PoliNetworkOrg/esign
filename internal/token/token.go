// Package token abstracts the devices that hold a signing key: the CIE through the official middleware (PKCS#11),
// the CIE spoken to directly over PC/SC, or a software key for development.
package token

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
)

// Provider is one way to reach a signing key: a PKCS#11 module, the card over PC/SC, or a software key.
type Provider interface {
	// Name identifies the provider ("cie-mw", "opencie", "cie", "soft").
	Name() string
	// Status reports whether the provider can be used right now, without touching the PIN.
	Status(ctx context.Context) Status
	// Open authenticates to the card with the PIN, as the user typed it (8 digits for a CIE), and returns a session
	// holding the signing certificate. Callers must Close it.
	Open(ctx context.Context, pin string) (Session, error)
}

// Session is an authenticated card session.
type Session interface {
	// Certificate is the signer's certificate.
	Certificate() *x509.Certificate
	// Chain is the issuing certificates the device knows, possibly none.
	Chain() []*x509.Certificate
	// SignDigest returns the RSA PKCS#1 v1.5 signature of a SHA-256 digest.
	SignDigest(ctx context.Context, digest []byte) ([]byte, error)
	Close() error
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

// Code classifies errors so the dashboard can explain them.
type Code string

const (
	CodeNoReader          Code = "no_reader"
	CodeNoCard            Code = "no_card"
	CodeCardUnsupported   Code = "card_unsupported"
	CodeMiddlewareMissing Code = "middleware_missing"
	CodeNotPaired         Code = "not_paired"
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
	// PINSent is true when the failure happened at or after the moment the PIN reached the module or the card
	// (C_Login, VERIFY, a pairing call): an attempt may have been used, so no other provider may be tried with it.
	PINSent bool
	Err     error
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

// AfterPIN marks err as happening after the PIN was sent (see Error.PINSent), classifying it as CodeDevice when it
// is not a token error yet. It returns nil for nil.
func AfterPIN(err error) error {
	if err == nil {
		return nil
	}
	var e *Error
	if errors.As(err, &e) {
		c := *e
		c.PINSent = true
		return &c
	}
	return &Error{Code: CodeDevice, RetriesLeft: -1, PINSent: true, Err: err}
}

// PINSent reports whether err happened after the PIN reached a module or card.
func PINSent(err error) bool {
	var e *Error
	return errors.As(err, &e) && e.PINSent
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
