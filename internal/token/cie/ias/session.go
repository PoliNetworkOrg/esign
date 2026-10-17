package ias

import (
	"crypto/x509"
	"errors"
	"fmt"
)

// PINError is a VERIFY failure.
type PINError struct {
	SW uint16
}

func (e *PINError) Error() string {
	switch {
	case e.Locked():
		return "PIN blocked (6983)"
	case e.SW == SWWrongLength:
		return "PIN rejected as malformed (6700)"
	}
	if n := e.Retries(); n >= 0 {
		return fmt.Sprintf("wrong PIN, %d attempts left (%04X)", n, e.SW)
	}
	return fmt.Sprintf("wrong PIN (%04X)", e.SW)
}

// Locked reports a blocked PIN.
func (e *PINError) Locked() bool { return e.SW == SWPinLocked }

// Retries is the number of attempts left from 63Cx, or -1 when the card did not say.
func (e *PINError) Retries() int {
	if e.SW&0xFFF0 == 0x63C0 {
		return int(e.SW & 0x0F)
	}
	return -1
}

// ErrNotAuthenticated is returned by Sign before Authenticate succeeded.
var ErrNotAuthenticated = errors.New("card session not authenticated")

// Authenticate runs the reference's login sequence (PKCS11/CIEP11Template.cpp CIEtemplateLogin) and then reads the
// certificate: select IAS and read EF.DH, select the CIE DF, read the DH parameters and EF 1004, check them against
// the document security object (VerifySOD; a *TrustError otherwise), read the CV root key, DH key agreement, DAPP,
// VERIFY with the full eight-digit PIN, and EF 1003 through the secure channel. A wrong PIN is reported as a
// *PINError after one attempt; nothing is retried.
func (c *Card) Authenticate(pin string) error {
	if len(pin) != 8 {
		return errors.New("the CIE PIN has 8 digits")
	}
	for _, r := range pin {
		if r < '0' || r > '9' {
			return errors.New("the CIE PIN has 8 digits")
		}
	}
	steps := []func() error{c.SelectIAS, c.readDHFile, c.SelectCIE, c.initDH, c.readIntAuthKey, c.verifySOD, c.readRootKey, c.keyExchange, c.dapp}
	for _, step := range steps {
		if err := step(); err != nil {
			var proto *ProtocolError
			if errors.As(err, &proto) && c.sm != nil {
				// A malformed or unauthenticated answer once the secure channel exists, or a chip that fails DAPP:
				// the card cannot be trusted with the PIN.
				return &TrustError{Err: err}
			}
			return err
		}
	}
	if err := c.verifyPIN(pin); err != nil {
		return err
	}
	c.authenticated = true
	der, err := c.ReadFile(FileCertificate)
	if err != nil {
		return err
	}
	n, err := EncodedLength(der)
	if err != nil {
		return &ProtocolError{Op: "certificate", Err: err}
	}
	c.certDER = der[:n]
	if c.cert, err = x509.ParseCertificate(c.certDER); err != nil {
		return &ProtocolError{Op: "certificate", Err: err}
	}
	return nil
}

// verifyPIN sends VERIFY with the PIN as eight ASCII digits, never BCD, through the secure channel.
func (c *Card) verifyPIN(pin string) error {
	c.pinSent = true
	_, sw, err := c.send("VERIFY", command{cla: 0x00, ins: 0x20, p1: 0x00, p2: pinRef, data: []byte(pin)})
	if err != nil {
		return err
	}
	switch {
	case sw == SWOK:
		return nil
	case sw&0xFFF0 == 0x63C0, sw == SWWrongPinNoInfo, sw == SWPinLocked, sw == SWWrongLength:
		return &PINError{SW: sw}
	}
	return &StatusError{Op: "VERIFY", SW: sw}
}

// PINSent reports whether a VERIFY reached the card: from then on a failure may have used a PIN attempt, and the
// caller must not fall back to another way of signing.
func (c *Card) PINSent() bool { return c.pinSent }

// Certificate is the citizen authentication certificate read during Authenticate.
func (c *Card) Certificate() *x509.Certificate { return c.cert }

// Sign has the card sign a DigestInfo with the citizen key: MSE SET AT 80 01 02 84 01 81, then INTERNAL
// AUTHENTICATE with the DigestInfo (CSP/IAS.cpp IAS::Sign). The card applies PKCS#1 v1.5 padding.
func (c *Card) Sign(digestInfo []byte) ([]byte, error) {
	if !c.authenticated || c.sm == nil {
		return nil, ErrNotAuthenticated
	}
	set := append(EncodeTLV(0x80, []byte{0x02}), EncodeTLV(0x84, []byte{keySign})...)
	if _, err := c.expect("MSE SET signature key", command{cla: 0x00, ins: 0x22, p1: 0x41, p2: 0xA4, data: set}); err != nil {
		return nil, err
	}
	return c.expect("INTERNAL AUTHENTICATE", command{cla: 0x00, ins: 0x88, p1: 0x00, p2: 0x00, data: digestInfo})
}
