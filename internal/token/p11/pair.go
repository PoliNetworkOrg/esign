package p11

import (
	"errors"
	"runtime"

	"github.com/miekg/pkcs11"

	"github.com/PoliNetworkOrg/sign-agent/internal/token"
)

// The official middleware and OpenCIE keep the certificate and the first four PIN digits in a local cache written by
// "pairing" with the full PIN (official CSP/AbilitaCIE.cpp, OpenCIE pkcs11/src/csp/cie_enable.cpp). Without it
// their PKCS#11 session setup fails before any PIN is asked. Both export the pairing function with the signature
//
//	CK_RV f(const char *pan, const char *pin, int *attempts, PROGRESS_CALLBACK, COMPLETED_CALLBACK)
//
// The PAN may be NULL: the function pairs the card it finds on the readers (the Windows build would otherwise
// compare it with the card's NIS). The callbacks must not be NULL in the official build; ours do nothing.

// OfficialPairing names the official middleware's pairing export: AbbinaCIE in CIEPKI.dll (AbilitaCIE there is a
// rundll32 GUI entry point), AbilitaCIE in libcie-pkcs11 on Linux and macOS.
func OfficialPairing() []string {
	if runtime.GOOS == "windows" {
		return []string{"AbbinaCIE"}
	}
	return []string{"AbilitaCIE"}
}

// OpenCIEPairing names OpenCIE's pairing export.
func OpenCIEPairing() []string { return []string{"cie_enable"} }

// cardAlreadyEnabled is returned by the pairing functions when the card is already paired, before any PIN is sent.
const cardAlreadyEnabled = 0xF0

var errNoPairing = errors.New("the module exports no pairing function")

// pairAndOpen pairs the card with the full PIN, then opens again once. A pairing attempt with a wrong PIN uses one of
// the card's attempts: it is reported and never repeated. Callers hold p.mu.
func (p *Provider) pairAndOpen(pin string, cause *unpairedError) (*session11, error) {
	if len(p.opts.Pair) == 0 {
		return nil, notPaired(cause)
	}
	// Let go of the module and its card handles: pairing connects to the card on its own and resets it.
	p.reset()
	rv, attempts, err := callPairing(p.path, p.opts.Pair, pin)
	if errors.Is(err, errNoPairing) {
		return nil, notPaired(cause)
	}
	if err != nil {
		// The module was not called.
		return nil, token.Errorf(token.CodeDevice, "pairing: %v", err)
	}
	switch rv {
	case cardAlreadyEnabled:
		// Paired already, found before the PIN is used: the failure has another cause.
		return nil, cause.err
	case pkcs11.CKR_PIN_LEN_RANGE, pkcs11.CKR_PIN_INVALID:
		// Checked before the card is touched.
		return nil, token.Errorf(token.CodePinInvalid, "the module rejected the PIN format while pairing")
	}
	// Any other outcome may come after the PIN reached the card.
	s, err := p.afterPairing(pin, rv, attempts)
	return s, token.AfterPIN(err)
}

func (p *Provider) afterPairing(pin string, rv uint, attempts int) (*session11, error) {
	switch rv {
	case pkcs11.CKR_OK:
		s, err := p.open(pin)
		var again *unpairedError
		if errors.As(err, &again) {
			return nil, token.Errorf(token.CodeDevice, "the card was paired but the module still cannot use it: %v", again.err)
		}
		return s, err
	case pkcs11.CKR_PIN_INCORRECT:
		left := -1
		if attempts >= 0 && attempts <= 15 {
			left = attempts
		}
		return nil, &token.Error{Code: token.CodePinIncorrect, RetriesLeft: left, Err: errors.New("wrong PIN while pairing the card")}
	case pkcs11.CKR_PIN_LOCKED:
		return nil, token.Errorf(token.CodePinLocked, "PIN blocked while pairing the card")
	case pkcs11.CKR_TOKEN_NOT_PRESENT:
		return nil, token.Errorf(token.CodeNoCard, "no card to pair")
	case pkcs11.CKR_TOKEN_NOT_RECOGNIZED:
		return nil, token.Errorf(token.CodeCardUnsupported, "the module does not recognize the card")
	}
	return nil, token.Errorf(token.CodeDevice, "pairing failed: %s", pkcs11.Error(rv))
}

func notPaired(cause *unpairedError) error {
	if token.CodeOf(cause.err) == token.CodeNotFound {
		return cause.err
	}
	return token.Errorf(token.CodeNotPaired, "pair the card with the CIE application first (%v)", cause.err)
}
