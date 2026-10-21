package server

import (
	"errors"
	"sync"

	"github.com/PoliNetworkOrg/esign/internal/backend"
	"github.com/PoliNetworkOrg/esign/internal/token"
)

// pinTries is how many wrong PINs in a row block the PIN of a CIE.
const pinTries = 3

// attempts is what the page shows about the PIN attempts left before the card blocks the PIN.
type attempts struct {
	// Left is the attempts left: as the card reported them after the last wrong PIN, or else pinTries minus the wrong
	// PINs typed in a row on this computer, which misses those typed in other apps.
	Left int `json:"left"`
	// Card is set when Left is what the card reported.
	Card bool `json:"card,omitempty"`
}

// wrongPINs counts the wrong PINs typed in a row, so that the page can warn before the last attempt even after it was
// closed and opened again: the official middleware does not say how many attempts are left.
//
// The count belongs to the person the dashboard asks to sign, whose card the PIN was typed for: another person
// signing on this computer starts without a warning, while the same person with a new card is warned until a PIN
// opens a card that the backend accepts as theirs, which errs on the safe side. It is kept in memory only, until the
// agent stops.
type wrongPINs struct {
	mu sync.Mutex
	by map[string]attempts
}

// signerKey identifies the person a job asks to sign.
func signerKey(origin string, job *backend.Job) string {
	return origin + "\n" + job.Signer.Name
}

// get returns the fewest attempts left among the signers, nil when none of them typed a wrong PIN.
func (w *wrongPINs) get(signers []string) *attempts {
	w.mu.Lock()
	defer w.mu.Unlock()
	var least *attempts
	for _, k := range signers {
		if a, ok := w.by[k]; ok && (least == nil || a.Left < least.Left) {
			least = &a
		}
	}
	return least
}

// wrong counts a wrong PIN for the signers, with the attempts the card reported (-1 when it did not), and returns
// what the page shows. A batch names its signer once per document, but the PIN was typed once: it counts once.
func (w *wrongPINs) wrong(signers []string, retriesLeft int) *attempts {
	w.mu.Lock()
	if w.by == nil {
		w.by = map[string]attempts{}
	}
	for _, k := range unique(signers) {
		a := attempts{Left: retriesLeft, Card: true}
		if retriesLeft < 0 {
			prev, ok := w.by[k]
			if !ok {
				prev.Left = pinTries
			}
			// The card refused the PIN without blocking it, so at least one attempt is left, whatever was missed.
			a = attempts{Left: max(prev.Left-1, 1)}
		}
		w.by[k] = a
	}
	w.mu.Unlock()
	return w.get(signers)
}

// forget drops the count of the signers: a PIN worked on their card, or the card is blocked, and only the PUK, which
// restores every attempt, unblocks it.
func (w *wrongPINs) forget(signers []string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, k := range signers {
		delete(w.by, k)
	}
}

// retriesLeft is the attempts left that the card reported with a wrong PIN, -1 when it did not.
func retriesLeft(err error) int {
	var te *token.Error
	if errors.As(err, &te) && te.Code == token.CodePinIncorrect {
		return te.RetriesLeft
	}
	return -1
}
