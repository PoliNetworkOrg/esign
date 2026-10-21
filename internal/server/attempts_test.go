package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/PoliNetworkOrg/esign/internal/backend"
	"github.com/PoliNetworkOrg/esign/internal/token"
	"github.com/PoliNetworkOrg/esign/internal/token/soft"
)

// mute is a card whose middleware does not say how many PIN attempts are left, like the official one.
type mute struct{ *soft.Provider }

func (m mute) Open(ctx context.Context, pin string) (token.Session, error) {
	session, err := m.Provider.Open(ctx, pin)
	var te *token.Error
	if errors.As(err, &te) {
		hidden := *te
		hidden.RetriesLeft = -1
		return nil, &hidden
	}
	return session, err
}

func muteCard(t *testing.T) mute {
	t.Helper()
	p, err := soft.New("12345678")
	if err != nil {
		t.Fatal(err)
	}
	return mute{p}
}

// attemptsOf reads the attempts of a /api/job answer or of a /api/sign error.
func attemptsOf(t *testing.T, rec *httptest.ResponseRecorder) *attempts {
	t.Helper()
	var res struct {
		Attempts *attempts `json:"attempts"`
		Error    struct {
			Attempts *attempts `json:"attempts"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if res.Attempts != nil {
		return res.Attempts
	}
	return res.Error.Attempts
}

// jobAttempts is what the page learns when it opens for tickets.
func jobAttempts(t *testing.T, s *Server, tickets ...string) *attempts {
	t.Helper()
	rec := do(t, s, req{method: "POST", path: "/api/job", origin: self, body: jobRequest{Tickets: tickets, Origin: dashboard}})
	if rec.Code != http.StatusOK {
		t.Fatalf("job: %d %s", rec.Code, rec.Body)
	}
	return attemptsOf(t, rec)
}

func wantAttempts(t *testing.T, what string, got *attempts, want *attempts) {
	t.Helper()
	if (got == nil) != (want == nil) || got != nil && *got != *want {
		t.Errorf("%s: attempts %+v, want %+v", what, got, want)
	}
}

// TestWrongPINsCounted: with a middleware that does not report the attempts left, the agent counts the wrong PINs in
// a row; a page opened again still learns the count, and a PIN that works clears it.
func TestWrongPINsCounted(t *testing.T) {
	s := newServer(&fakeBackend{}, muteCard(t))
	wantAttempts(t, "before any PIN", jobAttempts(t, s, ticket), nil)

	rec, _ := signRequest(t, s, "00000000", ticket)
	if rec.Code != http.StatusUnauthorized || errorCode(rec) != "pin_incorrect" {
		t.Fatalf("wrong PIN: %d %s", rec.Code, rec.Body)
	}
	wantAttempts(t, "first wrong PIN", attemptsOf(t, rec), &attempts{Left: 2})
	wantAttempts(t, "page opened again", jobAttempts(t, s, ticket), &attempts{Left: 2})

	rec, _ = signRequest(t, s, "00000000", ticket)
	wantAttempts(t, "second wrong PIN", attemptsOf(t, rec), &attempts{Left: 1})
	wantAttempts(t, "page opened again", jobAttempts(t, s, ticket), &attempts{Left: 1})

	if rec, _ = signRequest(t, s, "12345678", ticket); rec.Code != http.StatusOK {
		t.Fatalf("right PIN: %d %s", rec.Code, rec.Body)
	}
	wantAttempts(t, "after the right PIN", jobAttempts(t, s, ticket), nil)
}

// TestWrongPINsFromCard: the attempts the card reports win, and a blocked card leaves nothing to warn about.
func TestWrongPINsFromCard(t *testing.T) {
	s, _, _ := setup(t)
	rec, _ := signRequest(t, s, "00000000", ticket)
	wantAttempts(t, "first wrong PIN", attemptsOf(t, rec), &attempts{Left: 2, Card: true})
	rec, _ = signRequest(t, s, "00000000", ticket)
	wantAttempts(t, "second wrong PIN", attemptsOf(t, rec), &attempts{Left: 1, Card: true})
	wantAttempts(t, "page opened again", jobAttempts(t, s, ticket), &attempts{Left: 1, Card: true})
	if rec, _ = signRequest(t, s, "00000000", ticket); errorCode(rec) != "pin_locked" {
		t.Fatalf("third wrong PIN: %d %s", rec.Code, rec.Body)
	}
	wantAttempts(t, "blocked", jobAttempts(t, s, ticket), nil)
}

// TestWrongPINsPerSigner: another person signing on the same computer is not warned about someone else's card, and
// a batch warns when any of its signers should be.
func TestWrongPINsPerSigner(t *testing.T) {
	ts := tickets(3)
	fb := &fakeBackend{signer: map[string]string{ts[0]: "Mario Rossi", ts[1]: "Anna Bianchi", ts[2]: "Mario Rossi"}}
	s := newServer(fb, muteCard(t))
	signRequest(t, s, "00000000", ts[0])
	wantAttempts(t, "same signer, other job", jobAttempts(t, s, ts[2]), &attempts{Left: 2})
	wantAttempts(t, "other signer", jobAttempts(t, s, ts[1]), nil)
	wantAttempts(t, "batch", jobAttempts(t, s, ts[1], ts[2]), &attempts{Left: 2})
}

// TestWrongPINsInABatch: a wrong PIN typed once for several documents of the same signer is one attempt.
func TestWrongPINsInABatch(t *testing.T) {
	ts := tickets(3)
	fb := &fakeBackend{signer: map[string]string{ts[0]: "Mario Rossi", ts[1]: "Mario Rossi", ts[2]: "Mario Rossi"}}
	s := newServer(fb, muteCard(t))
	rec, _ := signRequest(t, s, "00000000", ts...)
	wantAttempts(t, "first wrong PIN", attemptsOf(t, rec), &attempts{Left: 2})
	rec, _ = signRequest(t, s, "00000000", ts...)
	wantAttempts(t, "second wrong PIN", attemptsOf(t, rec), &attempts{Left: 1})
}

// TestWrongPINsKeptForAnotherCard: a PIN that opens a card the backend refuses for the signer proves nothing about the
// signer's own card, so the count stays until a signature of theirs is accepted.
func TestWrongPINsKeptForAnotherCard(t *testing.T) {
	fb := &fakeBackend{}
	s := newServer(fb, muteCard(t))
	signRequest(t, s, "00000000", ticket)
	fb.prepareErr = map[string]error{ticket: &backend.Error{Status: 403, Code: "signer_mismatch", Message: "This CIE belongs to someone else."}}
	if rec, res := signRequest(t, s, "12345678", ticket); rec.Code != http.StatusOK || statuses(res)[0] != "failed:signer_mismatch" {
		t.Fatalf("other card: %d %s", rec.Code, rec.Body)
	}
	wantAttempts(t, "after another card", jobAttempts(t, s, ticket), &attempts{Left: 2})
	fb.prepareErr = nil
	signRequest(t, s, "12345678", ticket)
	wantAttempts(t, "after the signer's card", jobAttempts(t, s, ticket), nil)
}

// TestWrongPINsNeverZero: a card that refuses a PIN without blocking it has an attempt left, whatever the count missed.
func TestWrongPINsNeverZero(t *testing.T) {
	var w wrongPINs
	k := []string{"signer"}
	for range 4 {
		w.wrong(k, -1)
	}
	wantAttempts(t, "after four wrong PINs", w.get(k), &attempts{Left: 1})
	wantAttempts(t, "card reports", w.wrong(k, 2), &attempts{Left: 2, Card: true})
	wantAttempts(t, "card stops reporting", w.wrong(k, -1), &attempts{Left: 1})
}
