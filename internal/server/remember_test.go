package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PoliNetworkOrg/esign/internal/token"
	"github.com/PoliNetworkOrg/esign/internal/token/soft"
)

// reader is a software card that can be taken off the reader or swapped for another.
type reader struct {
	card    atomic.Pointer[soft.Provider]
	present atomic.Bool
	opened  atomic.Int32
}

func newReader(t *testing.T) *reader {
	t.Helper()
	r := &reader{}
	r.swap(t)
	r.present.Store(true)
	return r
}

// swap places another card, with the same PIN.
func (r *reader) swap(t *testing.T) {
	t.Helper()
	p, err := soft.New("12345678")
	if err != nil {
		t.Fatal(err)
	}
	r.card.Store(p)
}

func (r *reader) Name() string { return "reader" }
func (r *reader) Status(context.Context) token.Status {
	present := r.present.Load()
	return token.Status{Provider: "reader", Available: true, Readers: []string{"reader"}, CardPresent: &present}
}
func (r *reader) Open(ctx context.Context, pin string) (token.Session, error) {
	r.opened.Add(1)
	if !r.present.Load() {
		return nil, token.Errorf(token.CodeNoCard, "no card")
	}
	return r.card.Load().Open(ctx, pin)
}

func rememberServer(t *testing.T, rememberFor time.Duration) (*Server, *fakeBackend, *reader) {
	t.Helper()
	fb := &fakeBackend{}
	r := newReader(t)
	s := New(Options{
		Port:           47321,
		AllowedOrigins: []string{dashboard},
		Providers:      []token.Provider{r},
		Version:        "test",
		Backend:        func(string) Backend { return fb },
		RememberFor:    rememberFor,
		CardWatch:      5 * time.Millisecond,
	})
	return s, fb, r
}

func signWith(t *testing.T, s *Server, body jobRequest, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	body.Origin = dashboard
	if body.Tickets == nil {
		body.Tickets = []string{ticket}
	}
	return do(t, s, req{method: "POST", path: "/api/sign", origin: self, body: body, cookie: cookie})
}

func errorCode(rec *httptest.ResponseRecorder) string {
	var res struct {
		Error struct{ Code string } `json:"error"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &res)
	return res.Error.Code
}

func rememberCookieOf(t *testing.T, rec *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == rememberCookie {
			return c
		}
	}
	return nil
}

// rememberPIN signs once with the PIN, asking to remember it, and returns the browser's cookie.
func rememberPIN(t *testing.T, s *Server) *http.Cookie {
	t.Helper()
	rec := signWith(t, s, jobRequest{PIN: "12345678", Remember: true}, nil)
	c := rememberCookieOf(t, rec)
	if rec.Code != http.StatusOK || c == nil || c.Value == "" {
		t.Fatalf("remember: %d %v %s", rec.Code, rec.Result().Cookies(), rec.Body)
	}
	if !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.Path != "/api/" {
		t.Errorf("cookie attributes: %+v", c)
	}
	return c
}

func waitForgotten(t *testing.T, s *Server) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		s.memMu.Lock()
		m := s.mem
		s.memMu.Unlock()
		if m == nil {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("the PIN was not forgotten")
}

func TestRememberPIN(t *testing.T) {
	s, fb, _ := rememberServer(t, time.Minute)
	if rec := signWith(t, s, jobRequest{}, nil); rec.Code != http.StatusUnauthorized || errorCode(rec) != codePINRequired {
		t.Fatalf("no PIN, nothing remembered: %d %s", rec.Code, rec.Body)
	}
	cookie := rememberPIN(t, s)

	status := do(t, s, req{method: "GET", path: "/api/status", cookie: cookie})
	var st statusResponse
	_ = json.Unmarshal(status.Body.Bytes(), &st)
	if st.Remembered == nil || st.Remembered.Signer != "Prova Sviluppo" || time.Until(st.Remembered.Expires) < 50*time.Second {
		t.Errorf("status: %s", status.Body)
	}
	if strings.Contains(status.Body.String(), "12345678") {
		t.Error("status leaks the PIN")
	}

	rec := signWith(t, s, jobRequest{}, cookie)
	var res signResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &res)
	if rec.Code != http.StatusOK || !slices.Equal(statuses(res), []string{"completed"}) || len(fb.signatures) != 2 {
		t.Fatalf("sign with the remembered PIN: %d %s", rec.Code, rec.Body)
	}

	// Another browser, or a forged key, gets nothing.
	for _, c := range []*http.Cookie{nil, {Name: rememberCookie, Value: "forged"}} {
		if rec := signWith(t, s, jobRequest{}, c); rec.Code != http.StatusUnauthorized || errorCode(rec) != codePINRequired {
			t.Errorf("cookie %v: %d %s", c, rec.Code, rec.Body)
		}
	}
	if st := do(t, s, req{method: "GET", path: "/api/status"}); strings.Contains(st.Body.String(), "remembered") {
		t.Errorf("status without the cookie: %s", st.Body)
	}

	// Typing the PIN without asking to remember it forgets the remembered one.
	if rec := signWith(t, s, jobRequest{PIN: "12345678"}, cookie); rec.Code != http.StatusOK || rememberCookieOf(t, rec).MaxAge >= 0 {
		t.Fatalf("typed PIN: %d %v", rec.Code, rec.Result().Cookies())
	}
	if rec := signWith(t, s, jobRequest{}, cookie); rec.Code != http.StatusUnauthorized {
		t.Errorf("remembered after typing it again: %d %s", rec.Code, rec.Body)
	}
}

func TestRememberedPINWiped(t *testing.T) {
	s, _, _ := rememberServer(t, time.Minute)
	cookie := rememberPIN(t, s)
	m, _ := s.recall(httptest.NewRequest("GET", "/", nil))
	if m != nil {
		t.Fatal("recalled without a cookie")
	}
	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(cookie)
	m, pin := s.recall(r)
	if m == nil || pin != "12345678" {
		t.Fatal("not recalled")
	}
	rec := do(t, s, req{method: "POST", path: "/api/forget", origin: self, body: struct{}{}, cookie: cookie})
	if rec.Code != http.StatusOK || rememberCookieOf(t, rec).MaxAge >= 0 {
		t.Fatalf("forget: %d %v", rec.Code, rec.Result().Cookies())
	}
	if string(m.pin) != "\x00\x00\x00\x00\x00\x00\x00\x00" {
		t.Errorf("PIN not wiped: %q", m.pin)
	}
	if rec := signWith(t, s, jobRequest{}, cookie); rec.Code != http.StatusUnauthorized {
		t.Errorf("signed after forgetting: %d %s", rec.Code, rec.Body)
	}
}

func TestRememberedPINExpires(t *testing.T) {
	s, _, r := rememberServer(t, 30*time.Millisecond)
	cookie := rememberPIN(t, s)
	waitForgotten(t, s)
	opened := r.opened.Load()
	if rec := signWith(t, s, jobRequest{}, cookie); rec.Code != http.StatusUnauthorized || errorCode(rec) != codePINRequired {
		t.Errorf("expired: %d %s", rec.Code, rec.Body)
	}
	if r.opened.Load() != opened {
		t.Error("the card was opened after the PIN expired")
	}
}

// TestRememberedPINCardRemoved: taking the card off the reader forgets the PIN, so a card placed later never gets it.
func TestRememberedPINCardRemoved(t *testing.T) {
	s, fb, r := rememberServer(t, time.Minute)
	cookie := rememberPIN(t, s)
	r.present.Store(false)
	waitForgotten(t, s)
	r.swap(t)
	r.present.Store(true)
	opened := r.opened.Load()
	if rec := signWith(t, s, jobRequest{}, cookie); rec.Code != http.StatusUnauthorized || errorCode(rec) != codePINRequired {
		t.Errorf("after removal: %d %s", rec.Code, rec.Body)
	}
	if r.opened.Load() != opened || len(fb.signatures) != 1 {
		t.Error("the new card received the PIN")
	}
}

// TestRememberedPINOtherCard: a card swapped faster than the watcher notices is not signed with, even if it accepts
// the PIN.
func TestRememberedPINOtherCard(t *testing.T) {
	s, fb, r := rememberServer(t, time.Minute)
	cookie := rememberPIN(t, s)
	r.swap(t)
	rec := signWith(t, s, jobRequest{}, cookie)
	if rec.Code != http.StatusUnauthorized || errorCode(rec) != codePINRequired || len(fb.signatures) != 1 {
		t.Fatalf("other card: %d %s, %d signatures", rec.Code, rec.Body, len(fb.signatures))
	}
	waitForgotten(t, s)
}

// TestRememberedPINError: any failure to open the card with the remembered PIN forgets it.
func TestRememberedPINError(t *testing.T) {
	s, _, r := rememberServer(t, time.Minute)
	cookie := rememberPIN(t, s)
	// Holding the card keeps the watcher from noticing the removal first.
	if !s.card.LockWithin(context.Background(), time.Second) {
		t.Fatal("the card stayed busy")
	}
	r.present.Store(false)
	s.card.Unlock()
	rec := signWith(t, s, jobRequest{}, cookie)
	if rec.Code != http.StatusServiceUnavailable || errorCode(rec) != "no_card" {
		t.Fatalf("no card: %d %s", rec.Code, rec.Body)
	}
	waitForgotten(t, s)
}

func TestRememberDisabled(t *testing.T) {
	s, _, _ := rememberServer(t, -1)
	rec := signWith(t, s, jobRequest{PIN: "12345678", Remember: true}, nil)
	if c := rememberCookieOf(t, rec); rec.Code != http.StatusOK || c != nil && c.MaxAge >= 0 {
		t.Errorf("remembered while disabled: %d %v", rec.Code, rec.Result().Cookies())
	}
}

func TestCardGone(t *testing.T) {
	yes, no := true, false
	cases := []struct {
		statuses []token.Status
		gone     bool
	}{
		{nil, true},
		{[]token.Status{{Available: false}}, true},
		{[]token.Status{{Available: true, CardPresent: &no}}, true},
		{[]token.Status{{Available: true, CardPresent: &yes}}, false},
		{[]token.Status{{Available: true}}, false},
		{[]token.Status{{Available: true}, {Available: true, CardPresent: &no}}, true},
		{[]token.Status{{Available: true, CardPresent: &no}, {Available: true, CardPresent: &yes}}, false},
	}
	for i, c := range cases {
		if got := cardGone(c.statuses); got != c.gone {
			t.Errorf("case %d: cardGone = %v", i, got)
		}
	}
}
