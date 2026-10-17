package server

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/PoliNetworkOrg/sign-agent/internal/backend"
	"github.com/PoliNetworkOrg/sign-agent/internal/token"
	"github.com/PoliNetworkOrg/sign-agent/internal/token/soft"
)

const (
	dashboard = "https://admin.polinetwork.org"
	host      = "127.0.0.1:47321"
	self      = "http://" + host
	ticket    = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
)

type fakeBackend struct {
	digest    []byte
	cert      []byte
	signature []byte
	failed    []string
	jobErr    error
}

func (f *fakeBackend) Job(context.Context, string) (*backend.Job, error) {
	if f.jobErr != nil {
		return nil, f.jobErr
	}
	job := &backend.Job{ID: "j1", Status: "pending"}
	job.Document.Title = "Verbale"
	return job, nil
}

func (f *fakeBackend) Prepare(_ context.Context, _ string, cert []byte, _ [][]byte) ([]byte, error) {
	f.cert = cert
	sum := sha256.Sum256([]byte("signed attributes"))
	f.digest = sum[:]
	return f.digest, nil
}

func (f *fakeBackend) Complete(_ context.Context, _ string, sig []byte) (*backend.Completion, error) {
	f.signature = sig
	c := &backend.Completion{Status: "completed"}
	c.Request.Status = "in_progress"
	c.Request.Remaining = 1
	return c, nil
}

func (f *fakeBackend) Fail(_ context.Context, _ string, code, _ string) error {
	f.failed = append(f.failed, code)
	return nil
}

// noCard is a provider that never sees a card, to check fallback.
type noCard struct{ opened int }

func (n *noCard) Name() string { return "none" }
func (n *noCard) Status(context.Context) token.Status {
	return token.Status{Provider: "none", Available: true}
}
func (n *noCard) Open(context.Context, string) (token.Session, error) {
	n.opened++
	return nil, token.Errorf(token.CodeNotPaired, "not paired")
}

func setup(t *testing.T) (*Server, *fakeBackend, *noCard) {
	t.Helper()
	p, err := soft.New("12345678")
	if err != nil {
		t.Fatal(err)
	}
	fb := &fakeBackend{}
	nc := &noCard{}
	s := New(Options{
		Port:           47321,
		AllowedOrigins: []string{dashboard},
		Providers:      []token.Provider{nc, p},
		Version:        "test",
		Backend:        func(string) Backend { return fb },
	})
	return s, fb, nc
}

type req struct {
	method, path, host, origin, site string
	body                             any
	noHeader                         bool
}

func do(t *testing.T, s *Server, r req) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if r.body != nil {
		_ = json.NewEncoder(&buf).Encode(r.body)
	}
	h := httptest.NewRequest(r.method, r.path, &buf)
	h.Host = r.host
	if r.host == "" {
		h.Host = host
	}
	if r.origin != "" {
		h.Header.Set("Origin", r.origin)
	}
	if r.site != "" {
		h.Header.Set("Sec-Fetch-Site", r.site)
	}
	if !r.noHeader {
		h.Header.Set(APIHeader, "1")
	}
	if r.body != nil {
		h.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, h)
	return rec
}

func TestOriginAllowed(t *testing.T) {
	allowed := []string{dashboard, "http://localhost:*"}
	cases := map[string]bool{
		dashboard:                            true,
		"https://admin.polinetwork.org.evil": false,
		"http://admin.polinetwork.org":       false,
		"http://localhost:10001":             true,
		"http://localhost:0":                 false,
		"http://localhost:01":                false,
		"http://localhost:10001.evil.com":    false,
		"http://localhost.evil.com:80":       false,
		"":                                   false,
		"null":                               false,
	}
	for o, want := range cases {
		if got := OriginAllowed(allowed, o); got != want {
			t.Errorf("OriginAllowed(%q) = %v, want %v", o, got, want)
		}
	}
}

func TestGuards(t *testing.T) {
	s, _, _ := setup(t)
	body := jobRequest{Ticket: ticket, Origin: dashboard}
	cases := []struct {
		name string
		r    req
		want int
	}{
		{"rebinding host", req{method: "GET", path: "/sign", host: "evil.example:47321"}, http.StatusMisdirectedRequest},
		{"wrong port", req{method: "GET", path: "/sign", host: "127.0.0.1:1"}, http.StatusMisdirectedRequest},
		{"cross-site api", req{method: "POST", path: "/api/job", origin: "https://evil.example", site: "cross-site", body: body}, http.StatusForbidden},
		{"cross-origin api", req{method: "POST", path: "/api/job", origin: "https://evil.example", body: body}, http.StatusForbidden},
		{"no api header", req{method: "POST", path: "/api/job", origin: self, body: body, noHeader: true}, http.StatusBadRequest},
		{"foreign dashboard", req{method: "POST", path: "/api/job", origin: self, body: jobRequest{Ticket: ticket, Origin: "https://evil.example"}}, http.StatusForbidden},
		{"bad ticket", req{method: "POST", path: "/api/job", origin: self, body: jobRequest{Ticket: "x", Origin: dashboard}}, http.StatusBadRequest},
		{"job", req{method: "POST", path: "/api/job", origin: self, site: "same-origin", body: body}, http.StatusOK},
		{"page", req{method: "GET", path: "/sign?ticket=x"}, http.StatusOK},
		{"asset", req{method: "GET", path: "/assets/sign.js"}, http.StatusOK},
		{"status", req{method: "GET", path: "/api/status", site: "same-origin"}, http.StatusOK},
	}
	for _, c := range cases {
		if rec := do(t, s, c.r); rec.Code != c.want {
			t.Errorf("%s: got %d want %d (%s)", c.name, rec.Code, c.want, rec.Body)
		}
	}
	rec := do(t, s, req{method: "GET", path: "/sign"})
	if !strings.Contains(rec.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") || rec.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Errorf("page headers: %v", rec.Header())
	}
}

func TestSign(t *testing.T) {
	s, fb, nc := setup(t)
	rec := do(t, s, req{method: "POST", path: "/api/sign", origin: self, body: jobRequest{Ticket: ticket, Origin: dashboard, PIN: "00000000"}})
	var failure struct {
		Error struct {
			Code        string `json:"code"`
			RetriesLeft int    `json:"retriesLeft"`
		} `json:"error"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &failure)
	if rec.Code != http.StatusUnauthorized || failure.Error.Code != "pin_incorrect" || failure.Error.RetriesLeft != 2 {
		t.Fatalf("wrong PIN: %d %s", rec.Code, rec.Body)
	}
	if nc.opened != 1 {
		t.Errorf("fallback provider opened %d times", nc.opened)
	}
	if len(fb.failed) != 1 || fb.failed[0] != "pin_incorrect" {
		t.Errorf("failure not reported: %v", fb.failed)
	}

	rec = do(t, s, req{method: "POST", path: "/api/sign", origin: self, body: jobRequest{Ticket: ticket, Origin: dashboard, PIN: "12345678"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("sign: %d %s", rec.Code, rec.Body)
	}
	var done struct {
		Status  string `json:"status"`
		Request struct {
			Remaining int `json:"remaining"`
		} `json:"request"`
		Signer struct {
			DisplayName string `json:"displayName"`
		} `json:"signer"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &done)
	if done.Status != "completed" || done.Request.Remaining != 1 || done.Signer.DisplayName != "Prova Sviluppo" {
		t.Errorf("result: %s", rec.Body)
	}
	p := s.opts.Providers[1].(*soft.Provider)
	if !bytes.Equal(fb.cert, p.Certificate().Raw) {
		t.Error("prepare did not receive the certificate")
	}
	if err := rsa.VerifyPKCS1v15(p.Certificate().PublicKey.(*rsa.PublicKey), crypto.SHA256, fb.digest, fb.signature); err != nil {
		t.Errorf("signature: %v", err)
	}

	rec = do(t, s, req{method: "POST", path: "/api/sign", origin: self, body: jobRequest{Ticket: ticket, Origin: dashboard, PIN: "1234"}})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("short PIN: %d", rec.Code)
	}
}

func TestBackendErrors(t *testing.T) {
	s, fb, _ := setup(t)
	fb.jobErr = &backend.Error{Status: 410, Code: "job_expired", Message: "expired"}
	rec := do(t, s, req{method: "POST", path: "/api/job", origin: self, body: jobRequest{Ticket: ticket, Origin: dashboard}})
	if rec.Code != 410 || !strings.Contains(rec.Body.String(), "job_expired") {
		t.Errorf("expired: %d %s", rec.Code, rec.Body)
	}
	fb.jobErr = errors.New("dial tcp: refused")
	rec = do(t, s, req{method: "POST", path: "/api/job", origin: self, body: jobRequest{Ticket: ticket, Origin: dashboard}})
	if rec.Code != http.StatusBadGateway || !strings.Contains(rec.Body.String(), "backend_unreachable") {
		t.Errorf("unreachable: %d %s", rec.Code, rec.Body)
	}
}

// pinSentNotPaired is a provider whose Open fails with a fallback code after the PIN already reached its card.
type pinSentNotPaired struct{ opened int }

func (p *pinSentNotPaired) Name() string { return "sent" }
func (p *pinSentNotPaired) Status(context.Context) token.Status {
	present := true
	return token.Status{Provider: "sent", Available: true, CardPresent: &present}
}
func (p *pinSentNotPaired) Open(context.Context, string) (token.Session, error) {
	p.opened++
	return nil, token.AfterPIN(token.Errorf(token.CodeNotPaired, "pairing failed after VERIFY"))
}

// TestNoFallbackAfterPIN: once a provider sent the PIN, the next provider must not receive it, even when the error
// code would otherwise allow falling back.
func TestNoFallbackAfterPIN(t *testing.T) {
	first := &pinSentNotPaired{}
	next := &noCard{}
	s := New(Options{Port: 47321, AllowedOrigins: []string{dashboard}, Providers: []token.Provider{first, next}, Version: "test"})
	_, p, err := s.open(t.Context(), "12345678")
	if first.opened != 1 || next.opened != 0 {
		t.Fatalf("opened: first %d, next %d", first.opened, next.opened)
	}
	if p != first || token.CodeOf(err) != token.CodeNotPaired || !token.PINSent(err) {
		t.Fatalf("got provider %v, error %v", p, err)
	}

	// Without the mark the same code still falls back.
	s = New(Options{Port: 47321, AllowedOrigins: []string{dashboard}, Providers: []token.Provider{&noCard{}, next}, Version: "test"})
	_, _, _ = s.open(t.Context(), "12345678")
	if next.opened != 1 {
		t.Fatalf("fallback without PINSent: next opened %d times", next.opened)
	}
}
