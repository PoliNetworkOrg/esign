package server

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PoliNetworkOrg/esign/internal/backend"
	"github.com/PoliNetworkOrg/esign/internal/token"
	"github.com/PoliNetworkOrg/esign/internal/token/soft"
)

const (
	dashboard = "https://admin.polinetwork.org"
	host      = "127.0.0.1:47321"
	self      = "http://" + host
	ticket    = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
)

// tickets returns n distinct valid tickets.
func tickets(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = strings.Repeat(string(rune('A'+i)), 43)
	}
	return out
}

type failure struct{ ticket, code string }

// fakeBackend serves jobs that need steps[ticket] signatures (1 when unset).
type fakeBackend struct {
	mu         sync.Mutex
	steps      map[string]int
	signer     map[string]string
	jobErr     map[string]error
	prepareErr map[string]error
	cert       []byte
	digests    [][]byte
	signatures [][]byte
	done       map[string]int
	failed     []failure
}

func (f *fakeBackend) stepsOf(t string) int {
	if n := f.steps[t]; n > 0 {
		return n
	}
	return 1
}

func (f *fakeBackend) Job(_ context.Context, t string) (*backend.Job, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.jobErr[t]; err != nil {
		return nil, err
	}
	job := &backend.Job{ID: "job-" + t[:1], Status: "pending", Signatures: f.stepsOf(t)}
	job.Document.Title = "Verbale"
	job.Signer.Name = f.signer[t]
	return job, nil
}

func (f *fakeBackend) Prepare(_ context.Context, t string, cert []byte, _ [][]byte) (*backend.Prepared, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.prepareErr[t]; err != nil {
		return nil, err
	}
	f.cert = cert
	step := f.done[t]
	sum := sha256.Sum256([]byte(t + strconv.Itoa(step)))
	f.digests = append(f.digests, sum[:])
	return &backend.Prepared{Digest: sum[:], Step: step, Steps: f.stepsOf(t)}, nil
}

func (f *fakeBackend) Complete(_ context.Context, t string, sig []byte) (*backend.Completion, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.signatures = append(f.signatures, sig)
	if f.done == nil {
		f.done = map[string]int{}
	}
	f.done[t]++
	c := &backend.Completion{Status: "completed"}
	if f.done[t] < f.stepsOf(t) {
		c.Status = "next"
	}
	return c, nil
}

func (f *fakeBackend) Fail(_ context.Context, t, code, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failed = append(f.failed, failure{t, code})
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

func newServer(fb *fakeBackend, providers ...token.Provider) *Server {
	return New(Options{
		Port:           47321,
		AllowedOrigins: []string{dashboard},
		Providers:      providers,
		Version:        "test",
		Backend:        func(string) Backend { return fb },
	})
}

func setup(t *testing.T) (*Server, *fakeBackend, *noCard) {
	t.Helper()
	p, err := soft.New("12345678")
	if err != nil {
		t.Fatal(err)
	}
	fb := &fakeBackend{}
	nc := &noCard{}
	return newServer(fb, nc, p), fb, nc
}

type req struct {
	method, path, host, origin, site string
	body                             any
	noHeader                         bool
	cookie                           *http.Cookie
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
	if r.cookie != nil {
		h.AddCookie(r.cookie)
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
	body := jobRequest{Tickets: []string{ticket}, Origin: dashboard}
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
		{"foreign dashboard", req{method: "POST", path: "/api/job", origin: self, body: jobRequest{Tickets: []string{ticket}, Origin: "https://evil.example"}}, http.StatusForbidden},
		{"bad ticket", req{method: "POST", path: "/api/job", origin: self, body: jobRequest{Tickets: []string{ticket, "x"}, Origin: dashboard}}, http.StatusBadRequest},
		{"no ticket", req{method: "POST", path: "/api/job", origin: self, body: jobRequest{Origin: dashboard}}, http.StatusBadRequest},
		{"too many tickets", req{method: "POST", path: "/api/job", origin: self, body: jobRequest{Tickets: tickets(MaxTickets + 1), Origin: dashboard}}, http.StatusBadRequest},
		{"job", req{method: "POST", path: "/api/job", origin: self, site: "same-origin", body: body}, http.StatusOK},
		{"ten jobs", req{method: "POST", path: "/api/job", origin: self, body: jobRequest{Tickets: tickets(MaxTickets), Origin: dashboard}}, http.StatusOK},
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

func TestPagesShowTheVersion(t *testing.T) {
	for version, footer := range map[string]string{
		"v1.2.3": "PoliNetwork eSign 1.2.3</footer>",
		"<b>":    "PoliNetwork eSign &lt;b&gt;</footer>",
	} {
		s := New(Options{Port: 47321, Version: version})
		for _, path := range []string{"/", "/sign"} {
			rec := do(t, s, req{method: "GET", path: path})
			if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), footer) {
				t.Errorf("%s with version %q: %d, no %q in\n%s", path, version, rec.Code, footer, rec.Body)
			}
		}
	}
}

// TestSignPageDashboard: the signing page posts its messages, the first one before any request, only to a dashboard
// the agent signs for, which the agent names in the page.
func TestSignPageDashboard(t *testing.T) {
	s, _, _ := setup(t)
	cases := map[string]string{
		"/sign?origin=" + url.QueryEscape(dashboard) + "&ticket=" + ticket: dashboard,
		"/sign?origin=" + url.QueryEscape(dashboard):                       dashboard,
		"/sign?origin=" + url.QueryEscape("https://evil.example"):          "",
		"/sign?origin=" + url.QueryEscape(`"><script>`):                    "",
		"/sign": "",
	}
	for path, want := range cases {
		page := do(t, s, req{method: "GET", path: path}).Body.String()
		if attrs := `data-version="test" data-dashboard="` + want + `"`; !strings.Contains(page, attrs) {
			t.Errorf("%s: no %s in\n%s", path, attrs, page)
		}
	}
}

func TestDownload(t *testing.T) {
	cases := map[string]downloadLink{
		"darwin": {
			URL:    "https://github.com/PoliNetworkOrg/esign/releases/latest/download/PoliNetwork-eSign-macos.dmg",
			Label:  "Download for macOS",
			Update: "Download the new one, open it and open PoliNetwork eSign inside: it replaces this one.",
		},
		"windows": {
			URL:    "https://github.com/PoliNetworkOrg/esign/releases/latest/download/PoliNetwork-eSign-windows-amd64.zip",
			Label:  "Download for Windows",
			Update: "Download the new one, extract it and open esign.exe: it replaces this one.",
		},
		"linux": {
			URL:    "https://github.com/PoliNetworkOrg/esign/releases/latest",
			Label:  "Open the download page",
			Page:   true,
			Update: "Update the polinetwork-esign package, or install the new one from the download page.",
		},
	}
	for goos, want := range cases {
		if got := download(goos); got != want {
			t.Errorf("download(%q) = %+v, want %+v", goos, got, want)
		}
	}
}

// TestDownloadsAreReleased: the files the page downloads are the ones the build scripts write and the release
// workflow requires.
func TestDownloadsAreReleased(t *testing.T) {
	for goos, script := range map[string]string{"darwin": "build-macos.sh", "windows": "build-windows.sh"} {
		name := path.Base(download(goos).URL)
		for _, file := range []string{"../../scripts/" + script, "../../.github/workflows/release.yml"} {
			data, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(data), name) {
				t.Errorf("%s does not mention %s", file, name)
			}
		}
	}
}

// TestSignPageOffersTheDownload: the installer downloads in the window itself, the release page opens in a new tab.
func TestSignPageOffersTheDownload(t *testing.T) {
	attrs := func(goos string) string {
		return `href="` + download(goos).URL + `" data-update="` + template.HTMLEscapeString(download(goos).Update) + `" hidden`
	}
	link := map[string]string{
		"darwin":  `<a id="fatal-download" class="button" ` + attrs("darwin") + `>Download for macOS</a>`,
		"windows": `<a id="fatal-download" class="button" ` + attrs("windows") + `>Download for Windows</a>`,
		"linux":   `<a id="fatal-download" class="button" ` + attrs("linux") + ` target="_blank" rel="noreferrer">Open the download page</a>`,
	}
	for goos, want := range link {
		var page bytes.Buffer
		if err := pages.ExecuteTemplate(&page, "sign.html", pageData{Download: download(goos)}); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(page.String(), want) {
			t.Errorf("%s: no %s in\n%s", goos, want, &page)
		}
	}
	s, _, _ := setup(t)
	if page := do(t, s, req{method: "GET", path: "/sign"}).Body.String(); !strings.Contains(page, download(runtime.GOOS).URL) {
		t.Errorf("the page does not offer the download for %s:\n%s", runtime.GOOS, page)
	}
}

func TestShownVersion(t *testing.T) {
	cases := map[string]string{
		"v0.4.0":      "0.4.0",
		"v1.2.3-rc.1": "1.2.3-rc.1",
		"0.4.0":       "0.4.0",
		"dev":         "dev",
		"vnext":       "vnext",
		"v":           "v",
		"":            "",
	}
	for version, want := range cases {
		if got := shownVersion(version); got != want {
			t.Errorf("shownVersion(%q) = %q, want %q", version, got, want)
		}
	}
}

type signResponse struct {
	Results []signResult `json:"results"`
	Signer  *struct {
		DisplayName string `json:"displayName"`
	} `json:"signer"`
}

func signRequest(t *testing.T, s *Server, pin string, tickets ...string) (*httptest.ResponseRecorder, signResponse) {
	t.Helper()
	rec := do(t, s, req{method: "POST", path: "/api/sign", origin: self, body: jobRequest{Tickets: tickets, Origin: dashboard, PIN: pin}})
	var res signResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &res)
	return rec, res
}

// statuses lists each result as "status" or "status:code".
func statuses(res signResponse) []string {
	var out []string
	for _, r := range res.Results {
		s := r.Status
		if r.Error != nil {
			s += ":" + r.Error.Code
		}
		out = append(out, s)
	}
	return out
}

// verify checks that every signature the backend received is the card's signature of its digest.
func verify(t *testing.T, fb *fakeBackend, p *soft.Provider) {
	t.Helper()
	if !bytes.Equal(fb.cert, p.Certificate().Raw) {
		t.Error("prepare did not receive the certificate")
	}
	for i, sig := range fb.signatures {
		if err := rsa.VerifyPKCS1v15(p.Certificate().PublicKey.(*rsa.PublicKey), crypto.SHA256, fb.digests[i], sig); err != nil {
			t.Errorf("signature %d: %v", i, err)
		}
	}
}

func TestSign(t *testing.T) {
	s, fb, nc := setup(t)
	rec, _ := signRequest(t, s, "00000000", ticket)
	if rec.Code != http.StatusUnauthorized || errorCode(rec) != "pin_incorrect" {
		t.Fatalf("wrong PIN: %d %s", rec.Code, rec.Body)
	}
	if nc.opened != 1 {
		t.Errorf("fallback provider opened %d times", nc.opened)
	}
	if len(fb.failed) != 1 || fb.failed[0].code != "pin_incorrect" {
		t.Errorf("failure not reported: %v", fb.failed)
	}

	rec, res := signRequest(t, s, "12345678", ticket)
	if rec.Code != http.StatusOK {
		t.Fatalf("sign: %d %s", rec.Code, rec.Body)
	}
	if got := statuses(res); !slices.Equal(got, []string{"completed"}) || res.Signer == nil || res.Signer.DisplayName != "Prova Sviluppo" {
		t.Errorf("result: %s", rec.Body)
	}
	if len(fb.signatures) != 1 {
		t.Errorf("%d signatures", len(fb.signatures))
	}
	verify(t, fb, s.opts.Providers[1].(*soft.Provider))

	rec, _ = signRequest(t, s, "1234", ticket)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("short PIN: %d", rec.Code)
	}
}

// TestSignSeveralPlaces: a job with three places gets three signatures from one card session.
func TestSignSeveralPlaces(t *testing.T) {
	s, fb, _ := setup(t)
	fb.steps = map[string]int{ticket: 3}
	rec, res := signRequest(t, s, "12345678", ticket)
	if rec.Code != http.StatusOK || !slices.Equal(statuses(res), []string{"completed"}) {
		t.Fatalf("sign: %d %s", rec.Code, rec.Body)
	}
	if len(fb.signatures) != 3 || fb.done[ticket] != 3 || bytes.Equal(fb.digests[0], fb.digests[1]) {
		t.Fatalf("%d signatures, %d completed", len(fb.signatures), fb.done[ticket])
	}
	verify(t, fb, s.opts.Providers[1].(*soft.Provider))
}

// TestBatchBackendError: a job the backend refuses fails alone; the next ones are still signed.
func TestBatchBackendError(t *testing.T) {
	s, fb, _ := setup(t)
	ts := tickets(3)
	fb.steps = map[string]int{ts[2]: 2}
	fb.prepareErr = map[string]error{ts[1]: &backend.Error{Status: 409, Code: "document_changed", Message: "The document changed."}}
	rec, res := signRequest(t, s, "12345678", ts...)
	if rec.Code != http.StatusOK {
		t.Fatalf("sign: %d %s", rec.Code, rec.Body)
	}
	if got := statuses(res); !slices.Equal(got, []string{"completed", "failed:document_changed", "completed"}) {
		t.Errorf("results: %v", got)
	}
	if res.Results[1].Error.Message != "The document changed." {
		t.Errorf("message: %q", res.Results[1].Error.Message)
	}
	if !slices.Equal(fb.failed, []failure{{ts[1], "document_changed"}}) {
		t.Errorf("failed: %v", fb.failed)
	}
	if len(fb.signatures) != 3 {
		t.Errorf("%d signatures", len(fb.signatures))
	}
	verify(t, fb, s.opts.Providers[1].(*soft.Provider))
}

// flaky is a provider whose card stops answering after a number of signatures.
type flaky struct {
	*soft.Provider
	left int
}

func (f *flaky) Open(ctx context.Context, pin string) (token.Session, error) {
	session, err := f.Provider.Open(ctx, pin)
	if err != nil {
		return nil, err
	}
	return &flakySession{Session: session, f: f}, nil
}

type flakySession struct {
	token.Session
	f *flaky
}

func (s *flakySession) SignDigest(ctx context.Context, digest []byte) ([]byte, error) {
	if s.f.left == 0 {
		return nil, token.AfterPIN(token.Errorf(token.CodeCardRemoved, "card gone"))
	}
	s.f.left--
	return s.Session.SignDigest(ctx, digest)
}

// TestBatchCardError: when the card fails, the job fails and the jobs after it are skipped, all reported.
func TestBatchCardError(t *testing.T) {
	p, err := soft.New("12345678")
	if err != nil {
		t.Fatal(err)
	}
	fb := &fakeBackend{}
	s := newServer(fb, &flaky{Provider: p, left: 1})
	ts := tickets(3)
	rec, res := signRequest(t, s, "12345678", ts...)
	if rec.Code != http.StatusOK {
		t.Fatalf("sign: %d %s", rec.Code, rec.Body)
	}
	if got := statuses(res); !slices.Equal(got, []string{"completed", "failed:card_removed", "skipped:card_removed"}) {
		t.Errorf("results: %v", got)
	}
	if !slices.Equal(fb.failed, []failure{{ts[1], "card_removed"}, {ts[2], "card_removed"}}) {
		t.Errorf("failed: %v", fb.failed)
	}
	if fb.done[ts[0]] != 1 || fb.done[ts[1]] != 0 || fb.done[ts[2]] != 0 {
		t.Errorf("completed: %v", fb.done)
	}
}

// TestOpenErrorFailsAll: when the card session does not open, every job learns why.
func TestOpenErrorFailsAll(t *testing.T) {
	s, fb, _ := setup(t)
	ts := tickets(3)
	rec, _ := signRequest(t, s, "00000000", ts...)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong PIN: %d %s", rec.Code, rec.Body)
	}
	if !slices.Equal(fb.failed, []failure{{ts[0], "pin_incorrect"}, {ts[1], "pin_incorrect"}, {ts[2], "pin_incorrect"}}) {
		t.Errorf("failed: %v", fb.failed)
	}
	if len(fb.signatures) != 0 {
		t.Errorf("%d signatures", len(fb.signatures))
	}
}

// TestJobEndedBeforeSigning: a job that cannot be fetched is not signed, and with nothing left the PIN is not used.
func TestJobEndedBeforeSigning(t *testing.T) {
	s, fb, nc := setup(t)
	ts := tickets(2)
	fb.jobErr = map[string]error{ts[0]: &backend.Error{Status: 410, Code: "job_done", Message: "Already signed."}}
	rec, res := signRequest(t, s, "12345678", ts...)
	if got := statuses(res); rec.Code != http.StatusOK || !slices.Equal(got, []string{"failed:job_done", "completed"}) {
		t.Fatalf("sign: %d %s", rec.Code, rec.Body)
	}
	opened := nc.opened
	rec, res = signRequest(t, s, "12345678", ts[0])
	if got := statuses(res); rec.Code != http.StatusOK || !slices.Equal(got, []string{"failed:job_done"}) || res.Signer != nil {
		t.Fatalf("sign: %d %s", rec.Code, rec.Body)
	}
	if nc.opened != opened {
		t.Error("the card was opened with nothing to sign")
	}
}

// TestDuplicateTickets: a ticket repeated in the page URL or a request is signed once.
func TestDuplicateTickets(t *testing.T) {
	s, fb, _ := setup(t)
	ts := tickets(2)
	if rec := do(t, s, req{method: "GET", path: "/sign?origin=" + dashboard + "&ticket=" + ts[0] + "&ticket=" + ts[0] + "&ticket=" + ts[1]}); rec.Code != http.StatusOK {
		t.Fatalf("page: %d", rec.Code)
	}
	rec := do(t, s, req{method: "POST", path: "/api/job", origin: self, body: jobRequest{Tickets: []string{ts[0], ts[1], ts[0]}, Origin: dashboard}})
	var jobs struct {
		Jobs []jobResult `json:"jobs"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &jobs)
	if len(jobs.Jobs) != 2 || jobs.Jobs[0].Ticket != ts[0] || jobs.Jobs[1].Ticket != ts[1] {
		t.Fatalf("jobs: %s", rec.Body)
	}
	_, res := signRequest(t, s, "12345678", ts[1], ts[1])
	if got := statuses(res); !slices.Equal(got, []string{"completed"}) || len(fb.signatures) != 1 {
		t.Fatalf("results %v, %d signatures", got, len(fb.signatures))
	}
	// Eleven tickets with repeats are at most ten documents.
	if rec := do(t, s, req{method: "POST", path: "/api/job", origin: self, body: jobRequest{Tickets: append(tickets(MaxTickets), ts[0]), Origin: dashboard}}); rec.Code != http.StatusOK {
		t.Errorf("ten documents with a repeat: %d %s", rec.Code, rec.Body)
	}
}

func TestCancel(t *testing.T) {
	s, fb, _ := setup(t)
	ts := tickets(2)
	rec := do(t, s, req{method: "POST", path: "/api/cancel", origin: self, body: jobRequest{Tickets: ts, Origin: dashboard}})
	if rec.Code != http.StatusOK || len(fb.failed) != 2 || fb.failed[0].code != "cancelled" || fb.failed[1].code != "cancelled" {
		t.Errorf("cancel: %d %s %v", rec.Code, rec.Body, fb.failed)
	}
}

func TestSignTimeout(t *testing.T) {
	if got := signTimeout(1); got != 90*time.Second {
		t.Errorf("one signature: %v", got)
	}
	if got := signTimeout(100); got != 15*time.Minute {
		t.Errorf("cap: %v", got)
	}
}

func TestBackendErrors(t *testing.T) {
	s, fb, _ := setup(t)
	ts := tickets(3)
	fb.jobErr = map[string]error{
		ts[1]: &backend.Error{Status: 410, Code: "job_expired", Message: "expired"},
		ts[2]: errors.New("dial tcp: refused"),
	}
	rec := do(t, s, req{method: "POST", path: "/api/job", origin: self, body: jobRequest{Tickets: ts, Origin: dashboard}})
	var res struct {
		Jobs []jobResult `json:"jobs"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &res)
	if rec.Code != http.StatusOK || len(res.Jobs) != 3 {
		t.Fatalf("jobs: %d %s", rec.Code, rec.Body)
	}
	if res.Jobs[0].Job == nil || res.Jobs[0].Job.Signatures != 1 || res.Jobs[0].Error != nil {
		t.Errorf("first: %s", rec.Body)
	}
	if res.Jobs[1].Job != nil || res.Jobs[1].Error == nil || res.Jobs[1].Error.Code != "job_expired" {
		t.Errorf("expired: %s", rec.Body)
	}
	if res.Jobs[2].Error == nil || res.Jobs[2].Error.Code != "backend_unreachable" {
		t.Errorf("unreachable: %s", rec.Body)
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

// untrustedCard is a provider that refuses a card failing the authenticity checks, before the PIN.
type untrustedCard struct{ pinSentNotPaired }

func (u *untrustedCard) Open(context.Context, string) (token.Session, error) {
	u.opened++
	return nil, token.Errorf(token.CodeCardUntrusted, "SOD not signed by a trusted CSCA")
}

// TestNoFallbackForUntrustedCard: a card that may be counterfeit must not get the PIN through another provider.
func TestNoFallbackForUntrustedCard(t *testing.T) {
	first, next := &untrustedCard{}, &noCard{}
	s := New(Options{Port: 47321, AllowedOrigins: []string{dashboard}, Providers: []token.Provider{first, next}, Version: "test"})
	if _, _, err := s.open(t.Context(), "12345678"); token.CodeOf(err) != token.CodeCardUntrusted || next.opened != 0 {
		t.Fatalf("error %v, next opened %d times", err, next.opened)
	}
}

// broken is a provider whose Status or Open panics.
type broken struct{ status, open bool }

func (b *broken) Name() string { return "broken" }
func (b *broken) Status(context.Context) token.Status {
	if b.status {
		panic("status")
	}
	present := true
	return token.Status{Provider: "broken", Available: true, CardPresent: &present}
}
func (b *broken) Open(context.Context, string) (token.Session, error) {
	if b.open {
		panic("open")
	}
	return nil, token.Errorf(token.CodeNoCard, "no card")
}

// counted counts the sessions opened on a software card.
type counted struct {
	*soft.Provider
	opened int
}

func (c *counted) Open(ctx context.Context, pin string) (token.Session, error) {
	c.opened++
	return c.Provider.Open(ctx, pin)
}

func softCard(t *testing.T) *counted {
	t.Helper()
	p, err := soft.New("12345678")
	if err != nil {
		t.Fatal(err)
	}
	return &counted{Provider: p}
}

// TestStatusPanic: a provider whose status panics is reported unavailable, and the next one still signs.
func TestStatusPanic(t *testing.T) {
	fb := &fakeBackend{}
	card := softCard(t)
	s := newServer(fb, &broken{status: true}, card)
	rec := do(t, s, req{method: "GET", path: "/api/status"})
	var st statusResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &st)
	if rec.Code != http.StatusOK || len(st.Providers) != 2 || st.Providers[0].Available || !st.Providers[1].Available || !st.Ready {
		t.Fatalf("status: %d %s", rec.Code, rec.Body)
	}
	rec, res := signRequest(t, s, "12345678", ticket)
	if got := statuses(res); rec.Code != http.StatusOK || !slices.Equal(got, []string{"completed"}) || card.opened != 1 {
		t.Fatalf("sign: %d %s", rec.Code, rec.Body)
	}
}

// TestOpenPanic: a panic while opening the card is answered as an internal error, and the PIN goes nowhere else.
func TestOpenPanic(t *testing.T) {
	card := softCard(t)
	s := newServer(&fakeBackend{}, &broken{open: true}, card)
	rec, _ := signRequest(t, s, "12345678", ticket)
	if rec.Code != http.StatusInternalServerError || errorCode(rec) != "internal" || card.opened != 0 {
		t.Fatalf("sign: %d %s, fallback opened %d times", rec.Code, rec.Body, card.opened)
	}
}

// heldStatus is a software card whose first status check holds the card until released, as a slow reader's can.
type heldStatus struct {
	*counted
	once    sync.Once
	holding chan struct{}
	release chan struct{}
}

func (h *heldStatus) Status(ctx context.Context) token.Status {
	h.once.Do(func() {
		close(h.holding)
		<-h.release
	})
	return h.counted.Status(ctx)
}

// TestSignWaitsForStatus: a signature arriving while a status check (the status pages poll) holds the card waits for
// it instead of answering busy, which would make the user type the PIN again.
func TestSignWaitsForStatus(t *testing.T) {
	card := &heldStatus{counted: softCard(t), holding: make(chan struct{}), release: make(chan struct{})}
	s := newServer(&fakeBackend{}, card)
	status := make(chan *httptest.ResponseRecorder, 1)
	go func() { status <- do(t, s, req{method: "GET", path: "/api/status"}) }()
	<-card.holding
	signed := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		rec, _ := signRequest(t, s, "12345678", ticket)
		signed <- rec
	}()
	select {
	case rec := <-signed:
		t.Fatalf("sign answered while the status check held the card: %d %s", rec.Code, rec.Body)
	case <-time.After(100 * time.Millisecond):
	}
	close(card.release)

	if rec := <-status; rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), `"busy"`) {
		t.Errorf("status: %d %s", rec.Code, rec.Body)
	}
	rec := <-signed
	var res signResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &res)
	if rec.Code != http.StatusOK || !slices.Equal(statuses(res), []string{"completed"}) || card.opened != 1 {
		t.Fatalf("sign: %d %s, opened %d times", rec.Code, rec.Body, card.opened)
	}
}

// TestBusyCard: while a signature holds the card, a status check answers busy at once, and another signature after
// Options.CardWait without trying the card.
func TestBusyCard(t *testing.T) {
	fb := &fakeBackend{}
	card := softCard(t)
	s := New(Options{
		Port:           47321,
		AllowedOrigins: []string{dashboard},
		Providers:      []token.Provider{card},
		Version:        "test",
		Backend:        func(string) Backend { return fb },
		CardWait:       20 * time.Millisecond,
	})
	if !s.card.TryLock() {
		t.Fatal("the card is busy")
	}
	defer s.card.Unlock()
	if rec := do(t, s, req{method: "GET", path: "/api/status"}); rec.Code != http.StatusOK || strings.TrimSpace(rec.Body.String()) != `{"busy":true}` {
		t.Errorf("status: %d %s", rec.Code, rec.Body)
	}
	rec, _ := signRequest(t, s, "12345678", ticket)
	if rec.Code != http.StatusConflict || errorCode(rec) != "busy" || card.opened != 0 || len(fb.failed) != 0 {
		t.Fatalf("sign: %d %s, opened %d times, failed %v", rec.Code, rec.Body, card.opened, fb.failed)
	}
}

// fixed is a provider with a fixed status that has no card to open.
type fixed struct{ st token.Status }

func (f *fixed) Name() string                        { return f.st.Provider }
func (f *fixed) Status(context.Context) token.Status { return f.st }
func (f *fixed) Open(context.Context, string) (token.Session, error) {
	panic("a provider without a card was opened")
}

// TestNothingToOpen: when no provider can be tried, the error names what is missing, and the job learns it.
func TestNothingToOpen(t *testing.T) {
	absent := false
	off := &fixed{token.Status{Provider: "off"}}
	cases := []struct {
		providers []token.Provider
		code      string
	}{
		{[]token.Provider{off, off}, "no_reader"},
		{[]token.Provider{&fixed{token.Status{Provider: "off", Readers: []string{"ACS ACR1252"}}}}, "middleware_missing"},
		{[]token.Provider{off, &fixed{token.Status{Provider: "empty", Available: true, Readers: []string{"ACS ACR1252"}, CardPresent: &absent}}}, "no_card"},
	}
	for _, c := range cases {
		fb := &fakeBackend{}
		rec, _ := signRequest(t, newServer(fb, c.providers...), "12345678", ticket)
		if rec.Code != http.StatusServiceUnavailable || errorCode(rec) != c.code || !slices.Equal(fb.failed, []failure{{ticket, c.code}}) {
			t.Errorf("want %s: %d %s, failed %v", c.code, rec.Code, rec.Body, fb.failed)
		}
	}
}

// TestCardState: the page holds the PIN back exactly when open would try no provider, and never because a provider
// cannot tell whether a card is there.
func TestCardState(t *testing.T) {
	yes, no := true, false
	cases := []struct {
		statuses []token.Status
		want     string
	}{
		{nil, cardAbsent},
		{[]token.Status{{}}, cardAbsent},
		{[]token.Status{{CardPresent: &yes}}, cardAbsent},
		{[]token.Status{{Available: true, CardPresent: &no}}, cardAbsent},
		{[]token.Status{{Available: true, CardPresent: &yes}}, cardPresent},
		{[]token.Status{{Available: true}}, cardUnknown},
		{[]token.Status{{Available: true}, {Available: true, CardPresent: &no}}, cardUnknown},
		{[]token.Status{{Available: true, CardPresent: &no}, {Available: true, CardPresent: &yes}}, cardPresent},
		{[]token.Status{{Available: true}, {Available: true, CardPresent: &yes}}, cardPresent},
	}
	for i, c := range cases {
		if got := cardState(c.statuses); got != c.want {
			t.Errorf("case %d: cardState = %q, want %q", i, got, c.want)
		}
	}
}

// TestStatusCard: the status tells the page whether the card is there, and a signature started without it does not
// send the PIN anywhere.
func TestStatusCard(t *testing.T) {
	s, fb, r := rememberServer(t, -1)
	card := func() string {
		t.Helper()
		var st statusResponse
		rec := do(t, s, req{method: "GET", path: "/api/status"})
		if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil || rec.Code != http.StatusOK {
			t.Fatalf("status: %d %s", rec.Code, rec.Body)
		}
		return st.Card
	}
	if got := card(); got != cardPresent {
		t.Errorf("card on the reader: %q", got)
	}
	r.present.Store(false)
	if got := card(); got != cardAbsent {
		t.Errorf("card taken away: %q", got)
	}
	rec := signWith(t, s, jobRequest{PIN: "12345678"}, nil)
	if errorCode(rec) != "no_card" || r.opened.Load() != 0 || len(fb.signatures) != 0 {
		t.Errorf("sign without the card: %d %s, opened %d times", rec.Code, rec.Body, r.opened.Load())
	}

	s = newServer(&fakeBackend{}, &noCard{})
	var st statusResponse
	_ = json.Unmarshal(do(t, s, req{method: "GET", path: "/api/status"}).Body.Bytes(), &st)
	if st.Card != cardUnknown {
		t.Errorf("provider that cannot tell: %q", st.Card)
	}
}
