// Package server is the agent's loopback web app. The dashboard opens its /sign page in a popup (a top-level
// navigation, which browsers allow from HTTPS pages, unlike fetches to loopback). The page takes the PIN once and the
// agent signs one or more jobs, talking to the dashboard's backend with each job's single-use ticket. The dashboard
// never reaches the agent.
package server

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/PoliNetworkOrg/esign/internal/backend"
	"github.com/PoliNetworkOrg/esign/internal/certinfo"
	"github.com/PoliNetworkOrg/esign/internal/launch"
	"github.com/PoliNetworkOrg/esign/internal/token"
)

// APIHeader must be sent on every /api request by the agent's own page.
const APIHeader = "X-PN-eSign"

//go:embed web
var webFS embed.FS

// pages are the HTML pages, rendered with pageData; their assets are served as they are.
var pages = template.Must(template.ParseFS(webFS, "web/*.html"))

// pageData is what the pages show before any script runs.
type pageData struct {
	// Version is the agent's version as people read it: "0.4.0" for the release tagged v0.4.0, or "dev".
	Version string
}

// shownVersion drops the "v" of a release tag.
func shownVersion(version string) string {
	if rest, ok := strings.CutPrefix(version, "v"); ok && rest != "" && rest[0] >= '0' && rest[0] <= '9' {
		return rest
	}
	return version
}

// Options configures the server.
type Options struct {
	// Port the agent listens on; Host headers must name it.
	Port int
	// AllowedOrigins are dashboards the agent will sign for: exact origins ("https://admin.polinetwork.org") or a
	// loopback origin with any port ("http://localhost:*").
	AllowedOrigins []string
	// Providers in order of preference.
	Providers []token.Provider
	Version   string
	Logger    *slog.Logger
	// Backend builds the client for a dashboard origin; backend.New by default (tests replace it).
	Backend func(origin string) Backend
	// RememberFor is how long a PIN lasts when the user asks to remember it: DefaultRememberFor when zero, never
	// when negative.
	RememberFor time.Duration
	// CardWatch is how often the card is checked while a PIN is remembered; 2 seconds when zero.
	CardWatch time.Duration
	// CardWait is how long a signature waits for the card while a status check or the card watcher holds it;
	// 3 seconds when zero.
	CardWait time.Duration
}

// Backend is the part of the dashboard's API the agent uses.
type Backend interface {
	Job(ctx context.Context, ticket string) (*backend.Job, error)
	Prepare(ctx context.Context, ticket string, certificate []byte, chain [][]byte) (*backend.Prepared, error)
	Complete(ctx context.Context, ticket string, signature []byte) (*backend.Completion, error)
	Fail(ctx context.Context, ticket, code, message string) error
}

// Server serves the agent.
type Server struct {
	opts Options
	// card serializes signatures: one card, one operation at a time.
	card   cardLock
	static http.Handler

	// memMu guards mem, the PIN the user chose to remember (see remember.go). Lock it after card, never before.
	memMu sync.Mutex
	mem   *remembered
}

// New returns a server.
func New(opts Options) *Server {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.Backend == nil {
		version := opts.Version
		opts.Backend = func(origin string) Backend { return backend.New(origin, version) }
	}
	if opts.RememberFor == 0 {
		opts.RememberFor = DefaultRememberFor
	}
	if opts.CardWatch <= 0 {
		opts.CardWatch = defaultCardWatch
	}
	if opts.CardWait <= 0 {
		opts.CardWait = defaultCardWait
	}
	sub, _ := fs.Sub(webFS, "web")
	return &Server{opts: opts, card: make(cardLock, 1), static: http.FileServerFS(sub)}
}

// defaultCardWait outlasts a status check, which the status pages make every 1.5 seconds.
const defaultCardWait = 3 * time.Second

// cardLock is a mutex that a signature can wait for with a deadline.
type cardLock chan struct{}

func (l cardLock) Unlock() { <-l }

func (l cardLock) TryLock() bool {
	select {
	case l <- struct{}{}:
		return true
	default:
		return false
	}
}

// LockWithin waits for the lock until d passes or ctx ends, and reports whether it got it.
func (l cardLock) LockWithin(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case l <- struct{}{}:
		return true
	case <-timer.C:
		return false
	case <-ctx.Done():
		return false
	}
}

// Handler returns the HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.page("index.html"))
	mux.HandleFunc("GET /sign", s.page("sign.html"))
	mux.Handle("GET /assets/", s.static)
	mux.HandleFunc("GET /api/status", s.api(s.status))
	mux.HandleFunc("POST /api/job", s.api(s.job))
	mux.HandleFunc("POST /api/sign", s.api(s.sign))
	mux.HandleFunc("POST /api/cancel", s.api(s.cancel))
	mux.HandleFunc("POST /api/forget", s.api(s.forgetPIN))
	return s.guard(mux)
}

// ListenAndServe serves on 127.0.0.1 until ctx ends.
func (s *Server) ListenAndServe(ctx context.Context) error {
	srv := &http.Server{
		Addr:              net.JoinHostPort("127.0.0.1", strconv.Itoa(s.opts.Port)),
		Handler:           s.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		// Signing waits for the card and two backend round trips per signature, up to signTimeout's cap.
		WriteTimeout:   16 * time.Minute,
		MaxHeaderBytes: 16 << 10,
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutdown)
	}
}

func (s *Server) hostAllowed(host string) bool {
	h, port, err := net.SplitHostPort(host)
	if err != nil || port != strconv.Itoa(s.opts.Port) {
		return false
	}
	return h == "127.0.0.1" || h == "localhost"
}

// OriginAllowed reports whether origin is one of the allowed dashboards.
func OriginAllowed(allowed []string, origin string) bool {
	if origin == "" || origin == "null" {
		return false
	}
	for _, a := range allowed {
		if a == origin {
			return true
		}
		if prefix, ok := strings.CutSuffix(a, ":*"); ok && strings.HasPrefix(origin, prefix+":") {
			port := origin[len(prefix)+1:]
			if n, err := strconv.Atoi(port); err == nil && n > 0 && n < 65536 && strconv.Itoa(n) == port {
				return true
			}
		}
	}
	return false
}

func (s *Server) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		// Lets a second agent, or the polinetwork-esign:// link handler, recognize that the agent already runs.
		h.Set("Server", launch.ServerHeader+s.opts.Version)
		h.Set("Cache-Control", "no-store")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		// The ticket is in the page URL: never leak it to other sites.
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'")
		// Blocks DNS rebinding: a foreign host name resolving to 127.0.0.1 is refused.
		if !s.hostAllowed(r.Host) {
			http.Error(w, "Address PoliNetwork eSign as 127.0.0.1 or localhost", http.StatusMisdirectedRequest)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) page(name string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var page bytes.Buffer
		if err := pages.ExecuteTemplate(&page, name, pageData{Version: shownVersion(s.opts.Version)}); err != nil {
			s.opts.Logger.Error("render page", "page", name, "error", err)
			http.Error(w, "PoliNetwork eSign could not show this page.", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(page.Bytes())
	}
}

// api accepts only requests from the agent's own pages: same origin, JSON, with the API header.
func (s *Server) api(handler func(w http.ResponseWriter, r *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		self := "http://" + r.Host
		if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" {
			writeError(w, http.StatusForbidden, "forbidden", "Cross-site request")
			return
		}
		if origin := r.Header.Get("Origin"); r.Method != http.MethodGet && origin != self {
			writeError(w, http.StatusForbidden, "forbidden", "Cross-origin request")
			return
		}
		if r.Header.Get(APIHeader) != "1" {
			writeError(w, http.StatusBadRequest, "bad_request", APIHeader+" is required")
			return
		}
		if r.Method == http.MethodPost && !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			writeError(w, http.StatusUnsupportedMediaType, "bad_request", "Send JSON")
			return
		}
		defer func() {
			if v := recover(); v != nil {
				if v == http.ErrAbortHandler {
					panic(v)
				}
				s.opts.Logger.Error("api panic", "path", r.URL.Path, "panic", v, "stack", string(debug.Stack()))
				writeError(w, http.StatusInternalServerError, "internal", "PoliNetwork eSign hit an unexpected error. Try again.")
			}
		}()
		handler(w, r)
	}
}

type statusResponse struct {
	Agent     string         `json:"agent"`
	Version   string         `json:"version"`
	OS        string         `json:"os"`
	Providers []token.Status `json:"providers"`
	// Ready is true when some provider sees a card.
	Ready bool `json:"ready"`
	// Remembered is set while this browser has a remembered PIN.
	Remembered *rememberedInfo `json:"remembered,omitempty"`
}

// providerStatus is p's status; a panic in it is logged and reported as unavailable.
func (s *Server) providerStatus(ctx context.Context, p token.Provider) token.Status {
	st, err := token.SafeStatus(ctx, p)
	if err != nil {
		s.opts.Logger.Error("provider status", "provider", p.Name(), "error", err)
	}
	return st
}

func (s *Server) statuses(ctx context.Context) statusResponse {
	res := statusResponse{Agent: "polinetwork-esign", Version: s.opts.Version, OS: osName()}
	for _, p := range s.opts.Providers {
		st := s.providerStatus(ctx, p)
		res.Providers = append(res.Providers, st)
		if st.Available && st.CardPresent != nil && *st.CardPresent {
			res.Ready = true
		}
	}
	return res
}

func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	// While a signature runs the card is busy: report it rather than queueing behind it. A signature arriving
	// meanwhile waits for this check (Options.CardWait).
	if !s.card.TryLock() {
		writeJSON(w, http.StatusOK, map[string]any{"busy": true})
		return
	}
	defer s.card.Unlock()
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	res := s.statuses(ctx)
	res.Remembered = s.rememberedFor(r)
	writeJSON(w, http.StatusOK, res)
}

// MaxTickets is how many documents the page can sign with one PIN.
const MaxTickets = 10

type jobRequest struct {
	Tickets []string `json:"tickets"`
	Origin  string   `json:"origin"`
	// PIN is empty to sign with the PIN this browser remembered.
	PIN string `json:"pin,omitempty"`
	// Remember asks to remember PIN for Options.RememberFor once the card accepts it.
	Remember bool `json:"remember,omitempty"`
}

// apiError is the error of one ticket in a response.
type apiError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// decode reads a job request, drops repeated tickets and checks the tickets and origin.
func (s *Server) decode(w http.ResponseWriter, r *http.Request) (*jobRequest, Backend, bool) {
	var req jobRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "Malformed request")
		return nil, nil, false
	}
	req.Tickets = uniqueTickets(req.Tickets)
	valid := len(req.Tickets) > 0
	for _, t := range req.Tickets {
		valid = valid && backend.TicketPattern.MatchString(t)
	}
	if !valid {
		writeError(w, http.StatusBadRequest, "ticket_invalid", "This signing link is not valid.")
		return nil, nil, false
	}
	if len(req.Tickets) > MaxTickets {
		writeError(w, http.StatusBadRequest, "too_many_tickets", "Sign at most "+strconv.Itoa(MaxTickets)+" documents at a time.")
		return nil, nil, false
	}
	if !OriginAllowed(s.opts.AllowedOrigins, req.Origin) {
		s.opts.Logger.Warn("refused dashboard origin", "origin", req.Origin)
		writeError(w, http.StatusForbidden, "origin_forbidden", "PoliNetwork eSign does not sign for "+req.Origin+".")
		return nil, nil, false
	}
	return &req, s.opts.Backend(req.Origin), true
}

// uniqueTickets returns tickets without repeats, in their order.
func uniqueTickets(tickets []string) []string {
	seen := make(map[string]bool, len(tickets))
	var out []string
	for _, t := range tickets {
		if !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	return out
}

type jobResult struct {
	Ticket string       `json:"ticket"`
	Job    *backend.Job `json:"job,omitempty"`
	Error  *apiError    `json:"error,omitempty"`
}

// fetchJobs fetches the jobs in parallel. A ticket that fails gets its error, the others are unaffected.
func fetchJobs(ctx context.Context, be Backend, tickets []string) []jobResult {
	res := make([]jobResult, len(tickets))
	var wg sync.WaitGroup
	for i, t := range tickets {
		wg.Go(func() {
			res[i].Ticket = t
			job, err := be.Job(ctx, t)
			if err != nil {
				res[i].Error = backendError(err)
				return
			}
			res[i].Job = job
		})
	}
	wg.Wait()
	return res
}

func (s *Server) job(w http.ResponseWriter, r *http.Request) {
	req, be, ok := s.decode(w, r)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	res := map[string]any{"jobs": fetchJobs(ctx, be, req.Tickets), "remembered": s.rememberedFor(r)}
	if s.opts.RememberFor > 0 {
		res["rememberMinutes"] = int(s.opts.RememberFor / time.Minute)
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) cancel(w http.ResponseWriter, r *http.Request) {
	req, be, ok := s.decode(w, r)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	for _, t := range req.Tickets {
		wg.Go(func() {
			if err := be.Fail(ctx, t, "cancelled", "Cancelled in PoliNetwork eSign"); err != nil {
				s.opts.Logger.Warn("cancel job", "error", err)
			}
		})
	}
	wg.Wait()
	writeJSON(w, http.StatusOK, map[string]string{"status": "cancelled"})
}

// fallbackCodes are failures that a provider reports before any PIN reached a card: the next provider may still
// work. An error marked token.PINSent never falls back, whatever its code.
var fallbackCodes = map[token.Code]bool{
	token.CodeNoReader:          true,
	token.CodeNoCard:            true,
	token.CodeMiddlewareMissing: true,
	token.CodeNotPaired:         true,
	token.CodeCardUnsupported:   true,
}

// open authenticates with the first provider that sees a card, falling back only when the provider says no PIN was
// sent: a PIN that reached a module or card may have used an attempt, and must not be tried again elsewhere. When no
// provider can be tried, the error says what is missing: a reader, CIE software or the card.
func (s *Server) open(ctx context.Context, pin string) (token.Session, token.Provider, error) {
	var firstErr error
	readers, available := false, false
	for _, p := range s.opts.Providers {
		st := s.providerStatus(ctx, p)
		readers = readers || len(st.Readers) > 0
		available = available || st.Available
		if !st.Available || (st.CardPresent != nil && !*st.CardPresent) {
			continue
		}
		session, err := p.Open(ctx, pin)
		if err == nil {
			return session, p, nil
		}
		s.opts.Logger.Warn("open card session", "provider", p.Name(), "code", token.CodeOf(err), "error", err)
		if token.PINSent(err) || !fallbackCodes[token.CodeOf(err)] {
			return nil, p, err
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	switch {
	case firstErr != nil:
		return nil, nil, firstErr
	case !readers:
		return nil, nil, token.Errorf(token.CodeNoReader, "no provider sees a reader")
	case !available:
		return nil, nil, token.Errorf(token.CodeMiddlewareMissing, "no provider is available")
	}
	return nil, nil, token.Errorf(token.CodeNoCard, "no provider sees a card")
}

// signResult is what happened to one ticket: "completed", "failed" or "skipped" (not tried after a card error).
type signResult struct {
	Ticket string    `json:"ticket"`
	Status string    `json:"status"`
	Error  *apiError `json:"error,omitempty"`
}

// signTimeout is the time a request may take: a minute to open the card, then 30 seconds per signature, at most
// 15 minutes. The server's WriteTimeout must cover the cap.
func signTimeout(signatures int) time.Duration {
	return min(time.Minute+time.Duration(signatures)*30*time.Second, 15*time.Minute)
}

// sign opens one card session with the PIN, typed or remembered, and signs every job in order. A backend error ends
// only its job; a card error ends the session, and the jobs after it are skipped.
func (s *Server) sign(w http.ResponseWriter, r *http.Request) {
	req, be, ok := s.decode(w, r)
	if !ok {
		return
	}
	if req.PIN != "" && !token.ValidPIN(req.PIN, 8) {
		writeTokenError(w, token.Errorf(token.CodePinInvalid, "malformed PIN"))
		return
	}
	// A status check or the card watcher holds the card only briefly: wait for it rather than refusing the PIN.
	if !s.card.LockWithin(r.Context(), s.opts.CardWait) {
		writeError(w, http.StatusConflict, string(token.CodeBusy), "Another signature is in progress.")
		return
	}
	defer s.card.Unlock()
	var mem *remembered
	if req.PIN == "" {
		// Recalled with the card held, after any check of the watcher that found the card gone.
		if mem, req.PIN = s.recall(r); mem == nil {
			clearRememberCookie(w)
			writeError(w, http.StatusUnauthorized, codePINRequired, "Type your CIE PIN.")
			return
		}
	}

	// The jobs say how many signatures to expect. One that cannot be fetched (it ended meanwhile) is not signed.
	fetchCtx, cancelFetch := context.WithTimeout(r.Context(), 20*time.Second)
	jobs := fetchJobs(fetchCtx, be, req.Tickets)
	cancelFetch()
	results := make([]signResult, len(jobs))
	var todo []int
	signatures := 0
	for i, j := range jobs {
		if j.Error != nil {
			results[i] = signResult{Ticket: j.Ticket, Status: "failed", Error: j.Error}
			continue
		}
		results[i] = signResult{Ticket: j.Ticket, Status: "skipped"}
		todo = append(todo, i)
		signatures += max(j.Job.Signatures, 1)
	}
	if len(todo) == 0 {
		req.PIN = ""
		writeJSON(w, http.StatusOK, map[string]any{"results": results})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), signTimeout(signatures))
	defer cancel()
	session, provider, err := s.open(ctx, req.PIN)
	pin := req.PIN
	req.PIN = ""
	if err != nil {
		if mem != nil {
			// Whatever went wrong, the card it was typed for may not be there: ask for the PIN again.
			s.forget(mem, "card error: "+string(token.CodeOf(err)))
			clearRememberCookie(w)
		}
		code := token.CodeOf(err)
		for _, i := range todo {
			s.fail(ctx, be, jobs[i].Ticket, string(code), messageOf[code])
		}
		writeTokenError(w, err)
		return
	}
	defer session.Close()
	info := certinfo.Parse(session.Certificate())
	switch {
	case mem != nil && !bytes.Equal(session.Certificate().Raw, mem.cert):
		// Another card, which happens to have the same PIN: sign only after the user typed it for this card.
		s.forget(mem, "another card")
		clearRememberCookie(w)
		writeError(w, http.StatusUnauthorized, codePINRequired, "A different CIE is on the reader. Type its PIN.")
		return
	case mem == nil && req.Remember && s.opts.RememberFor > 0:
		s.remember(w, pin, session.Certificate().Raw, info.DisplayName)
	case mem == nil:
		// Typing the PIN without asking to remember it replaces a PIN remembered before.
		s.forgetAll("PIN typed again")
		clearRememberCookie(w)
	}
	pin = ""
	var chain [][]byte
	for _, c := range session.Chain() {
		chain = append(chain, c.Raw)
	}

	// stop is the card error that ended the session: the remaining jobs get it too.
	var stop *apiError
	for _, i := range todo {
		ticket, job := jobs[i].Ticket, jobs[i].Job
		if stop != nil {
			results[i].Error = stop
			s.fail(ctx, be, ticket, stop.Code, stop.Message)
			continue
		}
		started := time.Now()
		n, err := signJob(ctx, be, session, chain, ticket)
		if err == nil {
			results[i].Status = "completed"
			s.opts.Logger.Info("signed", "provider", provider.Name(), "signer", info.DisplayName, "job", job.ID, "signatures", n, "duration", time.Since(started).Round(time.Millisecond))
			continue
		}
		e, card := describe(err)
		s.opts.Logger.Warn("sign job", "provider", provider.Name(), "job", job.ID, "signatures", n, "code", e.Code, "error", err)
		results[i] = signResult{Ticket: ticket, Status: "failed", Error: e}
		s.fail(ctx, be, ticket, e.Code, e.Message)
		if card || ctx.Err() != nil {
			stop = e
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"results": results, "signer": info})
}

// codePINRequired answers a signature without a PIN when none is remembered, or no longer usable.
const codePINRequired = "pin_required"

// cardError is a failure of the card session, which is not used again after it.
type cardError struct{ error }

func (e cardError) Unwrap() error { return e.error }

// signJob adds the job's signatures one at a time (prepare, sign with the card, complete) until the backend says
// the job is complete, and returns how many it added.
func signJob(ctx context.Context, be Backend, session token.Session, chain [][]byte, ticket string) (int, error) {
	cert := session.Certificate()
	steps := 0
	for n := 0; ; n++ {
		p, err := be.Prepare(ctx, ticket, cert.Raw, chain)
		if err != nil {
			return n, err
		}
		if n == 0 {
			steps = p.Steps
		}
		// The card signs only as many digests as the backend announced at the start.
		if n >= steps {
			return n, fmt.Errorf("the server asked for signature %d of %d", n+1, steps)
		}
		signature, err := session.SignDigest(ctx, p.Digest)
		if err != nil {
			return n, cardError{err}
		}
		if pub, ok := cert.PublicKey.(*rsa.PublicKey); !ok || rsa.VerifyPKCS1v15(pub, crypto.SHA256, p.Digest, signature) != nil {
			return n, cardError{token.Errorf(token.CodeDevice, "the card returned a signature that does not verify")}
		}
		done, err := be.Complete(ctx, ticket, signature)
		if err != nil {
			return n, err
		}
		if done.Status == "completed" {
			return n + 1, nil
		}
	}
}

// describe turns a signJob error into the job's result error, and reports whether the card failed.
func describe(err error) (*apiError, bool) {
	var ce cardError
	if errors.As(err, &ce) {
		code := token.CodeOf(err)
		return &apiError{Code: string(code), Message: messageOf[code]}, true
	}
	return backendError(err), false
}

// fail tells the backend why a job was not signed, so the dashboard can show it. Its own failure is only logged.
func (s *Server) fail(ctx context.Context, be Backend, ticket, code, message string) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	if err := be.Fail(ctx, ticket, code, message); err != nil {
		s.opts.Logger.Warn("report failure", "code", code, "error", err)
	}
}

var statusOf = map[token.Code]int{
	token.CodeNoReader:          http.StatusServiceUnavailable,
	token.CodeNoCard:            http.StatusServiceUnavailable,
	token.CodeCardRemoved:       http.StatusServiceUnavailable,
	token.CodeMiddlewareMissing: http.StatusServiceUnavailable,
	token.CodeNotPaired:         http.StatusServiceUnavailable,
	token.CodeCardUnsupported:   http.StatusUnprocessableEntity,
	token.CodeCardUntrusted:     http.StatusUnprocessableEntity,
	token.CodeNotFound:          http.StatusNotFound,
	token.CodePinIncorrect:      http.StatusUnauthorized,
	token.CodePinInvalid:        http.StatusBadRequest,
	token.CodePinLocked:         http.StatusLocked,
	token.CodeBusy:              http.StatusConflict,
}

var messageOf = map[token.Code]string{
	token.CodeNoReader:          "No smart-card reader found. Connect the NFC reader.",
	token.CodeNoCard:            "No card on the reader. Place your CIE on the reader.",
	token.CodeCardRemoved:       "The card moved away from the reader. Keep the CIE still on the reader and try again.",
	token.CodeMiddlewareMissing: "CIE ID is not set up on this computer.",
	token.CodeNotPaired:         "This CIE is not paired with this computer yet. Pair it in CIE ID, then sign again.",
	token.CodeCardUnsupported:   "This card is not a supported CIE.",
	token.CodeCardUntrusted:     "This card could not be verified as a genuine CIE, so the PIN was not sent to it.",
	token.CodeNotFound:          "No signing certificate found on the card.",
	token.CodePinIncorrect:      "Wrong PIN.",
	token.CodePinInvalid:        "Type the 8 digits of your CIE PIN.",
	token.CodePinLocked:         "Your CIE PIN is blocked. Unblock it with your PUK in the CieID app on your phone or in CIE ID on this computer, then sign again from the dashboard. The PUK’s first half is on the receipt from the Comune, the second half in the letter that came with the card.",
	token.CodeBusy:              "Another signature is in progress.",
	token.CodeDevice:            "The card could not complete the operation. Try again.",
}

func writeTokenError(w http.ResponseWriter, err error) {
	code := token.CodeOf(err)
	status, ok := statusOf[code]
	if !ok {
		status = http.StatusBadGateway
	}
	body := map[string]any{"code": string(code), "message": messageOf[code]}
	var te *token.Error
	if errors.As(err, &te) && code == token.CodePinIncorrect && te.RetriesLeft >= 0 {
		body["retriesLeft"] = te.RetriesLeft
	}
	writeJSON(w, status, map[string]any{"error": body})
}

// backendError is the error to show for a failed backend call.
func backendError(err error) *apiError {
	var be *backend.Error
	if errors.As(err, &be) {
		return &apiError{Code: be.Code, Message: be.Message}
	}
	return &apiError{Code: "backend_unreachable", Message: "Cannot reach the dashboard. Check your connection and try again."}
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": message}})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
