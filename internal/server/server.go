// Package server is the agent's loopback web app. The dashboard opens its /sign page in a popup (a top-level
// navigation, which browsers allow from HTTPS pages, unlike fetches to loopback). The page takes the PIN and the agent
// signs, talking to the dashboard's backend with the job's single-use ticket. The dashboard never reaches the agent.
package server

import (
	"context"
	"crypto"
	"crypto/rsa"
	"embed"
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
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
}

// Backend is the part of the dashboard's API the agent uses.
type Backend interface {
	Job(ctx context.Context, ticket string) (*backend.Job, error)
	Prepare(ctx context.Context, ticket string, certificate []byte, chain [][]byte) ([]byte, error)
	Complete(ctx context.Context, ticket string, signature []byte) (*backend.Completion, error)
	Fail(ctx context.Context, ticket, code, message string) error
}

// Server serves the agent.
type Server struct {
	opts Options
	// card serializes signatures: one card, one operation at a time.
	card   sync.Mutex
	static http.Handler
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
	sub, _ := fs.Sub(webFS, "web")
	return &Server{opts: opts, static: http.FileServerFS(sub)}
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
	return s.guard(mux)
}

// ListenAndServe serves on 127.0.0.1 until ctx ends.
func (s *Server) ListenAndServe(ctx context.Context) error {
	srv := &http.Server{
		Addr:              net.JoinHostPort("127.0.0.1", strconv.Itoa(s.opts.Port)),
		Handler:           s.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		// Signing waits for the card and two backend round trips.
		WriteTimeout:   150 * time.Second,
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
			http.Error(w, "Address the agent as 127.0.0.1 or localhost", http.StatusMisdirectedRequest)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) page(name string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		data, err := webFS.ReadFile("web/" + name)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(data)
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
}

func (s *Server) statuses(ctx context.Context) statusResponse {
	res := statusResponse{Agent: "polinetwork-esign", Version: s.opts.Version, OS: osName()}
	for _, p := range s.opts.Providers {
		st := p.Status(ctx)
		res.Providers = append(res.Providers, st)
		if st.Available && st.CardPresent != nil && *st.CardPresent {
			res.Ready = true
		}
	}
	return res
}

func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	// While a signature runs the card is busy: report it rather than queueing behind it.
	if !s.card.TryLock() {
		writeJSON(w, http.StatusOK, map[string]any{"busy": true})
		return
	}
	defer s.card.Unlock()
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	writeJSON(w, http.StatusOK, s.statuses(ctx))
}

type jobRequest struct {
	Ticket string `json:"ticket"`
	Origin string `json:"origin"`
	PIN    string `json:"pin,omitempty"`
}

// decode reads a job request and checks the ticket and origin.
func (s *Server) decode(w http.ResponseWriter, r *http.Request) (*jobRequest, Backend, bool) {
	var req jobRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "Malformed request")
		return nil, nil, false
	}
	if !backend.TicketPattern.MatchString(req.Ticket) {
		writeError(w, http.StatusBadRequest, "ticket_invalid", "This signing link is not valid. Start again from the dashboard.")
		return nil, nil, false
	}
	if !OriginAllowed(s.opts.AllowedOrigins, req.Origin) {
		s.opts.Logger.Warn("refused dashboard origin", "origin", req.Origin)
		writeError(w, http.StatusForbidden, "origin_forbidden", "This agent does not sign for "+req.Origin+".")
		return nil, nil, false
	}
	return &req, s.opts.Backend(req.Origin), true
}

func (s *Server) job(w http.ResponseWriter, r *http.Request) {
	req, be, ok := s.decode(w, r)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	job, err := be.Job(ctx, req.Ticket)
	if err != nil {
		writeBackendError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"job": job})
}

func (s *Server) cancel(w http.ResponseWriter, r *http.Request) {
	req, be, ok := s.decode(w, r)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	if err := be.Fail(ctx, req.Ticket, "cancelled", "Cancelled in the agent"); err != nil {
		writeBackendError(w, err)
		return
	}
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
// sent: a PIN that reached a module or card may have used an attempt, and must not be tried again elsewhere.
func (s *Server) open(ctx context.Context, pin string) (token.Session, token.Provider, error) {
	var firstErr error
	for _, p := range s.opts.Providers {
		st := p.Status(ctx)
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
	if firstErr == nil {
		firstErr = token.Errorf(token.CodeNoCard, "no provider sees a card")
	}
	return nil, nil, firstErr
}

func (s *Server) sign(w http.ResponseWriter, r *http.Request) {
	req, be, ok := s.decode(w, r)
	if !ok {
		return
	}
	if !token.ValidPIN(req.PIN, 8) {
		writeTokenError(w, token.Errorf(token.CodePinInvalid, "malformed PIN"))
		return
	}
	if !s.card.TryLock() {
		writeError(w, http.StatusConflict, string(token.CodeBusy), "Another signature is in progress.")
		return
	}
	defer s.card.Unlock()
	ctx, cancel := context.WithTimeout(r.Context(), 140*time.Second)
	defer cancel()
	started := time.Now()

	session, provider, err := s.open(ctx, req.PIN)
	req.PIN = ""
	if err != nil {
		_ = be.Fail(context.WithoutCancel(ctx), req.Ticket, string(token.CodeOf(err)), messageOf[token.CodeOf(err)])
		writeTokenError(w, err)
		return
	}
	defer session.Close()
	cert := session.Certificate()
	var chain [][]byte
	for _, c := range session.Chain() {
		chain = append(chain, c.Raw)
	}
	digest, err := be.Prepare(ctx, req.Ticket, cert.Raw, chain)
	if err != nil {
		writeBackendError(w, err)
		return
	}
	signature, err := session.SignDigest(ctx, digest)
	if err != nil {
		_ = be.Fail(context.WithoutCancel(ctx), req.Ticket, string(token.CodeOf(err)), messageOf[token.CodeOf(err)])
		writeTokenError(w, err)
		return
	}
	if pub, ok := cert.PublicKey.(*rsa.PublicKey); !ok || rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest, signature) != nil {
		_ = be.Fail(context.WithoutCancel(ctx), req.Ticket, string(token.CodeDevice), "The card returned an invalid signature")
		writeTokenError(w, token.Errorf(token.CodeDevice, "the card returned a signature that does not verify"))
		return
	}
	done, err := be.Complete(ctx, req.Ticket, signature)
	if err != nil {
		writeBackendError(w, err)
		return
	}
	info := certinfo.Parse(cert)
	s.opts.Logger.Info("signed", "provider", provider.Name(), "signer", info.DisplayName, "duration", time.Since(started).Round(time.Millisecond))
	writeJSON(w, http.StatusOK, map[string]any{"status": "completed", "signer": info, "request": done.Request})
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
	token.CodeMiddlewareMissing: "No CIE software found on this computer.",
	token.CodeNotPaired:         "This CIE is not set up on this computer yet.",
	token.CodeCardUnsupported:   "This card is not a supported CIE.",
	token.CodeCardUntrusted:     "This card could not be verified as a genuine CIE, so the PIN was not sent to it.",
	token.CodeNotFound:          "No signing certificate found on the card.",
	token.CodePinIncorrect:      "Wrong PIN.",
	token.CodePinInvalid:        "Type the 8 digits of your CIE PIN.",
	token.CodePinLocked:         "Your PIN is blocked. Unblock it with the PUK in the CIE ID app.",
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

func writeBackendError(w http.ResponseWriter, err error) {
	var be *backend.Error
	if errors.As(err, &be) {
		status := be.Status
		if status < 400 {
			status = http.StatusBadGateway
		}
		writeError(w, status, be.Code, be.Message)
		return
	}
	writeError(w, http.StatusBadGateway, "backend_unreachable", "Cannot reach the dashboard. Check your connection and try again.")
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": message}})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
