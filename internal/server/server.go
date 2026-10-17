// Package server is the agent's loopback HTTP API, called by the dashboard from the user's browser.
//
// Every /v1 request must come from an allowed Origin, address the agent by a loopback Host (no DNS rebinding) and
// carry the X-PN-Sign-Agent header, which forces a CORS preflight. The PIN is only ever held for one signature.
package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/PoliNetworkOrg/sign-agent/internal/certinfo"
	"github.com/PoliNetworkOrg/sign-agent/internal/token"
)

// APIHeader must be sent on every /v1 request. A custom header makes browsers preflight even simple requests.
const APIHeader = "X-PN-Sign-Agent"

// APIVersion is the protocol version the dashboard checks.
const APIVersion = 1

// Options configures the server.
type Options struct {
	// Port the agent listens on; Host headers must name it.
	Port int
	// AllowedOrigins are exact origins ("https://admin.polinetwork.org") or a loopback origin with any port
	// ("http://localhost:*", "http://127.0.0.1:*").
	AllowedOrigins []string
	Providers      []token.Provider
	Version        string
	Logger         *slog.Logger
}

// Server serves the API.
type Server struct {
	opts Options
	// card serializes card access: the middleware and the card handle one operation at a time.
	card sync.Mutex
}

// New returns a server.
func New(opts Options) *Server {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	return &Server{opts: opts}
}

// Handler returns the HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.home)
	mux.HandleFunc("GET /v1/status", s.status)
	mux.HandleFunc("GET /v1/certificates", s.certificates)
	mux.HandleFunc("POST /v1/sign", s.sign)
	return s.guard(mux)
}

// ListenAndServe serves on 127.0.0.1 until ctx ends.
func (s *Server) ListenAndServe(ctx context.Context) error {
	srv := &http.Server{
		Addr:              net.JoinHostPort("127.0.0.1", strconv.Itoa(s.opts.Port)),
		Handler:           s.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		// Signing waits for the card, which can take several seconds on contactless readers.
		WriteTimeout:   90 * time.Second,
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
	return h == "127.0.0.1" || h == "localhost" || h == "::1"
}

// OriginAllowed reports whether origin may call the API.
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
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if !s.hostAllowed(r.Host) {
			writeError(w, http.StatusMisdirectedRequest, "forbidden_host", "Address the agent as 127.0.0.1 or localhost")
			return
		}
		if !strings.HasPrefix(r.URL.Path, "/v1/") {
			next.ServeHTTP(w, r)
			return
		}
		origin := r.Header.Get("Origin")
		if !OriginAllowed(s.opts.AllowedOrigins, origin) {
			s.opts.Logger.Warn("rejected origin", "origin", origin, "path", r.URL.Path)
			writeError(w, http.StatusForbidden, "forbidden_origin", "This site may not use the signing agent")
			return
		}
		h := w.Header()
		h.Set("Access-Control-Allow-Origin", origin)
		h.Add("Vary", "Origin")
		if r.Method == http.MethodOptions {
			h.Set("Access-Control-Allow-Methods", "GET, POST")
			h.Set("Access-Control-Allow-Headers", "Content-Type, "+APIHeader)
			h.Set("Access-Control-Max-Age", "600")
			// Chrome's Private Network Access preflight (superseded by the Local Network Access prompt, still sent).
			if r.Header.Get("Access-Control-Request-Private-Network") == "true" {
				h.Set("Access-Control-Allow-Private-Network", "true")
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Header.Get(APIHeader) != strconv.Itoa(APIVersion) {
			writeError(w, http.StatusBadRequest, "missing_header", APIHeader+": "+strconv.Itoa(APIVersion)+" is required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) home(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("PoliNetwork Sign Agent " + s.opts.Version + " is running.\nReturn to the dashboard to sign documents.\n"))
}

type statusResponse struct {
	Agent      string         `json:"agent"`
	Version    string         `json:"version"`
	API        int            `json:"api"`
	OS         string         `json:"os"`
	Providers  []token.Status `json:"providers"`
	ServerTime time.Time      `json:"serverTime"`
}

func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	res := statusResponse{Agent: "polinetwork-sign-agent", Version: s.opts.Version, API: APIVersion, OS: osName(), ServerTime: time.Now().UTC()}
	for _, p := range s.opts.Providers {
		res.Providers = append(res.Providers, p.Status(ctx))
	}
	writeJSON(w, http.StatusOK, res)
}

type certificateJSON struct {
	ID          string        `json:"id"`
	Provider    string        `json:"provider"`
	Label       string        `json:"label"`
	Certificate string        `json:"certificate"`
	Subject     certinfo.Info `json:"subject"`
	Issuer      string        `json:"issuer"`
	NotBefore   time.Time     `json:"notBefore"`
	NotAfter    time.Time     `json:"notAfter"`
}

func (s *Server) certificates(w http.ResponseWriter, r *http.Request) {
	if !s.card.TryLock() {
		writeError(w, http.StatusConflict, string(token.CodeBusy), "The card is busy with another operation")
		return
	}
	defer s.card.Unlock()
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	out := []certificateJSON{}
	var firstErr error
	for _, p := range s.opts.Providers {
		if !p.Status(ctx).Available {
			continue
		}
		certs, err := p.Certificates(ctx)
		if err != nil {
			s.opts.Logger.Warn("list certificates", "provider", p.Name(), "error", err)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		for _, c := range certs {
			out = append(out, certificateJSON{
				ID:          c.ID,
				Provider:    c.Provider,
				Label:       c.Label,
				Certificate: base64.StdEncoding.EncodeToString(c.Cert.Raw),
				Subject:     certinfo.Parse(c.Cert),
				Issuer:      c.Cert.Issuer.CommonName,
				NotBefore:   c.Cert.NotBefore.UTC(),
				NotAfter:    c.Cert.NotAfter.UTC(),
			})
		}
	}
	if len(out) == 0 && firstErr != nil {
		writeTokenError(w, firstErr)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"certificates": out})
}

type signRequest struct {
	CertificateID string `json:"certificateId"`
	// Digest is the base64 SHA-256 digest to sign (for PAdES: of the DER-encoded signed attributes).
	Digest string `json:"digest"`
	PIN    string `json:"pin"`
}

func (s *Server) sign(w http.ResponseWriter, r *http.Request) {
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		writeError(w, http.StatusUnsupportedMediaType, "bad_request", "Send JSON")
		return
	}
	var req signRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "Malformed request")
		return
	}
	digest, err := base64.StdEncoding.DecodeString(req.Digest)
	if err != nil || len(digest) != 32 {
		writeError(w, http.StatusBadRequest, "bad_request", "digest must be a base64 SHA-256 digest")
		return
	}
	provider := s.providerOf(req.CertificateID)
	if provider == nil {
		writeError(w, http.StatusNotFound, string(token.CodeNotFound), "Certificate not found; reconnect the card")
		return
	}
	if !s.card.TryLock() {
		writeError(w, http.StatusConflict, string(token.CodeBusy), "The card is busy with another operation")
		return
	}
	defer s.card.Unlock()
	ctx, cancel := context.WithTimeout(r.Context(), 75*time.Second)
	defer cancel()
	started := time.Now()
	sig, err := provider.SignDigest(ctx, req.CertificateID, digest, req.PIN)
	if err != nil {
		s.opts.Logger.Warn("sign", "provider", provider.Name(), "code", token.CodeOf(err), "error", err)
		writeTokenError(w, err)
		return
	}
	s.opts.Logger.Info("signed digest", "provider", provider.Name(), "duration", time.Since(started).Round(time.Millisecond))
	writeJSON(w, http.StatusOK, map[string]string{
		"signature": base64.StdEncoding.EncodeToString(sig),
		"algorithm": "RSASSA-PKCS1-v1_5-SHA256",
	})
}

func (s *Server) providerOf(certID string) token.Provider {
	name, _, ok := strings.Cut(certID, ":")
	if !ok {
		return nil
	}
	for _, p := range s.opts.Providers {
		if p.Name() == name {
			return p
		}
	}
	return nil
}

var statusOf = map[token.Code]int{
	token.CodeNoReader:          http.StatusServiceUnavailable,
	token.CodeNoCard:            http.StatusServiceUnavailable,
	token.CodeCardRemoved:       http.StatusServiceUnavailable,
	token.CodeMiddlewareMissing: http.StatusServiceUnavailable,
	token.CodeCardUnsupported:   http.StatusUnprocessableEntity,
	token.CodeNotFound:          http.StatusNotFound,
	token.CodePinIncorrect:      http.StatusUnauthorized,
	token.CodePinInvalid:        http.StatusBadRequest,
	token.CodePinLocked:         http.StatusLocked,
	token.CodeBusy:              http.StatusConflict,
}

var messageOf = map[token.Code]string{
	token.CodeNoReader:          "No smart-card reader found. Connect the NFC reader.",
	token.CodeNoCard:            "No card on the reader. Place the CIE on the reader.",
	token.CodeCardRemoved:       "The card was moved away. Keep the CIE on the reader and try again.",
	token.CodeMiddlewareMissing: "The CIE software is not installed.",
	token.CodeCardUnsupported:   "This card is not a supported CIE.",
	token.CodeNotFound:          "Certificate not found. Reconnect the card.",
	token.CodePinIncorrect:      "Wrong PIN.",
	token.CodePinInvalid:        "The PIN must be the 8 digits of the CIE PIN.",
	token.CodePinLocked:         "The PIN is blocked. Unblock it with the PUK in the CIE ID app.",
	token.CodeBusy:              "The card is busy with another operation.",
	token.CodeDevice:            "The card could not complete the operation.",
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

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": message}})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
