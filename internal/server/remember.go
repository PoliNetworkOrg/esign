package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"time"

	"github.com/PoliNetworkOrg/esign/internal/token"
)

// A PIN the user chose to remember stays in the agent's memory only, never on disk, and only while all of these hold:
//   - less than Options.RememberFor has passed since it was typed (the time is not extended by use);
//   - the card stays on the reader: the agent checks every Options.CardWatch and forgets the PIN when no provider
//     sees a card, so it is never sent to a card placed later;
//   - the card that accepts it is the one it was typed for (same certificate);
//   - no PIN error happens with it.
//
// It is usable only by the browser it was typed in, which holds a random key in an HttpOnly, SameSite=Strict
// cookie, and only through the agent's own page: every signature still needs the user to press Sign.

// DefaultRememberFor is how long a remembered PIN lasts unless Options.RememberFor says otherwise.
const DefaultRememberFor = 30 * time.Minute

const (
	rememberCookie   = "pn_esign_pin"
	defaultCardWatch = 2 * time.Second
)

// remembered is a PIN kept for a while. Its fields do not change after it is created, except pin, which is wiped
// when it is forgotten.
type remembered struct {
	pin     []byte
	key     string // the browser's cookie value
	cert    []byte // the certificate of the card that accepted the PIN
	signer  string
	expires time.Time
	done    chan struct{}
}

// rememberedInfo tells the page that a PIN is remembered, never the PIN.
type rememberedInfo struct {
	Signer  string    `json:"signer"`
	Expires time.Time `json:"expires"`
}

// recall returns the PIN remembered for the browser making r, and a copy of it taken before the watcher can wipe
// it; nil when there is none.
func (s *Server) recall(r *http.Request) (*remembered, string) {
	c, err := r.Cookie(rememberCookie)
	if err != nil || c.Value == "" {
		return nil, ""
	}
	s.memMu.Lock()
	defer s.memMu.Unlock()
	m := s.mem
	if m == nil || subtle.ConstantTimeCompare([]byte(c.Value), []byte(m.key)) != 1 || !time.Now().Before(m.expires) {
		return nil, ""
	}
	return m, string(m.pin)
}

// rememberedFor describes the remembered PIN of r's browser for the page, nil when there is none.
func (s *Server) rememberedFor(r *http.Request) *rememberedInfo {
	m, _ := s.recall(r)
	if m == nil {
		return nil
	}
	return &rememberedInfo{Signer: m.signer, Expires: m.expires}
}

// remember keeps pin for the browser w answers, in place of any PIN remembered before, and starts watching the card.
func (s *Server) remember(w http.ResponseWriter, pin string, cert []byte, signer string) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return
	}
	m := &remembered{
		pin:     []byte(pin),
		key:     base64.RawURLEncoding.EncodeToString(key),
		cert:    bytes.Clone(cert),
		signer:  signer,
		expires: time.Now().Add(s.opts.RememberFor),
		done:    make(chan struct{}),
	}
	s.memMu.Lock()
	old := s.mem
	s.mem = m
	s.memMu.Unlock()
	if old != nil {
		s.drop(old)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     rememberCookie,
		Value:    m.key,
		Path:     "/api/",
		MaxAge:   int(s.opts.RememberFor / time.Second),
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
	s.opts.Logger.Info("PIN remembered", "signer", signer, "until", m.expires.Format(time.TimeOnly))
	go s.watch(m)
}

// forget drops m if it is still the remembered PIN.
func (s *Server) forget(m *remembered, reason string) {
	s.memMu.Lock()
	current := s.mem == m
	if current {
		s.mem = nil
	}
	s.memMu.Unlock()
	if current {
		s.drop(m)
		s.opts.Logger.Info("PIN forgotten", "reason", reason)
	}
}

// forgetAll drops any remembered PIN.
func (s *Server) forgetAll(reason string) {
	s.memMu.Lock()
	m := s.mem
	s.memMu.Unlock()
	if m != nil {
		s.forget(m, reason)
	}
}

// drop wipes m's PIN and stops its watcher. Only the goroutine that took m out of s.mem calls it.
func (s *Server) drop(m *remembered) {
	clear(m.pin)
	close(m.done)
}

func clearRememberCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: rememberCookie, Path: "/api/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode})
}

// watch forgets m when it expires or when the card leaves the reader.
func (s *Server) watch(m *remembered) {
	expiry := time.NewTimer(time.Until(m.expires))
	defer expiry.Stop()
	tick := time.NewTicker(s.opts.CardWatch)
	defer tick.Stop()
	for {
		select {
		case <-m.done:
			return
		case <-expiry.C:
			s.forget(m, "expired")
			return
		case <-tick.C:
			// While a signature runs the card is in use, and the signature itself fails without it.
			if !s.card.TryLock() {
				continue
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			gone := cardGone(s.statuses(ctx).Providers)
			cancel()
			if gone {
				// Before the card is free: a signature waiting for it then finds no PIN to send to a card placed later.
				s.forget(m, "card removed")
			}
			s.card.Unlock()
			if gone {
				return
			}
		}
	}
}

// cardGone reports whether the providers agree that no card is on a reader: none sees one, and at least one can
// tell, or no provider is usable at all (the reader was unplugged).
func cardGone(statuses []token.Status) bool {
	usable, absent := false, false
	for _, st := range statuses {
		if !st.Available {
			continue
		}
		usable = true
		if st.CardPresent != nil {
			if *st.CardPresent {
				return false
			}
			absent = true
		}
	}
	return absent || !usable
}

func (s *Server) forgetPIN(w http.ResponseWriter, r *http.Request) {
	s.forgetAll("forgotten by the user")
	clearRememberCookie(w)
	writeJSON(w, http.StatusOK, map[string]string{"status": "forgotten"})
}
