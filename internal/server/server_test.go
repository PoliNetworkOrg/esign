package server

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/PoliNetworkOrg/sign-agent/internal/token"
	"github.com/PoliNetworkOrg/sign-agent/internal/token/soft"
)

const origin = "https://admin.polinetwork.org"

func newTestServer(t *testing.T) (*Server, *soft.Provider) {
	t.Helper()
	p, err := soft.New("12345678")
	if err != nil {
		t.Fatal(err)
	}
	return New(Options{Port: 47321, AllowedOrigins: []string{origin, "http://localhost:*"}, Providers: []token.Provider{p}, Version: "test"}), p
}

func do(t *testing.T, s *Server, method, path, host, org string, body any, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Host = host
	if org != "" {
		req.Header.Set("Origin", org)
	}
	if method != http.MethodOptions {
		req.Header.Set(APIHeader, "1")
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	return rec
}

func TestOriginAllowed(t *testing.T) {
	allowed := []string{origin, "http://localhost:*"}
	cases := map[string]bool{
		origin:                               true,
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
	s, _ := newTestServer(t)
	if rec := do(t, s, "GET", "/v1/status", "evil.example:47321", origin, nil, nil); rec.Code != http.StatusMisdirectedRequest {
		t.Errorf("rebinding host: got %d", rec.Code)
	}
	if rec := do(t, s, "GET", "/v1/status", "127.0.0.1:47322", origin, nil, nil); rec.Code != http.StatusMisdirectedRequest {
		t.Errorf("wrong port: got %d", rec.Code)
	}
	if rec := do(t, s, "GET", "/v1/status", "127.0.0.1:47321", "https://evil.example", nil, nil); rec.Code != http.StatusForbidden {
		t.Errorf("foreign origin: got %d", rec.Code)
	}
	if rec := do(t, s, "GET", "/v1/status", "127.0.0.1:47321", "", nil, nil); rec.Code != http.StatusForbidden {
		t.Errorf("no origin: got %d", rec.Code)
	}
	if rec := do(t, s, "GET", "/v1/status", "127.0.0.1:47321", origin, nil, map[string]string{APIHeader: "0"}); rec.Code != http.StatusBadRequest {
		t.Errorf("missing header: got %d", rec.Code)
	}
	rec := do(t, s, "OPTIONS", "/v1/sign", "localhost:47321", origin, nil, map[string]string{"Access-Control-Request-Private-Network": "true"})
	if rec.Code != http.StatusNoContent || rec.Header().Get("Access-Control-Allow-Private-Network") != "true" || rec.Header().Get("Access-Control-Allow-Origin") != origin {
		t.Errorf("preflight: %d %v", rec.Code, rec.Header())
	}
	if rec := do(t, s, "GET", "/", "127.0.0.1:47321", "", nil, nil); rec.Code != http.StatusOK {
		t.Errorf("home: got %d", rec.Code)
	}
}

func TestSignFlow(t *testing.T) {
	s, _ := newTestServer(t)
	host := "127.0.0.1:47321"

	rec := do(t, s, "GET", "/v1/certificates", host, origin, nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("certificates: %d %s", rec.Code, rec.Body)
	}
	var certs struct {
		Certificates []certificateJSON `json:"certificates"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &certs); err != nil || len(certs.Certificates) != 1 {
		t.Fatalf("certificates body: %v %s", err, rec.Body)
	}
	c := certs.Certificates[0]
	if c.Subject.FiscalCode != "SVLPRV80A01F205X" || c.Subject.DisplayName != "Prova Sviluppo" {
		t.Errorf("subject: %+v", c.Subject)
	}
	der, _ := base64.StdEncoding.DecodeString(c.Certificate)
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	digest := sha256.Sum256([]byte("signed attributes"))
	b64 := base64.StdEncoding.EncodeToString(digest[:])

	rec = do(t, s, "POST", "/v1/sign", host, origin, signRequest{CertificateID: c.ID, Digest: b64, PIN: "00000000"}, nil)
	var wrong struct {
		Error struct {
			Code        string `json:"code"`
			RetriesLeft int    `json:"retriesLeft"`
		} `json:"error"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &wrong)
	if rec.Code != http.StatusUnauthorized || wrong.Error.Code != "pin_incorrect" || wrong.Error.RetriesLeft != 2 {
		t.Fatalf("wrong pin: %d %s", rec.Code, rec.Body)
	}

	rec = do(t, s, "POST", "/v1/sign", host, origin, signRequest{CertificateID: c.ID, Digest: b64, PIN: "12345678"}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("sign: %d %s", rec.Code, rec.Body)
	}
	var signed struct {
		Signature string `json:"signature"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &signed)
	sig, _ := base64.StdEncoding.DecodeString(signed.Signature)
	if err := rsa.VerifyPKCS1v15(cert.PublicKey.(*rsa.PublicKey), crypto.SHA256, digest[:], sig); err != nil {
		t.Fatalf("signature does not verify: %v", err)
	}

	rec = do(t, s, "POST", "/v1/sign", host, origin, signRequest{CertificateID: c.ID, Digest: "AAAA", PIN: "12345678"}, nil)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("short digest: %d", rec.Code)
	}
}

func TestPinLock(t *testing.T) {
	s, p := newTestServer(t)
	certs, _ := p.Certificates(t.Context())
	digest := base64.StdEncoding.EncodeToString(make([]byte, 32))
	codes := []int{http.StatusUnauthorized, http.StatusUnauthorized, http.StatusLocked, http.StatusLocked}
	for i, want := range codes {
		pin := "00000000"
		if i == 3 {
			pin = "12345678"
		}
		rec := do(t, s, "POST", "/v1/sign", "127.0.0.1:47321", origin, signRequest{CertificateID: certs[0].ID, Digest: digest, PIN: pin}, nil)
		if rec.Code != want {
			t.Errorf("attempt %d: got %d want %d (%s)", i+1, rec.Code, want, rec.Body)
		}
	}
}
