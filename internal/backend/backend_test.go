package backend

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const ticket = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

func TestPrepareAndComplete(t *testing.T) {
	sum := sha256.Sum256([]byte("signed attributes"))
	status := "next"
	old := false // a backend older than protocol 2, which sends no steps
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		switch {
		case strings.HasSuffix(r.URL.Path, "/prepare"):
			if body["protocol"] != float64(Protocol) {
				w.WriteHeader(http.StatusUpgradeRequired)
				_, _ = w.Write([]byte(`{"error":{"code":"agent_outdated","message":"Update the agent."}}`))
				return
			}
			res := map[string]any{"toBeSigned": base64.StdEncoding.EncodeToString(sum[:]), "algorithm": "RSASSA-PKCS1-v1_5-SHA256", "step": 1, "steps": 3}
			if old {
				delete(res, "step")
				delete(res, "steps")
			}
			_ = json.NewEncoder(w).Encode(res)
		case strings.HasSuffix(r.URL.Path, "/complete"):
			_, _ = w.Write([]byte(`{"status":"` + status + `","request":{"status":"in_progress","remaining":1}}`))
		}
	}))
	defer srv.Close()
	c := New(srv.URL, "test")

	p, err := c.Prepare(t.Context(), ticket, []byte("cert"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(p.Digest) != string(sum[:]) || p.Step != 1 || p.Steps != 3 {
		t.Errorf("prepared: %+v", p)
	}
	old = true
	if p, err := c.Prepare(t.Context(), ticket, []byte("cert"), nil); err != nil || p.Step != 0 || p.Steps != 1 {
		t.Errorf("backend without steps: %+v %v", p, err)
	}
	for _, s := range []string{"next", "completed"} {
		status = s
		if done, err := c.Complete(t.Context(), ticket, []byte("sig")); err != nil || done.Status != s {
			t.Errorf("complete %s: %v %v", s, done, err)
		}
	}
	status = "pending"
	if _, err := c.Complete(t.Context(), ticket, []byte("sig")); err == nil {
		t.Error("unknown status accepted")
	}
}
