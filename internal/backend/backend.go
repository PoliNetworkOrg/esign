// Package backend calls the dashboard's signing endpoints for a job, authenticated by its single-use ticket.
package backend

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"time"
)

// TicketPattern is the ticket format: 32 random bytes, base64url without padding.
var TicketPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

// Job describes what the user is about to sign.
type Job struct {
	ID        string    `json:"id"`
	Status    string    `json:"status"`
	ExpiresAt time.Time `json:"expiresAt"`
	Document  struct {
		Title    string `json:"title"`
		FileName string `json:"fileName"`
		Pages    int    `json:"pages"`
	} `json:"document"`
	Signer struct {
		Name string `json:"name"`
		Role string `json:"role,omitempty"`
	} `json:"signer"`
	Placement struct {
		Page int `json:"page"`
	} `json:"placement"`
	RequestedBy string `json:"requestedBy,omitempty"`
	// Signatures is how many signatures this signer still has to add: one per place, each a separate PDF revision.
	Signatures int `json:"signatures"`
	// Marks is how many extra copies of the first signature's appearance it draws elsewhere in the document.
	Marks int `json:"marks"`
	// Pages are the 0-based pages with this signer's boxes, ascending.
	Pages []int `json:"pages"`
}

// Protocol is the agent protocol version sent with prepare: 2 signs several places, one digest per step.
const Protocol = 2

// Prepared is a digest to sign, step Step (0-based) of the job's Steps remaining signatures.
type Prepared struct {
	Digest []byte
	Step   int
	Steps  int
}

// Completion is the backend's answer to a completed signature.
type Completion struct {
	// Status is "next" when the job needs another signature (prepare again) or "completed".
	Status  string `json:"status"`
	Request struct {
		Status    string `json:"status"`
		Remaining int    `json:"remaining"`
	} `json:"request"`
}

// Error is an error answer from the backend.
type Error struct {
	Status  int
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *Error) Error() string { return fmt.Sprintf("%s (%d): %s", e.Code, e.Status, e.Message) }

// Client talks to one dashboard origin.
type Client struct {
	origin string
	http   *http.Client
	ua     string
}

// New returns a client for origin, which the caller has checked against the allowlist.
func New(origin, version string) *Client {
	return &Client{
		origin: origin,
		http: &http.Client{
			Timeout: 60 * time.Second,
			// The ticket is a bearer capability: never follow a redirect elsewhere with it.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		ua: "PoliNetwork-eSign/" + version,
	}
}

func (c *Client) url(ticket, action string) string {
	u := c.origin + "/api/esign/agent/jobs/" + url.PathEscape(ticket)
	if action != "" {
		u += "/" + action
	}
	return u
}

func (c *Client) do(ctx context.Context, method, url string, body, out any) error {
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.ua)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("cannot reach %s: %w", c.origin, err)
	}
	defer res.Body.Close()
	data, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return err
	}
	if res.StatusCode >= 300 {
		var wrapped struct {
			Error *Error `json:"error"`
		}
		if json.Unmarshal(data, &wrapped) == nil && wrapped.Error != nil {
			wrapped.Error.Status = res.StatusCode
			return wrapped.Error
		}
		return &Error{Status: res.StatusCode, Code: "http_error", Message: http.StatusText(res.StatusCode)}
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(data, out)
}

// Job fetches the job.
func (c *Client) Job(ctx context.Context, ticket string) (*Job, error) {
	var res struct {
		Job *Job `json:"job"`
	}
	if err := c.do(ctx, http.MethodGet, c.url(ticket, ""), nil, &res); err != nil {
		return nil, err
	}
	if res.Job == nil {
		return nil, errors.New("empty job")
	}
	return res.Job, nil
}

// Prepare sends the signer's certificate and returns the SHA-256 digest of the job's next signature.
func (c *Client) Prepare(ctx context.Context, ticket string, certificate []byte, chain [][]byte) (*Prepared, error) {
	body := map[string]any{"certificate": base64.StdEncoding.EncodeToString(certificate), "protocol": Protocol}
	if len(chain) > 0 {
		encoded := make([]string, len(chain))
		for i, c := range chain {
			encoded[i] = base64.StdEncoding.EncodeToString(c)
		}
		body["chain"] = encoded
	}
	var res struct {
		ToBeSigned string `json:"toBeSigned"`
		Algorithm  string `json:"algorithm"`
		Step       int    `json:"step"`
		Steps      int    `json:"steps"`
	}
	if err := c.do(ctx, http.MethodPost, c.url(ticket, "prepare"), body, &res); err != nil {
		return nil, err
	}
	if res.Algorithm != "RSASSA-PKCS1-v1_5-SHA256" {
		return nil, fmt.Errorf("unsupported algorithm %q", res.Algorithm)
	}
	digest, err := base64.StdEncoding.DecodeString(res.ToBeSigned)
	if err != nil || len(digest) != 32 {
		return nil, errors.New("malformed digest from the server")
	}
	// A backend older than protocol 2 sends no steps: its jobs have one signature.
	if res.Steps == 0 && res.Step == 0 {
		res.Steps = 1
	}
	if res.Step < 0 || res.Step >= res.Steps {
		return nil, fmt.Errorf("malformed step %d of %d from the server", res.Step, res.Steps)
	}
	return &Prepared{Digest: digest, Step: res.Step, Steps: res.Steps}, nil
}

// Complete sends the signature. On "next" the job needs another prepare and signature.
func (c *Client) Complete(ctx context.Context, ticket string, signature []byte) (*Completion, error) {
	var res Completion
	err := c.do(ctx, http.MethodPost, c.url(ticket, "complete"), map[string]string{"signature": base64.StdEncoding.EncodeToString(signature)}, &res)
	if err != nil {
		return nil, err
	}
	if res.Status != "next" && res.Status != "completed" {
		return nil, fmt.Errorf("unexpected status %q from the server", res.Status)
	}
	return &res, nil
}

// Fail records why the signature did not happen, so the dashboard can tell the user.
func (c *Client) Fail(ctx context.Context, ticket, code, message string) error {
	return c.do(ctx, http.MethodPost, c.url(ticket, "fail"), map[string]string{"code": code, "message": message}, nil)
}
