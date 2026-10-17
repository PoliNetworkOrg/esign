// Package launch finds a running agent, starts one when needed, and handles the polinetwork-esign:// link the
// dashboard offers when the agent is not running.
package launch

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Scheme is the URL scheme registered for the agent.
const Scheme = "polinetwork-esign"

// OpenURL is the only link the agent acts on: it starts the agent. Links carry no arguments, so a web page cannot
// make the agent do anything but start.
const OpenURL = Scheme + "://open"

// ValidURL reports whether u is the agent's link, OpenURL, optionally with a trailing slash.
func ValidURL(u string) bool {
	return u == OpenURL || u == OpenURL+"/"
}

// ServerHeader prefixes the Server header the agent sends, followed by its version.
const ServerHeader = "PoliNetwork-eSign/"

// Probe returns the version of the agent listening on the loopback port, or ok=false when none answers there.
func Probe(ctx context.Context, port int) (version string, ok bool) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	url := "http://" + net.JoinHostPort("127.0.0.1", strconv.Itoa(port)) + "/"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", false
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := client.Do(req)
	if err != nil {
		return "", false
	}
	defer res.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 64<<10))
	return strings.CutPrefix(res.Header.Get("Server"), ServerHeader)
}

// PortInUse reports whether something, agent or not, listens on the loopback port.
func PortInUse(port int) bool {
	c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), time.Second)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

// WaitRunning waits until an agent answers on port.
func WaitRunning(ctx context.Context, port int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for {
		if _, ok := Probe(ctx, port); ok {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(250 * time.Millisecond):
		}
	}
}

// EnsureRunning starts the agent unless one already answers on port: through start (the login service, when
// installed), else by running exe serve in the background.
func EnsureRunning(ctx context.Context, port int, exe string, start func() error) error {
	if _, ok := Probe(ctx, port); ok {
		return nil
	}
	if start == nil || start() != nil {
		if err := SpawnDetached(exe, "serve"); err != nil {
			return err
		}
	}
	if !WaitRunning(ctx, port, 15*time.Second) {
		return fmt.Errorf("the agent did not start on port %d", port)
	}
	return nil
}
