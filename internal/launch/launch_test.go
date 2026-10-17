package launch_test

import (
	"net"
	"net/http"
	"testing"

	"github.com/PoliNetworkOrg/esign/internal/launch"
	"github.com/PoliNetworkOrg/esign/internal/server"
)

func TestValidURL(t *testing.T) {
	cases := map[string]bool{
		"polinetwork-esign://open":                    true,
		"polinetwork-esign://open/":                   true,
		"polinetwork-esign://open?x=1":                false,
		"polinetwork-esign://open/--pkcs11=/tmp/x.so": false,
		"polinetwork-esign://install":                 false,
		"POLINETWORK-ESIGN://open":                    false,
		"polinetwork-esign://open\" --dev":            false,
		"":                                            false,
	}
	for u, want := range cases {
		if got := launch.ValidURL(u); got != want {
			t.Errorf("ValidURL(%q) = %v", u, got)
		}
	}
}

func TestProbe(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if _, ok := launch.Probe(t.Context(), port); ok {
		t.Fatal("probe answered before the server started")
	}
	srv := &http.Server{Handler: server.New(server.Options{Port: port, Version: "1.2.3"}).Handler()}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	if v, ok := launch.Probe(t.Context(), port); !ok || v != "1.2.3" {
		t.Fatalf("probe: %q %v", v, ok)
	}
	if !launch.PortInUse(port) {
		t.Fatal("port not in use")
	}
}

func TestProbeIgnoresOtherServers(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Header().Set("Server", "nginx") })}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	if _, ok := launch.Probe(t.Context(), port); ok {
		t.Fatal("another server taken for the agent")
	}
	if !launch.PortInUse(port) {
		t.Fatal("port not in use")
	}
}
