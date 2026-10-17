package worker

import (
	"testing"

	"github.com/PoliNetworkOrg/sign-agent/internal/token"
)

// TestWirePINSent: the worker must not lose the mark that keeps the agent from trying another provider.
func TestWirePINSent(t *testing.T) {
	in := token.AfterPIN(&token.Error{Code: token.CodeNotPaired, RetriesLeft: -1})
	out := toWire(in).err()
	if !token.PINSent(out) || token.CodeOf(out) != token.CodeNotPaired {
		t.Fatalf("got %v", out)
	}
	if token.PINSent(toWire(token.Errorf(token.CodeNoCard, "x")).err()) {
		t.Fatal("unmarked error marked")
	}
}
