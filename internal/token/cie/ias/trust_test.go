package ias

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"
)

// TestItalianCSCAs checks the embedded anchors against the fingerprints recorded in csca/SHA256SUMS (and in
// trust.go), and that each one is a self-signed CA this package can verify, including the SHA-1 and RSA-PSS ones.
func TestItalianCSCAs(t *testing.T) {
	sums, err := cscaFiles.ReadFile("csca/SHA256SUMS")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(sums))
	for sc.Scan() {
		var sum, name string
		if _, err := fmt.Sscan(sc.Text(), &sum, &name); err == nil {
			want[name] = sum
		}
	}
	entries, _ := cscaFiles.ReadDir("csca")
	n := 0
	for _, e := range entries {
		if e.Name() == "SHA256SUMS" {
			continue
		}
		n++
		der, _ := cscaFiles.ReadFile("csca/" + e.Name())
		got := sha256.Sum256(der)
		if hex.EncodeToString(got[:]) != want[e.Name()] {
			t.Errorf("%s: SHA-256 %x does not match SHA256SUMS", e.Name(), got)
		}
	}
	anchors := ItalianCSCAs()
	if n != 6 || len(anchors) != 6 {
		t.Fatalf("%d files, %d anchors", n, len(anchors))
	}
	for _, a := range anchors {
		if err := issuedBy(a, a); err != nil {
			t.Errorf("%s (%v): %v", a.Subject, a.SignatureAlgorithm, err)
		}
	}
	// CSCA04 and CSCA05 share their name: only the right key verifies.
	if err := issuedBy(anchors[5], anchors[4]); err == nil {
		t.Error("CSCA05 verified with CSCA04's key")
	}
}

func TestVerifySODRejectsGarbage(t *testing.T) {
	for _, b := range [][]byte{nil, {0x77, 0x00}, {0x30, 0x03, 0x06, 0x01, 0x00}} {
		if _, err := VerifySOD(b, ItalianCSCAs()); err == nil {
			t.Errorf("accepted %X", b)
		}
	}
}
