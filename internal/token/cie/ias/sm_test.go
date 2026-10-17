package ias

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestICAOWorkedExample checks the secure messaging codec against the worked example of ICAO Doc 9303 part 11,
// appendix D.4, which uses the same construction as IAS (3DES-CBC with zero IV, retail MAC over the padded
// SSC||header followed by the data objects). It is independent of the card simulator.
func TestICAOWorkedExample(t *testing.T) {
	s := &smState{
		kenc: unhex(t, "979EC13B1CBFE9DCD01AB0FED307EAE5"),
		kmac: unhex(t, "F1CB1F1FB5ADF208806B89DC579DC1F8"),
		ssc:  unhex(t, "887022120C06C226"),
	}
	got, err := s.wrap(command{cla: 0x00, ins: 0xA4, p1: 0x02, p2: 0x0C, data: []byte{0x01, 0x1E}})
	if err != nil {
		t.Fatal(err)
	}
	if want := unhex(t, "0CA4020C158709016375432908C044F68E08BF8B92D635FF24F800"); !bytes.Equal(got, want) {
		t.Fatalf("select:\n got %X\nwant %X", got, want)
	}
	data, sw, err := s.unwrap(unhex(t, "990290008E08FA855A5D4C50A8ED"))
	if err != nil || sw != SWOK || len(data) != 0 {
		t.Fatalf("select response: %X %04X %v", data, sw, err)
	}

	got, err = s.wrap(command{cla: 0x00, ins: 0xB0, p1: 0x00, p2: 0x00, le: le(4)})
	if err != nil {
		t.Fatal(err)
	}
	if want := unhex(t, "0CB000000D9701048E08ED6705417E96BA5500"); !bytes.Equal(got, want) {
		t.Fatalf("read binary:\n got %X\nwant %X", got, want)
	}
	data, sw, err = s.unwrap(unhex(t, "8709019FF0EC34F9922651990290008E08AD55CC17140B2DED"))
	if err != nil || sw != SWOK || !bytes.Equal(data, unhex(t, "60145F01")) {
		t.Fatalf("read binary response: %X %04X %v", data, sw, err)
	}

	// A tampered response must fail and must not be decrypted.
	s.ssc = unhex(t, "887022120C06C229")
	if _, _, err := s.unwrap(unhex(t, "8709019FF0EC34F9922651990290008E08AD55CC17140B2DEE")); err != errMAC {
		t.Fatalf("tampered MAC: %v", err)
	}
}

func TestPadding(t *testing.T) {
	for n := 0; n < 20; n++ {
		p := Pad(bytes.Repeat([]byte{0x11}, n))
		if len(p)%8 != 0 || len(p) <= n || p[n] != 0x80 {
			t.Fatalf("pad %d: %X", n, p)
		}
		u, err := Unpad(p)
		if err != nil || len(u) != n {
			t.Fatalf("unpad %d: %v", n, err)
		}
	}
	if _, err := Unpad([]byte{1, 2, 3, 0, 0, 0, 0, 0}); err == nil {
		t.Fatal("accepted missing 80")
	}
}

func TestTLV(t *testing.T) {
	enc := EncodeTLV(0x7F21, append(EncodeTLV(0x5F37, make([]byte, 256)), EncodeTLV(0x42, []byte{1, 2})...))
	top, rest, err := ParseTLV(enc)
	if err != nil || len(rest) != 0 || top.Tag != 0x7F21 {
		t.Fatalf("%v %X", err, top.Tag)
	}
	kids, err := ParseTLVs(top.Value)
	if err != nil || len(kids) != 2 || kids[0].Tag != 0x5F37 || len(kids[0].Value) != 256 || kids[1].Tag != 0x42 {
		t.Fatalf("children: %v %+v", err, kids)
	}
	v, err := Path(EncodeTLV(0x70, EncodeTLV(0xBFA101, EncodeTLV(0xA3, EncodeTLV(0x97, []byte{2})))), 0x70, 0xBFA101, 0xA3, 0x97)
	if err != nil || !bytes.Equal(v.Value, []byte{2}) {
		t.Fatalf("path: %v %X", err, v.Value)
	}
	if _, _, err := ParseTLV([]byte{0x30, 0x82, 0x01}); err == nil {
		t.Fatal("accepted truncated length")
	}
}

func TestIdentify(t *testing.T) {
	tests := []struct {
		atr  string
		want Family
	}{
		{"3B8F80018031806549544E5850120FFF82900000", FamilyNXP},
		{"3B8F8001803180659B085040011120FFF8290000", FamilyUnknown},
		{"3B8F8001803180654954 4A3443120FFF8290008A", FamilyActalis},
		{"3B8F80018031806549544A3449120FFF82900080", FamilyBit4id},
		{"3B8F80018031806549544A344F120FFF8290008F", FamilyActalis}, // unlisted ITJ4 batch
		{"3B8E800180318065B08504001112 0FFF829000", FamilyGemalto},
		{"3B8A80018066475000B8007F00", FamilySTM},
	}
	for _, tc := range tests {
		atr := unhex(t, stripSpaces(tc.atr))
		if got, _ := Identify(atr); got != tc.want {
			t.Errorf("%s: got %v want %v", tc.atr, got, tc.want)
		}
	}
}

func stripSpaces(s string) string { return string(bytes.ReplaceAll([]byte(s), []byte(" "), nil)) }
