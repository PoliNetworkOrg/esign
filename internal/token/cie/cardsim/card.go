// Package cardsim simulates a CIE 3.0 for tests: its file system, the DH parameters, the DAPP keys and the citizen
// key, the PIN and PUK counters, and IAS secure messaging, which it verifies on every protected command. It speaks
// the protocol of the official middleware (italia/cie-middleware-linux), so the same simulator can serve that
// middleware, OpenCIE and the agent's own implementation through a virtual reader.
package cardsim

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sync"
	"time"

	"github.com/PoliNetworkOrg/sign-agent/internal/token/cie/ias"
)

// Variant is the chip family the simulator imitates.
type Variant int

const (
	// NXP selects IAS through the MF and serves the DH parameters one GET DATA at a time.
	NXP Variant = iota
	// Gemalto selects IAS by AID and serves the DH parameters in one GET DATA.
	Gemalto
	// Unlisted has an ATR no CIE table knows, NXP behavior, and no IAS AID: the client must probe.
	Unlisted
)

// Options configures a simulated card.
type Options struct {
	Variant  Variant
	PIN      string // 8 digits, default 12345678
	PUK      string // 8 digits, default 87654321
	Identity Identity
	// Keys default to a freshly generated set.
	Keys *Keys
	// Rand supplies DH exponents and challenges; crypto/rand when nil.
	Rand io.Reader

	// UnprotectedErrors answers failed protected commands with a bare status word, without secure messaging
	// (some cards do; the reference accepts both).
	UnprotectedErrors bool
	// ShortReadsWith6C answers a READ BINARY that runs past the end of the file with 6Cxx instead of the remaining
	// bytes and 6282.
	ShortReadsWith6C bool
	// PublicValueLeadingZero makes the card's DH public value start with a zero byte; MinimalPublicValue then sends
	// it without that byte.
	PublicValueLeadingZero bool
	MinimalPublicValue     bool
	// CertificateFileSize pads EF 1003 with zeros to this size, like a fixed-size file on a card.
	CertificateFileSize int
}

const (
	pinTries = 3
	pukTries = 10
)

type file struct {
	df        int
	data      []byte
	protected bool // readable only through SM after VERIFY PIN
}

const (
	dfNone = iota
	dfIAS
	dfCIE
)

// Card is a simulated CIE. It is safe for concurrent use; each Transmit is atomic.
type Card struct {
	mu    sync.Mutex
	opts  Options
	keys  *Keys
	pki   *pki
	atr   []byte
	files map[uint16]file
	snICC []byte

	pin, puk          string
	pinLeft, pukLeft  int
	rootCHR, rootCHA  []byte
	transmits, resets int

	s state
}

// state is everything a reset clears.
type state struct {
	df  int
	ef  uint16
	sm  *channel
	dh  *dhState
	sel struct {
		verifyRoot bool   // MSE SET 81 B6: CV root selected for PSO VERIFY CERTIFICATE
		extAuthCHR []byte // MSE SET 81 A4: terminal key selected for EXTERNAL AUTHENTICATE
		intKey     byte   // MSE SET 41 A4: key for INTERNAL AUTHENTICATE (81, 82, 83)
	}
	terminal         *rsa.PublicKey
	terminalCHR      []byte
	challenge        []byte // last GET CHALLENGE, consumed by EXTERNAL AUTHENTICATE
	dappChallenge    []byte // RND.ICC of the successful EXTERNAL AUTHENTICATE
	terminalAuth     bool
	chipAuth         bool
	pinOK, pukOK     bool
	chainINS         byte
	chainData        []byte
	chaining         bool
	pending          []byte
	afterResponseSSC []byte
}

type channel struct {
	kenc, kmac, ssc []byte
	used            bool // a protected command arrived: from now on a plain command ends the channel
}

type dhState struct {
	x          *big.Int
	yICC, yIFD []byte
}

// New personalizes a simulated card.
func New(opts Options) (*Card, error) {
	if opts.PIN == "" {
		opts.PIN = "12345678"
	}
	if opts.PUK == "" {
		opts.PUK = "87654321"
	}
	if opts.Identity == (Identity{}) {
		opts.Identity = DefaultIdentity
	}
	keys := opts.Keys
	if keys == nil {
		var err error
		if keys, err = GenerateKeys(); err != nil {
			return nil, err
		}
	}
	c := &Card{opts: opts, keys: keys, pin: opts.PIN, puk: opts.PUK, pinLeft: pinTries, pukLeft: pukTries}
	var err error
	if c.pki, err = makePKI(opts.Identity, keys, time.Now()); err != nil {
		return nil, err
	}
	if err := c.personalize(); err != nil {
		return nil, err
	}
	switch opts.Variant {
	case Gemalto:
		c.atr = withTCK([]byte{0x3B, 0x8F, 0x80, 0x01, 0x80, 0x31, 0x80, 0x65, 0xB0, 0x85, 0x04, 0x00, 0x11, 0x12, 0x0F, 0xFF, 0x82, 0x90, 0x00})
	case Unlisted:
		c.atr = withTCK([]byte{0x3B, 0x88, 0x80, 0x01, 0x53, 0x49, 0x4D, 0x2D, 0x43, 0x49, 0x45, 0x00})
	default:
		c.atr = withTCK([]byte{0x3B, 0x8F, 0x80, 0x01, 0x80, 0x31, 0x80, 0x65, 0x49, 0x54, 0x4E, 0x58, 0x50, 0x12, 0x0F, 0xFF, 0x82, 0x90, 0x00})
	}
	return c, nil
}

// withTCK appends the ATR check byte: the XOR of T0 through the last historical byte.
func withTCK(atr []byte) []byte {
	var x byte
	for _, b := range atr[1:] {
		x ^= b
	}
	return append(atr, x)
}

func (c *Card) personalize() error {
	id := c.opts.Identity
	p, err := pan(id.NIS)
	if err != nil {
		return err
	}
	if len(id.Serial) != 9 {
		return errors.New("serial must be 9 characters")
	}
	cert := append([]byte{}, c.pki.citizen.Raw...)
	if n := c.opts.CertificateFileSize; n > len(cert) {
		cert = append(cert, make([]byte, n-len(cert))...)
	}
	intAuth := x509.MarshalPKCS1PublicKey(&c.keys.IntAuth.PublicKey)
	service := x509.MarshalPKCS1PublicKey(&c.keys.Service.PublicKey)
	dh := dhFile()
	c.files = map[uint16]file{
		ias.FilePAN:         {df: dfIAS, data: p},
		ias.FileDH:          {df: dfIAS, data: dh},
		ias.FileServiceID:   {df: dfCIE, data: []byte(id.NIS)},
		ias.FileSerial:      {df: dfCIE, data: []byte(id.Serial), protected: true},
		ias.FileCertificate: {df: dfCIE, data: cert, protected: true},
		ias.FileIntAuthKey:  {df: dfCIE, data: intAuth},
		ias.FileServiceKey:  {df: dfCIE, data: service},
	}
	s, err := sod(map[byte][]byte{
		0xA1: sum([]byte(id.NIS)),
		0xA2: sum([]byte(id.Serial)),
		0xA3: sum(c.pki.citizen.Raw),
		0xA4: sum(intAuth),
		0xA5: sum(service),
		0x1B: sum(dh),
	}, c.pki.docSigner, c.keys.DocSigner)
	if err != nil {
		return err
	}
	c.files[ias.FileSOD] = file{df: dfCIE, data: s}
	c.snICC = sum([]byte("SN.ICC" + id.NIS))[:8]
	c.rootCHR = append([]byte{0, 0, 0, 0}, []byte("ITSIM001")...)
	c.rootCHA = append(append([]byte{}, ias.CIEAID...), 0x00)
	return nil
}

// ATR is the answer to reset a contactless reader reports for the card.
func (c *Card) ATR() []byte { return append([]byte{}, c.atr...) }

// Certificate is the citizen certificate in EF 1003.
func (c *Card) Certificate() *x509.Certificate { return c.pki.citizen }

// IssuerCertificate is the CA that issued the citizen certificate.
func (c *Card) IssuerCertificate() *x509.Certificate { return c.pki.issuer }

// PINTriesLeft is the PIN retry counter.
func (c *Card) PINTriesLeft() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.pinLeft
}

// Reset is a cold or warm reset: it ends the secure channel and every security status, keeping the counters.
func (c *Card) Reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.resets++
	c.s = state{}
}

// Stats reports how many APDUs and resets the card has seen.
func (c *Card) Stats() (transmits, resets int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.transmits, c.resets
}

func (c *Card) rand() io.Reader {
	if c.opts.Rand != nil {
		return c.opts.Rand
	}
	return rand.Reader
}

// apdu is a parsed command.
type apdu struct {
	cla, ins, p1, p2 byte
	data             []byte
	ne               int // expected response length; 0 when absent
	hasLe            bool
}

func parseAPDU(b []byte) (apdu, bool) {
	if len(b) < 4 {
		return apdu{}, false
	}
	a := apdu{cla: b[0], ins: b[1], p1: b[2], p2: b[3]}
	body := b[4:]
	switch {
	case len(body) == 0:
	case len(body) == 1:
		a.hasLe, a.ne = true, int(body[0])
		if a.ne == 0 {
			a.ne = 256
		}
	case body[0] != 0:
		lc := int(body[0])
		switch len(body) {
		case 1 + lc:
			a.data = body[1:]
		case 2 + lc:
			a.data = body[1 : 1+lc]
			a.hasLe, a.ne = true, int(body[1+lc])
			if a.ne == 0 {
				a.ne = 256
			}
		default:
			return apdu{}, false
		}
	case len(body) == 3:
		a.hasLe, a.ne = true, int(body[1])<<8|int(body[2])
		if a.ne == 0 {
			a.ne = 65536
		}
	case len(body) >= 3:
		lc := int(body[1])<<8 | int(body[2])
		switch len(body) {
		case 3 + lc:
			a.data = body[3:]
		case 5 + lc:
			a.data = body[3 : 3+lc]
			a.hasLe, a.ne = true, int(body[3+lc])<<8|int(body[4+lc])
			if a.ne == 0 {
				a.ne = 65536
			}
		default:
			return apdu{}, false
		}
	default:
		return apdu{}, false
	}
	return a, true
}

func swBytes(sw uint16) []byte { return []byte{byte(sw >> 8), byte(sw)} }

// Transmit processes one command APDU and returns the response APDU.
func (c *Card) Transmit(cmd []byte) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.transmits++
	a, ok := parseAPDU(cmd)
	if !ok {
		return swBytes(ias.SWWrongLength), nil
	}
	if a.ins == 0xC0 {
		return c.getResponse(a), nil
	}
	c.s.pending = nil
	extended := len(cmd) >= 7 && cmd[4] == 0
	limit := 256
	if extended && a.hasLe {
		limit = a.ne
	}
	if a.cla&0x0C == 0x0C {
		body, sw := c.protected(a)
		return c.respond(body, sw, limit), nil
	}
	if c.s.sm != nil && c.s.sm.used {
		// An unprotected command ends the secure channel and the security status it carried.
		c.endChannel()
	}
	data, sw := c.command(a, false)
	return c.respond(data, sw, limit), nil
}

// respond returns at most limit bytes, leaving the rest for GET RESPONSE behind 61xx.
func (c *Card) respond(body []byte, sw uint16, limit int) []byte {
	if len(body) <= limit {
		return append(append([]byte{}, body...), swBytes(sw)...)
	}
	c.s.pending = append([]byte{}, body[limit:]...)
	return append(append([]byte{}, body[:limit]...), 0x61, byte(min(len(c.s.pending), 256)))
}

func (c *Card) getResponse(a apdu) []byte {
	if c.s.pending == nil {
		return swBytes(0x6985)
	}
	n := a.ne
	if !a.hasLe || n == 0 {
		n = 256
	}
	n = min(n, len(c.s.pending))
	out := c.s.pending[:n]
	c.s.pending = c.s.pending[n:]
	if len(c.s.pending) == 0 {
		c.s.pending = nil
		return append(append([]byte{}, out...), 0x90, 0x00)
	}
	return append(append([]byte{}, out...), 0x61, byte(min(len(c.s.pending), 256)))
}

func (c *Card) endChannel() {
	c.s.sm = nil
	c.s.pinOK, c.s.pukOK = false, false
	c.s.terminalAuth, c.s.chipAuth = false, false
	c.s.chaining, c.s.chainData = false, nil
}

// protected verifies and decrypts a protected command, runs it and protects the answer. An SM error ends the
// channel and is answered without protection.
func (c *Card) protected(a apdu) ([]byte, uint16) {
	ch := c.s.sm
	if ch == nil {
		return nil, 0x6988
	}
	objs, err := ias.ParseTLVs(a.data)
	if err != nil {
		c.endChannel()
		return nil, 0x6988
	}
	incrementSSC(ch.ssc)
	macInput := ias.Pad(append(append([]byte{}, ch.ssc...), a.cla, a.ins, a.p1, a.p2))
	var mac, crypto []byte
	var plain apdu
	plain.cla, plain.ins, plain.p1, plain.p2 = a.cla&^0x0C, a.ins, a.p1, a.p2
	for _, o := range objs {
		switch o.Tag {
		case 0x87:
			if len(o.Value) < 9 || o.Value[0] != 0x01 {
				c.endChannel()
				return nil, 0x6988
			}
			crypto = o.Value[1:]
			macInput = append(macInput, o.Raw...)
		case 0x85:
			crypto = o.Value
			macInput = append(macInput, o.Raw...)
		case 0x97:
			plain.hasLe = true
			for _, b := range o.Value {
				plain.ne = plain.ne<<8 | int(b)
			}
			if plain.ne == 0 {
				plain.ne = 256
				if len(o.Value) == 2 {
					plain.ne = 65536
				}
			}
			macInput = append(macInput, o.Raw...)
		case 0x8E:
			mac = o.Value
		default:
			c.endChannel()
			return nil, 0x6988
		}
	}
	if mac == nil {
		c.endChannel()
		return nil, 0x6987
	}
	want, err := ias.RetailMAC(ch.kmac, ias.Pad(macInput))
	if err != nil || subtle.ConstantTimeCompare(want, mac) != 1 {
		c.endChannel()
		return nil, 0x6988
	}
	if crypto != nil {
		dec, err := ias.Decrypt3DES(ch.kenc, crypto)
		if err == nil {
			plain.data, err = ias.Unpad(dec)
		}
		if err != nil {
			c.endChannel()
			return nil, 0x6988
		}
	}
	ch.used = true
	data, sw := c.command(plain, true)
	if c.s.sm != ch { // the command ended or replaced the channel
		return data, sw
	}
	if c.opts.UnprotectedErrors && sw != ias.SWOK && sw != ias.SWEndOfFile && sw != ias.SWWrongOffset {
		return nil, sw
	}
	incrementSSC(ch.ssc)
	var field []byte
	if len(data) > 0 {
		enc, _ := ias.Encrypt3DES(ch.kenc, ias.Pad(data))
		field = append(field, ias.EncodeTLV(0x87, append([]byte{0x01}, enc...))...)
	}
	field = append(field, ias.EncodeTLV(0x99, swBytes(sw))...)
	m, _ := ias.RetailMAC(ch.kmac, ias.Pad(append(append([]byte{}, ch.ssc...), field...)))
	field = append(field, ias.EncodeTLV(0x8E, m)...)
	if c.s.afterResponseSSC != nil {
		ch.ssc = c.s.afterResponseSSC
		c.s.afterResponseSSC = nil
	}
	return field, ias.SWOK
}

func incrementSSC(ssc []byte) {
	for i := len(ssc) - 1; i >= 0; i-- {
		ssc[i]++
		if ssc[i] != 0 {
			return
		}
	}
}

// command runs a plain (or already unwrapped) command, collecting chained parts first.
func (c *Card) command(a apdu, sm bool) ([]byte, uint16) {
	if a.cla&0x10 != 0 {
		if c.s.chaining && c.s.chainINS != a.ins {
			c.s.chaining, c.s.chainData = false, nil
			return nil, 0x6883
		}
		c.s.chaining, c.s.chainINS = true, a.ins
		c.s.chainData = append(c.s.chainData, a.data...)
		return nil, ias.SWOK
	}
	if c.s.chaining {
		if c.s.chainINS != a.ins {
			c.s.chaining, c.s.chainData = false, nil
			return nil, 0x6883
		}
		a.data = append(c.s.chainData, a.data...)
		c.s.chaining, c.s.chainData = false, nil
	}
	switch a.ins {
	case 0xA4:
		return c.selectFile(a)
	case 0xB0:
		return c.readBinary(a, sm)
	case 0xCB:
		return c.getData(a)
	case 0x22:
		return c.mseSet(a, sm)
	case 0x2A:
		return c.verifyCertificate(a, sm)
	case 0x84:
		return c.getChallenge(a)
	case 0x82:
		return c.externalAuthenticate(a, sm)
	case 0x88:
		return c.internalAuthenticate(a, sm)
	case 0x20:
		return c.verify(a, sm)
	case 0x2C:
		return c.resetRetryCounter(a, sm)
	case 0x24:
		return c.changeReference(a, sm)
	}
	return nil, 0x6D00
}

func (c *Card) selectFile(a apdu) ([]byte, uint16) {
	switch {
	case a.p1 == 0x00 && len(a.data) == 0:
		if c.opts.Variant == Gemalto {
			return nil, 0x6A82
		}
		c.s.df, c.s.ef = dfIAS, 0
	case a.p1 == 0x04 && bytes.Equal(a.data, ias.IASAID()):
		if c.opts.Variant == Unlisted {
			return nil, 0x6A82
		}
		c.s.df, c.s.ef = dfIAS, 0
	case a.p1 == 0x04 && bytes.Equal(a.data, ias.CIEAID):
		c.s.df, c.s.ef = dfCIE, 0
	case a.p1 == 0x02 && len(a.data) == 2:
		fid := uint16(a.data[0])<<8 | uint16(a.data[1])
		f, ok := c.files[fid]
		if !ok || f.df != c.s.df {
			return nil, 0x6A82
		}
		c.s.ef = fid
	default:
		return nil, 0x6A82
	}
	return nil, ias.SWOK
}

func (c *Card) readBinary(a apdu, sm bool) ([]byte, uint16) {
	f, ok := c.files[c.s.ef]
	if c.s.ef == 0 || !ok {
		return nil, 0x6986
	}
	if f.protected && !(sm && c.s.pinOK) {
		return nil, 0x6982
	}
	if a.p1&0x80 != 0 {
		return nil, 0x6A81
	}
	off := int(a.p1)<<8 | int(a.p2)
	if off >= len(f.data) {
		return nil, ias.SWWrongOffset
	}
	n := a.ne
	if !a.hasLe {
		n = 256
	}
	rest := f.data[off:]
	if len(rest) < n {
		if c.opts.ShortReadsWith6C {
			return nil, 0x6C00 | uint16(len(rest))
		}
		return rest, ias.SWEndOfFile
	}
	return rest[:n], ias.SWOK
}

var (
	listAll  = []byte{0x4D, 0x08, 0x70, 0x06, 0xBF, 0xA1, 0x01, 0x02, 0xA3, 0x80}
	listG    = []byte{0x4D, 0x0A, 0x70, 0x08, 0xBF, 0xA1, 0x01, 0x04, 0xA3, 0x02, 0x97, 0x00}
	listP    = []byte{0x4D, 0x0A, 0x70, 0x08, 0xBF, 0xA1, 0x01, 0x04, 0xA3, 0x02, 0x98, 0x00}
	listQ    = []byte{0x4D, 0x0A, 0x70, 0x08, 0xBF, 0xA1, 0x01, 0x04, 0xA3, 0x02, 0x99, 0x00}
	listRoot = []byte{0x4D, 0x09, 0x70, 0x07, 0xBF, 0xA0, 0x04, 0x03, 0x7F, 0x49, 0x80}
	listYICC = []byte{0x4D, 0x04, 0xA6, 0x02, 0x91, 0x00}
)

func dhObject(tag uint32, values ...[]byte) []byte {
	var inner []byte
	for i, v := range values {
		inner = append(inner, ias.EncodeTLV(tag+uint32(i), v)...)
	}
	return tlv(0x70, tlv(0xBFA101, tlv(0xA3, inner)))
}

func (c *Card) getData(a apdu) ([]byte, uint16) {
	if a.p1 != 0x3F || a.p2 != 0xFF {
		return nil, 0x6A86
	}
	gemalto := c.opts.Variant == Gemalto
	switch {
	case bytes.Equal(a.data, listAll) && gemalto:
		return dhObject(0x97, dhG.Bytes(), dhP.Bytes(), dhQ.Bytes()), ias.SWOK
	case bytes.Equal(a.data, listG) && !gemalto:
		return dhObject(0x97, dhG.Bytes()), ias.SWOK
	case bytes.Equal(a.data, listP) && !gemalto:
		return dhObject(0x98, dhP.Bytes()), ias.SWOK
	case bytes.Equal(a.data, listQ) && !gemalto:
		return dhObject(0x99, dhQ.Bytes()), ias.SWOK
	case bytes.Equal(a.data, listRoot):
		inner := tlv(0x81, rootN.Bytes())
		inner = append(inner, tlv(0x82, rootE.Bytes())...)
		inner = append(inner, tlv(0x5F20, c.rootCHR)...)
		inner = append(inner, tlv(0x5F4C, c.rootCHA)...)
		return tlv(0x70, tlv(0xBFA004, tlv(0x7F49, inner))), ias.SWOK
	case bytes.Equal(a.data, listYICC):
		if c.s.dh == nil {
			return nil, 0x6985
		}
		return tlv(0xA6, tlv(0x91, c.s.dh.yICC)), ias.SWOK
	}
	return nil, 0x6A88
}

// mseSet handles the MANAGE SECURITY ENVIRONMENT variants the middleware uses.
func (c *Card) mseSet(a apdu, sm bool) ([]byte, uint16) {
	objs, err := ias.ParseTLVs(a.data)
	if err != nil {
		return nil, 0x6A80
	}
	get := func(tag uint32) []byte {
		o, _ := ias.Find(objs, tag)
		return o.Value
	}
	switch {
	case a.p1 == 0x41 && a.p2 == 0xA6:
		if !bytes.Equal(get(0x80), []byte{0x9B}) || !bytes.Equal(get(0x83), []byte{0x81}) {
			return nil, 0x6A80
		}
		return c.keyAgreement(get(0x91))
	case a.p1 == 0x81 && a.p2 == 0xB6:
		if !sm || !bytes.Equal(get(0x80), []byte{0x41}) || !bytes.Equal(get(0x83), []byte{0x84}) {
			return nil, 0x6A80
		}
		c.s.sel.verifyRoot = true
		return nil, ias.SWOK
	case a.p1 == 0x81 && a.p2 == 0xA4:
		chr := get(0x83)
		if !sm || c.s.terminal == nil || !bytes.Equal(chr, c.s.terminalCHR) {
			return nil, 0x6A88
		}
		c.s.sel.extAuthCHR = chr
		return nil, ias.SWOK
	case a.p1 == 0x41 && a.p2 == 0xA4:
		key := get(0x84)
		alg := get(0x80)
		switch {
		case bytes.Equal(key, []byte{0x82}) && bytes.Equal(alg, []byte{0x9B}),
			bytes.Equal(key, []byte{0x81}) && bytes.Equal(alg, []byte{0x02}),
			bytes.Equal(key, []byte{0x83}) && bytes.Equal(alg, []byte{0x02}):
			c.s.sel.intKey = key[0]
			return nil, ias.SWOK
		}
		return nil, 0x6A88
	}
	return nil, 0x6A86
}

// keyAgreement runs the card side of DH: it validates Y.IFD, draws its own value and derives the session keys.
// The channel starts with SSC 1 and is active from the first protected command.
func (c *Card) keyAgreement(yIFD []byte) ([]byte, uint16) {
	y := new(big.Int).SetBytes(yIFD)
	if y.Cmp(big.NewInt(1)) <= 0 || y.Cmp(new(big.Int).Sub(dhP, big.NewInt(1))) >= 0 {
		return nil, 0x6A80
	}
	size := len(dhP.Bytes())
	var x, yICC *big.Int
	for {
		var err error
		x, err = rand.Int(c.rand(), new(big.Int).Sub(dhQ, big.NewInt(2)))
		if err != nil {
			return nil, 0x6F00
		}
		x.Add(x, big.NewInt(2))
		yICC = new(big.Int).Exp(dhG, x, dhP)
		leadingZero := yICC.BitLen() <= 8*(size-1)
		if leadingZero == c.opts.PublicValueLeadingZero {
			break
		}
	}
	enc := yICC.FillBytes(make([]byte, size))
	if c.opts.MinimalPublicValue {
		enc = yICC.Bytes()
	}
	// A card computes the shared secret on the full size of p.
	zz := new(big.Int).Exp(y, x, dhP).FillBytes(make([]byte, size))
	kenc := sha256.Sum256(append(append([]byte{}, zz...), 0, 0, 0, 1))
	kmac := sha256.Sum256(append(append([]byte{}, zz...), 0, 0, 0, 2))
	c.s.dh = &dhState{x: x, yICC: enc, yIFD: append([]byte{}, yIFD...)}
	c.s.sm = &channel{kenc: kenc[:16], kmac: kmac[:16], ssc: []byte{0, 0, 0, 0, 0, 0, 0, 1}}
	c.s.terminal, c.s.terminalCHR, c.s.challenge = nil, nil, nil
	c.s.terminalAuth, c.s.chipAuth, c.s.pinOK, c.s.pukOK = false, false, false, false
	c.s.sel.verifyRoot, c.s.sel.extAuthCHR, c.s.sel.intKey = false, nil, 0
	return nil, ias.SWOK
}

// verifyCertificate is PSO VERIFY CERTIFICATE of the terminal CV certificate under the CV root key.
func (c *Card) verifyCertificate(a apdu, sm bool) ([]byte, uint16) {
	if !sm || !c.s.sel.verifyRoot || a.p1 != 0x00 || a.p2 != 0xAE {
		return nil, 0x6982
	}
	outer, _, err := ias.ParseTLV(a.data)
	if err != nil || outer.Tag != 0x7F21 {
		return nil, 0x6A80
	}
	kids, err := ias.ParseTLVs(outer.Value)
	if err != nil {
		return nil, 0x6A80
	}
	sig, ok1 := ias.Find(kids, 0x5F37)
	rem, ok2 := ias.Find(kids, 0x5F38)
	car, ok3 := ias.Find(kids, 0x42)
	if !ok1 || !ok2 || !ok3 || !bytes.Equal(car.Value, c.rootCHR[4:]) {
		return nil, 0x6A80
	}
	k := len(rootN.Bytes())
	if len(sig.Value) != k || new(big.Int).SetBytes(sig.Value).Cmp(rootN) >= 0 {
		return nil, 0x6A80
	}
	m := ias.RawRSA(rootN, rootE, sig.Value)
	if m[0] != 0x6A || m[k-1] != 0xBC {
		return nil, 0x6300
	}
	body := append(append([]byte{}, m[1:k-33]...), rem.Value...)
	if h := sha256.Sum256(body); subtle.ConstantTimeCompare(h[:], m[k-33:k-1]) != 1 {
		return nil, 0x6300
	}
	// CPI || CAR || CHR(12) || CHA(7) || OID(9) || modulus || exponent(4)
	carLen := len(car.Value)
	if len(body) < 1+carLen+12+7+9+4+128 || body[0] != 0x8A || !bytes.Equal(body[1:1+carLen], car.Value) {
		return nil, 0x6A80
	}
	rest := body[1+carLen:]
	chr, cha, oid, key := rest[:12], rest[12:19], rest[19:28], rest[28:]
	if !bytes.Equal(cha[:6], c.rootCHA[:6]) || !bytes.Equal(oid, ias.CVOID()) {
		return nil, 0x6A80
	}
	n := new(big.Int).SetBytes(key[:len(key)-4])
	e := new(big.Int).SetBytes(key[len(key)-4:])
	if !e.IsInt64() {
		return nil, 0x6A80
	}
	c.s.terminal = &rsa.PublicKey{N: n, E: int(e.Int64())}
	c.s.terminalCHR = append([]byte{}, chr...)
	c.s.terminalAuth = false
	return nil, ias.SWOK
}

func (c *Card) getChallenge(a apdu) ([]byte, uint16) {
	if !a.hasLe || a.ne != 8 {
		return nil, 0x6700
	}
	ch := make([]byte, 8)
	if _, err := io.ReadFull(c.rand(), ch); err != nil {
		return nil, 0x6F00
	}
	c.s.challenge = ch
	return ch, ias.SWOK
}

func (c *Card) transcript() []byte {
	return append(append(dhG.Bytes(), dhP.Bytes()...), dhQ.Bytes()...)
}

// externalAuthenticate checks the terminal's signature over the DH transcript and the challenge.
func (c *Card) externalAuthenticate(a apdu, sm bool) ([]byte, uint16) {
	if !sm || c.s.sel.extAuthCHR == nil || c.s.challenge == nil || c.s.dh == nil {
		return nil, 0x6982
	}
	challenge := c.s.challenge
	c.s.challenge = nil
	t := c.s.terminal
	k := (t.N.BitLen() + 7) / 8
	if len(a.data) != 8+k || !bytes.Equal(a.data[:8], c.s.terminalCHR[4:]) {
		return nil, 0x6A80
	}
	sig := a.data[8:]
	if new(big.Int).SetBytes(sig).Cmp(t.N) >= 0 {
		return nil, 0x6300
	}
	m := ias.RawRSA(t.N, big.NewInt(int64(t.E)), sig)
	if m[0] != 0x6A || m[k-1] != 0xBC {
		return nil, 0x6300
	}
	h := sha256.New()
	for _, part := range [][]byte{m[1 : k-33], c.s.dh.yIFD, a.data[:8], challenge, c.s.dh.yICC, c.transcript()} {
		h.Write(part)
	}
	if subtle.ConstantTimeCompare(h.Sum(nil), m[k-33:k-1]) != 1 {
		return nil, 0x6300
	}
	c.s.terminalAuth = true
	c.s.dappChallenge = challenge
	return nil, ias.SWOK
}

func (c *Card) internalAuthenticate(a apdu, sm bool) ([]byte, uint16) {
	switch c.s.sel.intKey {
	case 0x82:
		if !sm || !c.s.terminalAuth {
			return nil, 0x6982
		}
		if len(a.data) != 8 {
			return nil, 0x6700
		}
		key := c.keys.IntAuth
		k := key.Size()
		prnd := make([]byte, k-34)
		if _, err := io.ReadFull(c.rand(), prnd); err != nil {
			return nil, 0x6F00
		}
		h := sha256.New()
		for _, part := range [][]byte{prnd, c.s.dh.yICC, c.snICC, a.data, c.s.dh.yIFD, c.transcript()} {
			h.Write(part)
		}
		block := append(append([]byte{0x6A}, prnd...), h.Sum(nil)...)
		block = append(block, 0xBC)
		sig := ias.RawRSA(key.N, key.D, block)
		c.s.chipAuth = true
		// After this response the channel continues with SSC = RND.ICC[4:] || RND.IFD[4:].
		c.s.afterResponseSSC = append(append([]byte{}, c.s.dappChallenge[4:]...), a.data[4:]...)
		return append(append([]byte{}, c.snICC...), sig...), ias.SWOK
	case 0x81:
		if !sm || !c.s.chipAuth || !c.s.pinOK {
			return nil, 0x6982
		}
		sig, err := rsa.SignPKCS1v15(nil, c.keys.Citizen, crypto.Hash(0), a.data)
		if err != nil {
			return nil, 0x6700
		}
		return sig, ias.SWOK
	case 0x83:
		sig, err := rsa.SignPKCS1v15(nil, c.keys.Service, crypto.Hash(0), a.data)
		if err != nil {
			return nil, 0x6700
		}
		return sig, ias.SWOK
	}
	return nil, 0x6985
}

// verify is VERIFY of the PIN (81) or PUK (82), possible only after DAPP. An empty data field asks the counter.
func (c *Card) verify(a apdu, sm bool) ([]byte, uint16) {
	if !sm || !c.s.chipAuth {
		return nil, 0x6982
	}
	var secret string
	var left *int
	var ok *bool
	switch a.p2 {
	case 0x81:
		secret, left, ok = c.pin, &c.pinLeft, &c.s.pinOK
	case 0x82:
		secret, left, ok = c.puk, &c.pukLeft, &c.s.pukOK
	default:
		return nil, 0x6A88
	}
	if *left == 0 {
		return nil, ias.SWPinLocked
	}
	if len(a.data) == 0 {
		if *ok {
			return nil, ias.SWOK
		}
		return nil, 0x63C0 | uint16(*left)
	}
	if len(a.data) != 8 {
		return nil, ias.SWWrongLength
	}
	if subtle.ConstantTimeCompare(a.data, []byte(secret)) != 1 {
		*left--
		*ok = false
		return nil, 0x63C0 | uint16(*left)
	}
	if a.p2 == 0x81 {
		*left = pinTries
	} else {
		*left = pukTries
	}
	*ok = true
	return nil, ias.SWOK
}

// resetRetryCounter is RESET RETRY COUNTER after the PUK: P1=03 unblocks, P1=02 also sets a new PIN.
func (c *Card) resetRetryCounter(a apdu, sm bool) ([]byte, uint16) {
	if !sm || !c.s.pukOK || a.p2 != 0x81 {
		return nil, 0x6982
	}
	switch {
	case a.p1 == 0x03 && len(a.data) == 0:
	case a.p1 == 0x02 && len(a.data) == 8:
		c.pin = string(a.data)
	default:
		return nil, 0x6A86
	}
	c.pinLeft = pinTries
	return nil, ias.SWOK
}

// changeReference is CHANGE REFERENCE DATA of the PIN: old || new.
func (c *Card) changeReference(a apdu, sm bool) ([]byte, uint16) {
	if !sm || !c.s.chipAuth || a.p2 != 0x81 || len(a.data) != 16 {
		return nil, 0x6982
	}
	if _, sw := c.verify(apdu{p2: 0x81, data: a.data[:8]}, true); sw != ias.SWOK {
		return nil, sw
	}
	c.pin = string(a.data[8:])
	return nil, ias.SWOK
}

// Describe is a one-line summary for logs.
func (c *Card) Describe() string {
	return fmt.Sprintf("simulated CIE (%s %s, NIS %s, PIN tries %d)", c.opts.Identity.Surname, c.opts.Identity.GivenName, c.opts.Identity.NIS, c.PINTriesLeft())
}
