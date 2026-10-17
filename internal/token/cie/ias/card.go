// Package ias speaks the CIE 3.0 IAS protocol as the official middleware does (italia/cie-middleware-linux,
// CSP/IAS.cpp): DH key agreement with card-provided parameters, 3DES secure messaging, DAPP mutual authentication,
// PIN verification with the full PIN, certificate read and INTERNAL AUTHENTICATE signatures.
package ias

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"math/big"
)

// Files of the CIE.
const (
	FilePAN         = 0xD003 // EF.SN.ICC, IAS DF
	FileDH          = 0xD004 // EF.DH, IAS DF
	FileServiceID   = 0x1001 // EF.ID_Servizi (NIS), CIE DF
	FileSerial      = 0x1002 // printed card number, CIE DF, PIN + SM
	FileCertificate = 0x1003 // citizen authentication certificate, CIE DF, PIN + SM
	FileIntAuthKey  = 0x1004 // RSA key verifying DAPP internal authentication, CIE DF
	FileServiceKey  = 0x1005 // RSA key of the PIN-less service internal authentication, CIE DF
	FileSOD         = 0x1006 // document security object, CIE DF
)

// Key references.
const (
	keyDH       = 0x81
	keyExtAuth  = 0x84
	keyIntAuth  = 0x82
	keySign     = 0x81
	pinRef      = 0x81
	maxFileSize = 0x7FFF
)

// Card is one card connection. It is not safe for concurrent use.
type Card struct {
	t      Transport
	family Family
	// Rand supplies DH exponents and DAPP challenges; crypto/rand when nil.
	Rand io.Reader

	sm *smState

	g, p, q    []byte // DH domain parameters as the card encodes them
	yIFD, yICC []byte // DH public values as exchanged
	x          *big.Int

	intAuthN, intAuthE *big.Int // EF 1004
	rootN, rootE       *big.Int // CV root key from the card
	rootCAR, rootAID   []byte

	pinSent       bool
	authenticated bool
	cert          *x509.Certificate
	certDER       []byte
}

// NewCard prepares a card connection; atr decides the supplier family (see Identify).
func NewCard(t Transport, atr []byte) *Card {
	f, _ := Identify(atr)
	return &Card{t: t, family: f}
}

// Family is the supplier family recognized from the ATR, or found by probing.
func (c *Card) Family() Family { return c.family }

func (c *Card) rand() io.Reader {
	if c.Rand != nil {
		return c.Rand
	}
	return rand.Reader
}

func (c *Card) send(op string, cmd command) ([]byte, uint16, error) {
	if c.sm != nil {
		return c.sendSM(op, cmd)
	}
	return c.sendPlain(op, cmd)
}

// expect sends cmd and fails unless the card answers 9000.
func (c *Card) expect(op string, cmd command) ([]byte, error) {
	resp, sw, err := c.send(op, cmd)
	if err != nil {
		return nil, err
	}
	if sw != SWOK {
		return nil, &StatusError{Op: op, SW: sw}
	}
	return resp, nil
}

// SelectIAS selects the IAS application: by AID on Gemalto and STM cards, the MF on NXP and later suppliers. With
// an unknown ATR it tries the AID, then the MF. Selection ends the secure channel, as in the reference.
func (c *Card) SelectIAS() error {
	c.sm = nil
	byAID := command{cla: 0x00, ins: 0xA4, p1: 0x04, p2: 0x0C, data: iasAID}
	mf := command{cla: 0x00, ins: 0xA4, p1: 0x00, p2: 0x00}
	switch {
	case c.family == FamilyUnknown:
		if _, err := c.expect("select IAS", byAID); err == nil {
			return nil
		} else if !isStatus(err) {
			return err
		}
		_, err := c.expect("select MF", mf)
		return err
	case c.family.selectsMF():
		_, err := c.expect("select MF", mf)
		return err
	default:
		_, err := c.expect("select IAS", byAID)
		return err
	}
}

// SelectCIE selects the CIE DF.
func (c *Card) SelectCIE() error {
	c.sm = nil
	_, err := c.expect("select CIE", command{cla: 0x00, ins: 0xA4, p1: 0x04, p2: 0x0C, data: CIEAID})
	return err
}

func isStatus(err error) bool {
	var se *StatusError
	return errors.As(err, &se)
}

// ReadFile reads a transparent EF of the current DF in 128-byte chunks, through the secure channel once established.
// The loop ends on a short read (6282) or at the end of the file (6B00), as in the reference.
func (c *Card) ReadFile(fid uint16) ([]byte, error) {
	op := fmt.Sprintf("read %04X", fid)
	if _, err := c.expect("select "+op[5:], command{cla: 0x00, ins: 0xA4, p1: 0x02, p2: 0x04, data: []byte{byte(fid >> 8), byte(fid)}}); err != nil {
		return nil, err
	}
	var content []byte
	for {
		off := len(content)
		if off > maxFileSize {
			return nil, protoErr(op, "file larger than %d bytes", maxFileSize)
		}
		chunk, sw, err := c.send(op, command{cla: 0x00, ins: 0xB0, p1: byte(off >> 8), p2: byte(off), le: le(0x80)})
		if err != nil {
			return nil, err
		}
		switch sw {
		case SWOK:
			if len(chunk) == 0 {
				return content, nil
			}
			content = append(content, chunk...)
		case SWEndOfFile:
			return append(content, chunk...), nil
		case SWWrongOffset:
			return content, nil
		default:
			return nil, &StatusError{Op: op, SW: sw}
		}
	}
}

// getData sends GET DATA 00 CB 3F FF with a header list, without Le like the reference.
func (c *Card) getData(op string, list []byte) ([]byte, error) {
	return c.expect(op, command{cla: 0x00, ins: 0xCB, p1: 0x3F, p2: 0xFF, data: list})
}

// Header lists of the GET DATA commands, verbatim from the reference.
var (
	dhAllList  = []byte{0x4D, 0x08, 0x70, 0x06, 0xBF, 0xA1, 0x01, 0x02, 0xA3, 0x80}
	dhGList    = []byte{0x4D, 0x0A, 0x70, 0x08, 0xBF, 0xA1, 0x01, 0x04, 0xA3, 0x02, 0x97, 0x00}
	dhPList    = []byte{0x4D, 0x0A, 0x70, 0x08, 0xBF, 0xA1, 0x01, 0x04, 0xA3, 0x02, 0x98, 0x00}
	dhQList    = []byte{0x4D, 0x0A, 0x70, 0x08, 0xBF, 0xA1, 0x01, 0x04, 0xA3, 0x02, 0x99, 0x00}
	rootList   = []byte{0x4D, 0x09, 0x70, 0x07, 0xBF, 0xA0, keyExtAuth & 0x7F, 0x03, 0x7F, 0x49, 0x80}
	yICCList   = []byte{0x4D, 0x04, 0xA6, 0x02, 0x91, 0x00}
	errDomain  = errors.New("unusable DH domain parameters")
	errPublic  = errors.New("DH public value out of range")
	errDAPP    = errors.New("chip authentication failed")
	errRootKey = errors.New("the card's CV root key does not match the terminal certificate key")
)

// initDH reads g, p and q: one GET DATA on Gemalto cards, one per value on the others (CSP/IAS.cpp InitDHParam).
func (c *Card) initDH() error {
	readAll := func() error {
		resp, err := c.getData("get DH parameters", dhAllList)
		if err != nil {
			return err
		}
		inner, err := Path(resp, 0, 0, 0)
		if err != nil {
			return &ProtocolError{Op: "get DH parameters", Err: err}
		}
		kids, err := ParseTLVs(inner.Value)
		if err != nil || len(kids) < 3 {
			return protoErr("get DH parameters", "expected g, p, q")
		}
		c.g, c.p, c.q = kids[0].Value, kids[1].Value, kids[2].Value
		return nil
	}
	readEach := func() error {
		var out [3][]byte
		for i, list := range [][]byte{dhGList, dhPList, dhQList} {
			resp, err := c.getData("get DH parameter", list)
			if err != nil {
				return err
			}
			v, err := Path(resp, 0, 0, 0, 0)
			if err != nil {
				return &ProtocolError{Op: "get DH parameter", Err: err}
			}
			out[i] = v.Value
		}
		c.g, c.p, c.q = out[0], out[1], out[2]
		return nil
	}
	var err error
	switch c.family {
	case FamilyGemalto:
		err = readAll()
	case FamilyUnknown:
		if err = readEach(); isStatus(err) {
			err = readAll()
		}
	default:
		err = readEach()
	}
	if err != nil {
		return err
	}
	p, g, q := new(big.Int).SetBytes(c.p), new(big.Int).SetBytes(c.g), new(big.Int).SetBytes(c.q)
	if p.BitLen() < 1024 || p.Bit(0) == 0 || q.Cmp(big.NewInt(3)) < 0 || g.Cmp(big.NewInt(1)) <= 0 || g.Cmp(new(big.Int).Sub(p, big.NewInt(1))) >= 0 {
		return &ProtocolError{Op: "DH parameters", Err: errDomain}
	}
	return nil
}

// readIntAuthKey reads the RSA key the chip's DAPP signature is verified with (EF 1004, two integers).
func (c *Card) readIntAuthKey() error {
	data, err := c.ReadFile(FileIntAuthKey)
	if err != nil {
		return err
	}
	top, _, err := ParseTLV(data)
	if err != nil {
		return &ProtocolError{Op: "internal authentication key", Err: err}
	}
	kids, err := ParseTLVs(top.Value)
	if err != nil || len(kids) < 2 {
		return protoErr("internal authentication key", "expected modulus and exponent")
	}
	c.intAuthN = new(big.Int).SetBytes(kids[0].Value)
	c.intAuthE = new(big.Int).SetBytes(kids[1].Value)
	if c.intAuthN.BitLen() < 1024 || c.intAuthE.Sign() == 0 {
		return protoErr("internal authentication key", "unusable key")
	}
	return nil
}

// readRootKey reads the CV root key (modulus 81, exponent 82, CHR 5F20, CHA 5F4C) that verifies the terminal
// certificate (CSP/IAS.cpp InitExtAuthKeyParam).
func (c *Card) readRootKey() error {
	resp, err := c.getData("get CV root key", rootList)
	if err != nil {
		return err
	}
	inner, err := Path(resp, 0, 0, 0)
	if err != nil {
		return &ProtocolError{Op: "CV root key", Err: err}
	}
	kids, err := ParseTLVs(inner.Value)
	if err != nil {
		return &ProtocolError{Op: "CV root key", Err: err}
	}
	n, ok1 := Find(kids, 0x81)
	e, ok2 := Find(kids, 0x82)
	chr, ok3 := Find(kids, 0x5F20)
	cha, ok4 := Find(kids, 0x5F4C)
	if !ok1 || !ok2 || !ok3 || !ok4 || len(chr.Value) < 5 || len(cha.Value) < 6 {
		return protoErr("CV root key", "missing objects")
	}
	c.rootN = new(big.Int).SetBytes(n.Value)
	c.rootE = new(big.Int).SetBytes(e.Value)
	c.rootCAR = chr.Value[4:]
	c.rootAID = cha.Value[:6]
	if c.rootN.BitLen() < 1024 {
		return protoErr("CV root key", "modulus too small")
	}
	return nil
}

// maxDHAttempts bounds how often the exchange is repeated when a value would need fewer bytes than p minus one
// (see keyExchange).
const maxDHAttempts = 4

// keyExchange runs the DH key agreement (CSP/IAS.cpp DHKeyExchange) and opens the secure channel.
//
// The reference encodes the DH values as minimal big-endian integers, except that a 255-byte value is sent as 256
// bytes. That equals the fixed-length encoding (the size of p) unless a value starts with two zero bytes, where the
// card's encoding is unknown. Such values occur with probability 2^-16 and are avoided: our public value is drawn
// again, and a shared secret starting with two zero bytes restarts the exchange. Both happen before the PIN is sent.
func (c *Card) keyExchange() error {
	p := new(big.Int).SetBytes(c.p)
	g := new(big.Int).SetBytes(c.g)
	q := new(big.Int).SetBytes(c.q)
	size := len(c.p)
	limit := new(big.Int).Lsh(big.NewInt(1), uint(8*(size-2))) // values below need fewer than size-1 bytes
	pMinus1 := new(big.Int).Sub(p, big.NewInt(1))
	for attempt := 0; attempt < maxDHAttempts; attempt++ {
		var y *big.Int
		for {
			x, err := rand.Int(c.rand(), new(big.Int).Sub(q, big.NewInt(2)))
			if err != nil {
				return err
			}
			c.x = x.Add(x, big.NewInt(2)) // 2 <= x < q
			y = new(big.Int).Exp(g, c.x, p)
			if y.Cmp(limit) >= 0 {
				break
			}
		}
		c.yIFD = y.FillBytes(make([]byte, size))
		c.sm = nil
		kat := append(EncodeTLV(0x80, []byte{0x9B}), EncodeTLV(0x83, []byte{keyDH})...)
		kat = append(kat, EncodeTLV(0x91, c.yIFD)...)
		if _, err := c.expect("MSE SET KAT", command{cla: 0x00, ins: 0x22, p1: 0x41, p2: 0xA6, data: kat}); err != nil {
			return err
		}
		resp, err := c.getData("get DH public value", yICCList)
		if err != nil {
			return err
		}
		obj, err := Path(resp, 0, 0)
		if err != nil {
			return &ProtocolError{Op: "DH public value", Err: err}
		}
		yICC := new(big.Int).SetBytes(obj.Value)
		if yICC.Cmp(big.NewInt(1)) <= 0 || yICC.Cmp(pMinus1) >= 0 {
			return &ProtocolError{Op: "DH public value", Err: errPublic}
		}
		c.yICC = obj.Value
		zz := new(big.Int).Exp(yICC, c.x, p)
		if zz.Cmp(limit) < 0 {
			continue
		}
		secret := zz.FillBytes(make([]byte, size))
		kenc := sha256.Sum256(append(append([]byte{}, secret...), 0, 0, 0, 1))
		kmac := sha256.Sum256(append(append([]byte{}, secret...), 0, 0, 0, 2))
		c.sm = &smState{kenc: kenc[:16], kmac: kmac[:16], ssc: []byte{0, 0, 0, 0, 0, 0, 0, 1}}
		return nil
	}
	return protoErr("DH key agreement", "no usable shared secret after %d attempts", maxDHAttempts)
}

// transcriptTail is the end of the DH transcript both DAPP signatures cover: g || p || q as the card sent them.
func (c *Card) transcriptTail() []byte {
	var b bytes.Buffer
	b.Write(c.g)
	b.Write(c.p)
	b.Write(c.q)
	return b.Bytes()
}

// TerminalCertificate builds the terminal CV certificate signed by the root key the card announced, exactly as
// CSP/IAS.cpp DAPP does: the body is CPI || CAR || CHR || CHA || OID || modulus || exponent; the signature recovers
// 6A || the first k-34 body bytes || SHA-256(body) || BC, and 5F38 carries the rest of the body.
func TerminalCertificate(rootN *big.Int, car, aid []byte) (cert []byte, chr []byte, err error) {
	cert, chr, _, err = terminalCertificate(rootN, car, aid)
	return cert, chr, err
}

// terminalCertificate also returns the signed block, so the caller can check the root key recovers it.
func terminalCertificate(rootN *big.Int, car, aid []byte) (cert, chr, block []byte, err error) {
	chr = append([]byte{0, 0, 0, 0}, TerminalSerial...)
	cha := append(append([]byte{}, aid...), 0x01)
	var body []byte
	body = append(body, cvCPI)
	body = append(body, car...)
	body = append(body, chr...)
	body = append(body, cha...)
	body = append(body, cvOID...)
	body = append(body, terminalModulus...)
	body = append(body, terminalPubExp...)
	k := (rootN.BitLen() + 7) / 8
	if k-34 <= 0 || k-34 > len(body) {
		return nil, nil, nil, errors.New("root key size unsupported")
	}
	digest := sha256.Sum256(body)
	block = append([]byte{0x6A}, body[:k-34]...)
	block = append(block, digest[:]...)
	block = append(block, 0xBC)
	sig := RawRSA(rootN, new(big.Int).SetBytes(RootPrivExp), block)
	inner := EncodeTLV(0x5F37, sig)
	inner = append(inner, EncodeTLV(0x5F38, body[k-34:])...)
	inner = append(inner, EncodeTLV(0x42, car)...)
	return EncodeTLV(0x7F21, inner), chr, block, nil
}

// dapp runs Device Authentication with Privacy Protection inside the secure channel (CSP/IAS.cpp DAPP): the card
// verifies the terminal certificate and the terminal's signature over the DH transcript, then proves its own key
// with INTERNAL AUTHENTICATE. The chip signature is checked here; afterwards the counter restarts from the two
// challenges.
func (c *Card) dapp() error {
	k := (c.rootN.BitLen() + 7) / 8
	cert, chr, block, err := terminalCertificate(c.rootN, c.rootCAR, c.rootAID)
	if err != nil {
		return protoErr("DAPP", "%v", err)
	}
	// Like the reference, check that the card's public root key recovers what the fixed private exponent signed.
	if err := c.checkRootSignature(cert, block, k); err != nil {
		return err
	}
	if _, err := c.expect("MSE SET verify certificate", command{cla: 0x00, ins: 0x22, p1: 0x81, p2: 0xB6,
		data: append(EncodeTLV(0x80, []byte{0x41}), EncodeTLV(0x83, []byte{keyExtAuth})...), le: le(0)}); err != nil {
		return err
	}
	if _, err := c.expect("PSO VERIFY CERTIFICATE", command{cla: 0x00, ins: 0x2A, p1: 0x00, p2: 0xAE, data: cert}); err != nil {
		return err
	}
	if _, err := c.expect("MSE SET external authentication", command{cla: 0x00, ins: 0x22, p1: 0x81, p2: 0xA4, data: EncodeTLV(0x83, chr)}); err != nil {
		return err
	}
	rndICC, err := c.expect("GET CHALLENGE", command{cla: 0x00, ins: 0x84, p1: 0x00, p2: 0x00, le: le(8)})
	if err != nil {
		return err
	}
	if len(rndICC) != 8 {
		return protoErr("GET CHALLENGE", "challenge of %d bytes", len(rndICC))
	}

	tn := new(big.Int).SetBytes(terminalModulus)
	prnd := make([]byte, len(terminalModulus)-32-2)
	if _, err := io.ReadFull(c.rand(), prnd); err != nil {
		return err
	}
	h := sha256.New()
	for _, part := range [][]byte{prnd, c.yIFD, TerminalSerial, rndICC, c.yICC, c.transcriptTail()} {
		h.Write(part)
	}
	challenge := append([]byte{0x6A}, prnd...)
	challenge = append(challenge, h.Sum(nil)...)
	challenge = append(challenge, 0xBC)
	sig := RawRSA(tn, new(big.Int).SetBytes(terminalPrivExp), challenge)
	if _, err := c.expect("EXTERNAL AUTHENTICATE", command{cla: 0x00, ins: 0x82, p1: 0x00, p2: 0x00, data: append(append([]byte{}, TerminalSerial...), sig...)}); err != nil {
		return err
	}

	if _, err := c.expect("MSE SET internal authentication", command{cla: 0x00, ins: 0x22, p1: 0x41, p2: 0xA4,
		data: append(EncodeTLV(0x84, []byte{keyIntAuth}), EncodeTLV(0x80, []byte{0x9B})...)}); err != nil {
		return err
	}
	rndIFD := make([]byte, 8)
	if _, err := io.ReadFull(c.rand(), rndIFD); err != nil {
		return err
	}
	resp, err := c.expect("INTERNAL AUTHENTICATE", command{cla: 0x00, ins: 0x88, p1: 0x00, p2: 0x00, data: rndIFD})
	if err != nil {
		return err
	}
	if err := c.checkChip(resp, rndIFD); err != nil {
		return err
	}
	c.sm.ssc = append(append([]byte{}, rndICC[4:]...), rndIFD[4:]...)
	return nil
}

func (c *Card) checkRootSignature(cert, block []byte, k int) error {
	outer, _, err := ParseTLV(cert)
	if err != nil {
		return err
	}
	kids, err := ParseTLVs(outer.Value)
	if err != nil || len(kids) < 1 || len(kids[0].Value) != k {
		return protoErr("DAPP", "bad terminal certificate")
	}
	if !bytes.Equal(RawRSA(c.rootN, c.rootE, kids[0].Value), block) {
		return &ProtocolError{Op: "DAPP", Err: errRootKey}
	}
	return nil
}

// checkChip verifies the chip's INTERNAL AUTHENTICATE answer: SN.ICC (8 bytes) || signature, where the signature
// recovers under EF 1004's key to 6A || PRND2 || SHA-256(PRND2 || Y.ICC || SN.ICC || RND.IFD || Y.IFD || g || p || q) || BC.
func (c *Card) checkChip(resp, rndIFD []byte) error {
	k := (c.intAuthN.BitLen() + 7) / 8
	if len(resp) != 8+k {
		return &ProtocolError{Op: "DAPP", Err: fmt.Errorf("%w: answer of %d bytes", errDAPP, len(resp))}
	}
	snICC, sig := resp[:8], resp[8:]
	if new(big.Int).SetBytes(sig).Cmp(c.intAuthN) >= 0 {
		return &ProtocolError{Op: "DAPP", Err: errDAPP}
	}
	m := RawRSA(c.intAuthN, c.intAuthE, sig)
	if m[0] != 0x6A || m[k-1] != 0xBC || k < 34 {
		return &ProtocolError{Op: "DAPP", Err: errDAPP}
	}
	prnd2, got := m[1:k-33], m[k-33:k-1]
	h := sha256.New()
	for _, part := range [][]byte{prnd2, c.yICC, snICC, rndIFD, c.yIFD, c.transcriptTail()} {
		h.Write(part)
	}
	if subtle.ConstantTimeCompare(h.Sum(nil), got) != 1 {
		return &ProtocolError{Op: "DAPP", Err: errDAPP}
	}
	return nil
}
