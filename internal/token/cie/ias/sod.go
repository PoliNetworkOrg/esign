package ias

import (
	"bytes"
	"crypto"
	"crypto/subtle"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
)

// Data groups of the CIE's document security object (EF.SOD, EF 1006), as the official pairing code hashes them
// (CSP/AbilitaCIE.cpp, the hashSet before VerificaSOD): each value is the hash of the file's first BER object.
const (
	DGServiceID  = 0xA1 // EF 1001, first 12 bytes
	DGSerial     = 0xA2 // EF 1002, first 9 bytes
	DGCert       = 0xA3 // EF 1003
	DGIntAuthKey = 0xA4 // EF 1004, the DAPP chip key
	DGServiceKey = 0xA5 // EF 1005
	DGDH         = 0x1B // EF.DH (D004), the DH domain parameters
)

// OIDs, as encoded object identifier contents.
var (
	oidSignedData     = []byte{0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02}
	oidLDSSecurity    = []byte{0x67, 0x81, 0x08, 0x01, 0x01, 0x01}
	oidContentType    = []byte{0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x03}
	oidMessageDigest  = []byte{0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x04}
	oidRSAEncryption  = []byte{0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01}
	oidSHA1WithRSA    = []byte{0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x05}
	oidSHA256WithRSA  = []byte{0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B}
	oidSHA384WithRSA  = []byte{0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0C}
	oidSHA512WithRSA  = []byte{0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0D}
	oidRSAPSS         = []byte{0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0A}
	oidECDSAWithSHA1  = []byte{0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x01}
	oidECDSAWithSHA2x = []byte{0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03} // .2 SHA-256, .3 SHA-384, .4 SHA-512
)

var digestOIDs = map[string]crypto.Hash{
	string([]byte{0x2B, 0x0E, 0x03, 0x02, 0x1A}):                         crypto.SHA1,
	string([]byte{0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01}): crypto.SHA256,
	string([]byte{0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02}): crypto.SHA384,
	string([]byte{0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03}): crypto.SHA512,
	string([]byte{0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04}): crypto.SHA224,
}

// SOD is a document security object whose signature and Document Signer chain were verified.
type SOD struct {
	hash   crypto.Hash
	hashes map[byte][]byte
	// Signer is the Document Signer certificate; Anchor the trusted CSCA that issued it.
	Signer, Anchor *x509.Certificate
}

// children parses the content of a constructed object.
func children(t TLV) ([]TLV, error) { return ParseTLVs(t.Value) }

// algorithmOID returns the OID of an AlgorithmIdentifier and its parameters, if any.
func algorithmOID(t TLV) ([]byte, *TLV, error) {
	kids, err := children(t)
	if err != nil || len(kids) == 0 || kids[0].Tag != 0x06 {
		return nil, nil, errors.New("bad AlgorithmIdentifier")
	}
	if len(kids) > 1 && kids[1].Tag != 0x05 {
		return kids[0].Value, &kids[1], nil
	}
	return kids[0].Value, nil, nil
}

func digestAlgorithm(t TLV) (crypto.Hash, error) {
	oid, _, err := algorithmOID(t)
	if err != nil {
		return 0, err
	}
	h, ok := digestOIDs[string(oid)]
	if !ok || !h.Available() {
		return 0, fmt.Errorf("unsupported digest algorithm %X", oid)
	}
	return h, nil
}

func expect(t TLV, tag uint32, what string) error {
	if t.Tag != tag {
		return fmt.Errorf("%s: tag %X, want %X", what, t.Tag, tag)
	}
	return nil
}

// VerifySOD parses EF.SOD (ICAO tag 77 around a CMS ContentInfo with SignedData over an LDS security object),
// verifies the signer's signature and that the Document Signer certificate inside it was issued by one of anchors.
// The returned SOD then authenticates the hashes of the card's files.
func VerifySOD(sod []byte, anchors []*x509.Certificate) (*SOD, error) {
	s, err := verifySOD(sod, anchors)
	if err != nil {
		return nil, fmt.Errorf("document security object: %w", err)
	}
	return s, nil
}

func verifySOD(sod []byte, anchors []*x509.Certificate) (*SOD, error) {
	top, _, err := ParseTLV(sod)
	if err != nil {
		return nil, err
	}
	if top.Tag == 0x77 {
		if top, _, err = ParseTLV(top.Value); err != nil {
			return nil, err
		}
	}
	// ContentInfo
	ci, err := children(top)
	if err != nil || len(ci) < 2 || ci[0].Tag != 0x06 || !bytes.Equal(ci[0].Value, oidSignedData) || ci[1].Tag != 0xA0 {
		return nil, errors.New("not a CMS SignedData")
	}
	sdObj, _, err := ParseTLV(ci[1].Value)
	if err != nil {
		return nil, err
	}
	sd, err := children(sdObj)
	if err != nil || len(sd) < 4 {
		return nil, errors.New("bad SignedData")
	}
	// version, digestAlgorithms, encapContentInfo, [0] certificates, [1] crls, signerInfos
	encap, err := children(sd[2])
	if err != nil || len(encap) < 2 || !bytes.Equal(encap[0].Value, oidLDSSecurity) || encap[1].Tag != 0xA0 {
		return nil, errors.New("content is not an LDS security object")
	}
	octets, _, err := ParseTLV(encap[1].Value)
	if err != nil || octets.Tag != 0x04 {
		return nil, errors.New("bad encapsulated content")
	}
	lds := octets.Value

	var certs []*x509.Certificate
	var signerInfos []TLV
	for _, o := range sd[3:] {
		switch o.Tag {
		case 0xA0:
			kids, err := children(o)
			if err != nil {
				return nil, err
			}
			for _, k := range kids {
				if c, err := x509.ParseCertificate(k.Raw); err == nil {
					certs = append(certs, c)
				}
			}
		case 0x31:
			if signerInfos, err = children(o); err != nil {
				return nil, err
			}
		}
	}
	if len(signerInfos) != 1 {
		return nil, fmt.Errorf("%d signer infos, want 1", len(signerInfos))
	}
	si, err := children(signerInfos[0])
	if err != nil || len(si) < 5 {
		return nil, errors.New("bad SignerInfo")
	}
	ds, err := findSigner(si[1], certs)
	if err != nil {
		return nil, err
	}
	digest, err := digestAlgorithm(si[2])
	if err != nil {
		return nil, err
	}
	rest := si[3:]
	var signed []byte
	if rest[0].Tag == 0xA0 {
		attrs := rest[0]
		if err := checkSignedAttributes(attrs, digest, lds); err != nil {
			return nil, err
		}
		// The signature covers the attributes encoded as a SET.
		signed = append([]byte{0x31}, attrs.Raw[1:]...)
		rest = rest[1:]
	} else {
		signed = lds
	}
	if len(rest) < 2 || rest[1].Tag != 0x04 {
		return nil, errors.New("bad SignerInfo signature")
	}
	if err := checkSignature(rest[0], digest, ds, signed, rest[1].Value); err != nil {
		return nil, fmt.Errorf("signature: %w", err)
	}
	anchor, err := verifyDocumentSigner(ds, anchors)
	if err != nil {
		return nil, err
	}
	out := &SOD{Signer: ds, Anchor: anchor, hashes: map[byte][]byte{}}
	if err := out.parseLDS(lds); err != nil {
		return nil, err
	}
	return out, nil
}

// findSigner picks the certificate the SignerInfo names: issuer and serial number, or [0] subject key identifier.
func findSigner(sid TLV, certs []*x509.Certificate) (*x509.Certificate, error) {
	switch sid.Tag {
	case 0x30:
		kids, err := children(sid)
		if err != nil || len(kids) != 2 || kids[1].Tag != 0x02 {
			return nil, errors.New("bad signer identifier")
		}
		serial := new(big.Int).SetBytes(kids[1].Value)
		for _, c := range certs {
			if bytes.Equal(c.RawIssuer, kids[0].Raw) && c.SerialNumber.Cmp(serial) == 0 {
				return c, nil
			}
		}
	case 0x80:
		for _, c := range certs {
			if len(c.SubjectKeyId) > 0 && bytes.Equal(c.SubjectKeyId, sid.Value) {
				return c, nil
			}
		}
	}
	return nil, errors.New("the Document Signer certificate is not in the SOD")
}

// checkSignedAttributes requires the content type to be an LDS security object and the message digest to match.
func checkSignedAttributes(attrs TLV, h crypto.Hash, lds []byte) error {
	list, err := children(attrs)
	if err != nil {
		return err
	}
	var contentTypeOK, digestOK bool
	for _, a := range list {
		kids, err := children(a)
		if err != nil || len(kids) != 2 || kids[0].Tag != 0x06 || kids[1].Tag != 0x31 {
			return errors.New("bad signed attribute")
		}
		vals, err := children(kids[1])
		if err != nil || len(vals) != 1 {
			return errors.New("bad signed attribute value")
		}
		switch {
		case bytes.Equal(kids[0].Value, oidContentType):
			contentTypeOK = vals[0].Tag == 0x06 && bytes.Equal(vals[0].Value, oidLDSSecurity)
		case bytes.Equal(kids[0].Value, oidMessageDigest):
			d := h.New()
			d.Write(lds)
			digestOK = vals[0].Tag == 0x04 && subtle.ConstantTimeCompare(vals[0].Value, d.Sum(nil)) == 1
		}
	}
	if !contentTypeOK {
		return errors.New("content type attribute missing or wrong")
	}
	if !digestOK {
		return errors.New("message digest does not match the security object")
	}
	return nil
}

// checkSignature verifies the SignerInfo signature with the Document Signer key: RSA PKCS#1 v1.5 (rsaEncryption or
// shaNWithRSAEncryption), RSASSA-PSS with its hash parameter, or ECDSA.
func checkSignature(alg TLV, digest crypto.Hash, ds *x509.Certificate, signed, sig []byte) error {
	oid, params, err := algorithmOID(alg)
	if err != nil {
		return err
	}
	h, pss := digest, false
	switch {
	case bytes.Equal(oid, oidRSAEncryption):
	case bytes.Equal(oid, oidSHA1WithRSA), bytes.Equal(oid, oidECDSAWithSHA1):
		h = crypto.SHA1
	case bytes.Equal(oid, oidSHA256WithRSA), bytes.Equal(oid, append(append([]byte{}, oidECDSAWithSHA2x...), 0x02)):
		h = crypto.SHA256
	case bytes.Equal(oid, oidSHA384WithRSA), bytes.Equal(oid, append(append([]byte{}, oidECDSAWithSHA2x...), 0x03)):
		h = crypto.SHA384
	case bytes.Equal(oid, oidSHA512WithRSA), bytes.Equal(oid, append(append([]byte{}, oidECDSAWithSHA2x...), 0x04)):
		h = crypto.SHA512
	case bytes.Equal(oid, oidRSAPSS):
		pss = true
		h = crypto.SHA1 // RFC 4055 default
		if params != nil {
			fields, err := children(*params)
			if err != nil {
				return err
			}
			if f, ok := Find(fields, 0xA0); ok {
				inner, _, err := ParseTLV(f.Value)
				if err != nil {
					return err
				}
				if h, err = digestAlgorithm(inner); err != nil {
					return err
				}
			}
		}
	default:
		return fmt.Errorf("unsupported signature algorithm %X", oid)
	}
	d := h.New()
	d.Write(signed)
	return verifyDigest(ds.PublicKey, h, pss, d.Sum(nil), sig)
}

// parseLDS reads the LDS security object: version, hash algorithm, then (data group, hash) pairs.
func (s *SOD) parseLDS(lds []byte) error {
	top, _, err := ParseTLV(lds)
	if err != nil {
		return err
	}
	kids, err := children(top)
	if err != nil || len(kids) < 3 {
		return errors.New("bad LDS security object")
	}
	if s.hash, err = digestAlgorithm(kids[1]); err != nil {
		return err
	}
	groups, err := children(kids[2])
	if err != nil {
		return err
	}
	for _, g := range groups {
		f, err := children(g)
		if err != nil || len(f) != 2 || f[0].Tag != 0x02 || len(f[0].Value) == 0 || f[1].Tag != 0x04 {
			return errors.New("bad data group hash")
		}
		// The number is read as its last byte: the CIE encodes A1…A5 in one byte, as the reference expects.
		s.hashes[f[0].Value[len(f[0].Value)-1]] = f[1].Value
	}
	return nil
}

// Check compares the hash of a file's content (its first BER object, as the official code hashes it) with the
// SOD's hash for data group dg.
func (s *SOD) Check(dg byte, content []byte) error {
	want, ok := s.hashes[dg]
	if !ok {
		return fmt.Errorf("the SOD has no hash for data group %02X", dg)
	}
	if n, err := EncodedLength(content); err == nil {
		content = content[:n]
	}
	d := s.hash.New()
	d.Write(content)
	if subtle.ConstantTimeCompare(d.Sum(nil), want) != 1 {
		return fmt.Errorf("data group %02X does not match the SOD", dg)
	}
	return nil
}
