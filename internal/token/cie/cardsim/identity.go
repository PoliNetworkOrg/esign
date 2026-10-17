package cardsim

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"math/big"
	"time"

	"github.com/PoliNetworkOrg/sign-agent/internal/token/cie/ias"
)

// Identity is the citizen and document data on the card.
type Identity struct {
	Surname    string
	GivenName  string
	FiscalCode string
	// NIS is EF.ID_Servizi, 12 digits. The PAN in EF.SN.ICC carries it in BCD at bytes 5..10, which is how the
	// official middleware names the pairing cache both when writing and when reading it.
	NIS string
	// Serial is the printed card number, EF 1002 (9 characters).
	Serial string
}

// DefaultIdentity is a fictitious citizen.
var DefaultIdentity = Identity{Surname: "ROSSI", GivenName: "MARIO", FiscalCode: "RSSMRA80A01F205X", NIS: "123456789012", Serial: "CA00000AA"}

// Keys are the card's RSA keys and the test PKI around them.
type Keys struct {
	Citizen   *rsa.PrivateKey // key 81, certificate in EF 1003
	IntAuth   *rsa.PrivateKey // key 82, DAPP chip authentication, public in EF 1004
	Service   *rsa.PrivateKey // key 83, PIN-less service authentication, public in EF 1005
	Issuer    *rsa.PrivateKey // CA issuing the citizen certificate
	DocSigner *rsa.PrivateKey // signs EF.SOD
}

// GenerateKeys creates a fresh set of RSA-2048 keys. It takes a few seconds; tests share one set.
func GenerateKeys() (*Keys, error) {
	var ks [5]*rsa.PrivateKey
	for i := range ks {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
		ks[i] = k
	}
	return &Keys{Citizen: ks[0], IntAuth: ks[1], Service: ks[2], Issuer: ks[3], DocSigner: ks[4]}, nil
}

var (
	oidSurname   = asn1.ObjectIdentifier{2, 5, 4, 4}
	oidGivenName = asn1.ObjectIdentifier{2, 5, 4, 42}
	oidSerial    = asn1.ObjectIdentifier{2, 5, 4, 5}
)

// pki is the certificates a card is personalized with.
type pki struct {
	issuer, citizen, docSigner *x509.Certificate
}

func makePKI(id Identity, k *Keys, now time.Time) (*pki, error) {
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Country: []string{"IT"}, Organization: []string{"Simulated Ministero dell'Interno"}, CommonName: "Simulated CIE Issuing CA"},
		NotBefore:             now.Add(-24 * time.Hour),
		NotAfter:              now.AddDate(10, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &k.Issuer.PublicKey, k.Issuer)
	if err != nil {
		return nil, err
	}
	ca, _ := x509.ParseCertificate(caDER)
	// The CIE authentication certificate (chip specification §6.12.2): critical keyUsage digitalSignature only,
	// extendedKeyUsage clientAuth.
	cTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()),
		Subject: pkix.Name{
			Country:    []string{"IT"},
			CommonName: id.Surname + " " + id.GivenName,
			ExtraNames: []pkix.AttributeTypeAndValue{
				{Type: oidSurname, Value: id.Surname},
				{Type: oidGivenName, Value: id.GivenName},
				{Type: oidSerial, Value: "TINIT-" + id.FiscalCode},
			},
		},
		NotBefore:   now.Add(-24 * time.Hour),
		NotAfter:    now.AddDate(10, 0, 0),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	cDER, err := x509.CreateCertificate(rand.Reader, cTmpl, ca, &k.Citizen.PublicKey, k.Issuer)
	if err != nil {
		return nil, err
	}
	citizen, _ := x509.ParseCertificate(cDER)
	dsTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{Country: []string{"IT"}, CommonName: "Simulated CIE Document Signer"},
		NotBefore:    now.Add(-24 * time.Hour),
		NotAfter:     now.AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	dsDER, err := x509.CreateCertificate(rand.Reader, dsTmpl, ca, &k.DocSigner.PublicKey, k.Issuer)
	if err != nil {
		return nil, err
	}
	ds, _ := x509.ParseCertificate(dsDER)
	return &pki{issuer: ca, citizen: citizen, docSigner: ds}, nil
}

// pan builds EF.SN.ICC: five header bytes, the NIS in BCD, one trailing byte.
func pan(nis string) ([]byte, error) {
	bcd, err := hex.DecodeString(nis)
	if err != nil || len(nis) != 12 {
		return nil, fmt.Errorf("NIS must be 12 digits")
	}
	return append(append([]byte{0x5A, 0x0A, 0x00, 0x00, 0x00}, bcd...), 0x00), nil
}

// dhFile is EF.DH: SEQUENCE { p, g, q }.
func dhFile() []byte {
	var body []byte
	for _, v := range []*big.Int{dhP, dhG, dhQ} {
		body = append(body, ias.EncodeTLV(0x02, derInt(v))...)
	}
	return ias.EncodeTLV(0x30, body)
}

func derInt(v *big.Int) []byte {
	b := v.Bytes()
	if len(b) == 0 || b[0]&0x80 != 0 {
		b = append([]byte{0}, b...)
	}
	return b
}

var (
	oidSHA256        = []byte{0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01}
	oidSignedData    = []byte{0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02}
	oidLDSSecurity   = []byte{0x67, 0x81, 0x08, 0x01, 0x01, 0x01}
	oidContentType   = []byte{0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x03}
	oidMessageDigest = []byte{0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x04}
	oidSHA256RSA     = []byte{0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B}
)

func tlv(tag uint32, parts ...[]byte) []byte {
	var v []byte
	for _, p := range parts {
		v = append(v, p...)
	}
	return ias.EncodeTLV(tag, v)
}

// sod builds EF.SOD as the official pairing code parses it (CSP/IAS.cpp VerificaSOD): CMS SignedData over an ICAO
// LDS security object with SHA-256 hashes of the NIS (A1), serial (A2), certificate (A3), EF 1004 (A4), EF 1005 (A5)
// and EF.DH (1B), signed with RSA PKCS#1 v1.5 SHA-256. Data group numbers are one-byte INTEGERs, which is what the
// reference's ByteArrayToVar(content, BYTE) reads.
func sod(hashes map[byte][]byte, ds *x509.Certificate, key *rsa.PrivateKey) ([]byte, error) {
	var dgs []byte
	for _, n := range []byte{0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0x1B} {
		dgs = append(dgs, tlv(0x30, ias.EncodeTLV(0x02, []byte{n}), ias.EncodeTLV(0x04, hashes[n]))...)
	}
	lds := tlv(0x30, ias.EncodeTLV(0x02, []byte{0}), tlv(0x30, ias.EncodeTLV(0x06, oidSHA256)), tlv(0x30, dgs))
	ldsDigest := sha256.Sum256(lds)
	attrs := append(
		tlv(0x30, ias.EncodeTLV(0x06, oidContentType), tlv(0x31, ias.EncodeTLV(0x06, oidLDSSecurity))),
		tlv(0x30, ias.EncodeTLV(0x06, oidMessageDigest), tlv(0x31, ias.EncodeTLV(0x04, ldsDigest[:])))...,
	)
	signed := sha256.Sum256(ias.EncodeTLV(0x31, attrs))
	sig, err := rsa.SignPKCS1v15(nil, key, crypto.SHA256, signed[:])
	if err != nil {
		return nil, err
	}
	signerInfo := tlv(0x30,
		ias.EncodeTLV(0x02, []byte{1}),
		tlv(0x30, ds.RawIssuer, ias.EncodeTLV(0x02, derInt(ds.SerialNumber))),
		tlv(0x30, ias.EncodeTLV(0x06, oidSHA256)),
		ias.EncodeTLV(0xA0, attrs),
		tlv(0x30, ias.EncodeTLV(0x06, oidSHA256RSA), []byte{0x05, 0x00}),
		ias.EncodeTLV(0x04, sig),
	)
	signedData := tlv(0x30,
		ias.EncodeTLV(0x02, []byte{3}),
		tlv(0x31, tlv(0x30, ias.EncodeTLV(0x06, oidSHA256))),
		tlv(0x30, ias.EncodeTLV(0x06, oidLDSSecurity), tlv(0xA0, ias.EncodeTLV(0x04, lds))),
		tlv(0xA0, ds.Raw),
		tlv(0x31, signerInfo),
	)
	return tlv(0x30, ias.EncodeTLV(0x06, oidSignedData), tlv(0xA0, signedData)), nil
}

func sum(b []byte) []byte {
	s := sha256.Sum256(b)
	return s[:]
}
