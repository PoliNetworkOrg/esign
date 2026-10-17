package ias

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	_ "crypto/sha1" // SHA-1 signatures of CSCA02/03-era certificates and SODs
	_ "crypto/sha256"
	_ "crypto/sha512"
	"crypto/x509"
	"embed"
	"errors"
	"fmt"
	"strings"
	"sync"
)

// The Italian Country Signing CA (CSCA) certificates, the trust anchors of the CIE's document security object.
// Downloaded on 17 October 2026 from https://csca-ita.interno.gov.it/ (links "CSCA00.cer" … "CSCA05.cer", under
// https://csca-ita.interno.gov.it/certificatiCSCA/); SHA-256 of the DER files:
//
//	67854114c1eb9cdf204193f109a45e0c5df89ae775b9ea339670692022c9f02f  CSCA00.cer  CERTIFICATION AUTHORITY, 2006–2022
//	881c9c09589c134b3dbb99635ba8487f6b19bde7b56e4918eadb9621be7112f9  CSCA01.cer  CERTIFICATION AUTHORITY 01, 2011–2027
//	24490b589de47553733db6053865edfe14266d5d46bc3933186327a7cb7cfb8e  CSCA02.cer  Italian Country Signer CA, 2016–2031
//	1cebe30f2122b8d134b0a3018554ed0f62945056290942fce08396407b944146  CSCA03.cer  Italian Country Signer CA, 2016–2031
//	f9f2c2554b60c7c6c1f17a3696cfd46afb65618fee17a3d42ac89be3a8f8c689  CSCA04.cer  Italian Country Signer CA, 2020–2035
//	615bd40cd7bc63aeb572cf168ccb78162003b31cd98130dd71f7d2d69c83fa3a  CSCA05.cer  Italian Country Signer CA, 2024–2039
//
// The same list is in csca/SHA256SUMS, and TestItalianCSCAs checks the embedded files against it. All six are
// self-signed and pinned directly, so the published link certificates are not needed. CSCA00–03 sign with SHA-1,
// which crypto/x509's chain verification refuses; this file verifies the one-level chain itself.

//go:embed csca
var cscaFiles embed.FS

var (
	cscaOnce  sync.Once
	cscaCerts []*x509.Certificate
)

// ItalianCSCAs returns the pinned Italian CSCA certificates, the default trust anchors.
func ItalianCSCAs() []*x509.Certificate {
	cscaOnce.Do(func() {
		entries, err := cscaFiles.ReadDir("csca")
		if err != nil {
			panic(err)
		}
		for _, e := range entries {
			if !strings.HasSuffix(e.Name(), ".cer") {
				continue
			}
			der, err := cscaFiles.ReadFile("csca/" + e.Name())
			if err != nil {
				panic(err)
			}
			c, err := x509.ParseCertificate(der)
			if err != nil {
				panic(fmt.Sprintf("embedded CSCA %s: %v", e.Name(), err))
			}
			cscaCerts = append(cscaCerts, c)
		}
	})
	return cscaCerts
}

// signatureHash is the hash of an X.509 signature algorithm, and whether it is RSASSA-PSS.
func signatureHash(a x509.SignatureAlgorithm) (crypto.Hash, bool, error) {
	switch a {
	case x509.SHA1WithRSA, x509.ECDSAWithSHA1:
		return crypto.SHA1, false, nil
	case x509.SHA256WithRSA, x509.ECDSAWithSHA256:
		return crypto.SHA256, false, nil
	case x509.SHA384WithRSA, x509.ECDSAWithSHA384:
		return crypto.SHA384, false, nil
	case x509.SHA512WithRSA, x509.ECDSAWithSHA512:
		return crypto.SHA512, false, nil
	case x509.SHA256WithRSAPSS:
		return crypto.SHA256, true, nil
	case x509.SHA384WithRSAPSS:
		return crypto.SHA384, true, nil
	case x509.SHA512WithRSAPSS:
		return crypto.SHA512, true, nil
	}
	return 0, false, fmt.Errorf("unsupported signature algorithm %v", a)
}

// verifyDigest checks a signature over digest with an RSA (PKCS#1 v1.5 or PSS) or ECDSA public key.
func verifyDigest(pub any, h crypto.Hash, pss bool, digest, sig []byte) error {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		if pss {
			return rsa.VerifyPSS(k, h, digest, sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto})
		}
		return rsa.VerifyPKCS1v15(k, h, digest, sig)
	case *ecdsa.PublicKey:
		if pss || !ecdsa.VerifyASN1(k, digest, sig) {
			return errors.New("ECDSA verification failed")
		}
		return nil
	}
	return fmt.Errorf("unsupported public key %T", pub)
}

// issuedBy checks that child was signed by ca, a CA certificate valid when child was issued. The time of issuance is
// the point of reference (the chain model): Document Signer keys sign only at personalization, and a card stays
// genuine while its own certificate is valid, which the backend checks.
func issuedBy(child, ca *x509.Certificate) error {
	if !ca.BasicConstraintsValid || !ca.IsCA {
		return errors.New("issuer is not a CA")
	}
	if ca.KeyUsage != 0 && ca.KeyUsage&x509.KeyUsageCertSign == 0 {
		return errors.New("issuer may not sign certificates")
	}
	if !bytes.Equal(child.RawIssuer, ca.RawSubject) && child.Issuer.String() != ca.Subject.String() {
		return errors.New("issuer name differs")
	}
	if child.NotBefore.Before(ca.NotBefore) || child.NotBefore.After(ca.NotAfter) {
		return errors.New("issued outside the CA's validity")
	}
	h, pss, err := signatureHash(child.SignatureAlgorithm)
	if err != nil {
		return err
	}
	d := h.New()
	d.Write(child.RawTBSCertificate)
	return verifyDigest(ca.PublicKey, h, pss, d.Sum(nil), child.Signature)
}

// verifyDocumentSigner finds the anchor that issued ds. Several Italian CSCAs share a name, so every candidate is
// tried by signature.
func verifyDocumentSigner(ds *x509.Certificate, anchors []*x509.Certificate) (*x509.Certificate, error) {
	var errs []error
	for _, a := range anchors {
		if err := issuedBy(ds, a); err == nil {
			return a, nil
		} else {
			errs = append(errs, fmt.Errorf("%s: %w", a.Subject.CommonName, err))
		}
	}
	if len(anchors) == 0 {
		return nil, errors.New("no trust anchors")
	}
	return nil, fmt.Errorf("document signer %q is not issued by a trusted CSCA: %w", ds.Subject.String(), errors.Join(errs...))
}
