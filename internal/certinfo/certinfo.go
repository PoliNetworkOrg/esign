// Package certinfo extracts the signer's identity from a CIE certificate.
package certinfo

import (
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"regexp"
	"strings"
)

// Info is the identity in a certificate subject.
type Info struct {
	CommonName string `json:"commonName"`
	GivenName  string `json:"givenName,omitempty"`
	Surname    string `json:"surname,omitempty"`
	// FiscalCode is the Italian codice fiscale: a CIE authentication certificate has it in CN "<code>/<NIS>", its
	// serialNumber being the document number "IDCIT-…"; other Italian certificates in serialNumber "TINIT-<code>"
	// (ETSI EN 319 412-1).
	FiscalCode string `json:"fiscalCode,omitempty"`
	// DisplayName is "Given Surname" in title case, or the common name.
	DisplayName string `json:"displayName"`
}

var (
	oidSurname      = asn1.ObjectIdentifier{2, 5, 4, 4}
	oidSerialNumber = asn1.ObjectIdentifier{2, 5, 4, 5}
	oidGivenName    = asn1.ObjectIdentifier{2, 5, 4, 42}

	// fiscalCode is six letters, birth year, month letter, day, municipality and check letter; digits may be replaced
	// by letters (omocodia).
	fiscalCode = regexp.MustCompile(`^[A-Z]{6}[0-9LMNPQRSTUV]{2}[A-Z][0-9LMNPQRSTUV]{2}[A-Z][0-9LMNPQRSTUV]{3}[A-Z]$`)
)

// Parse reads the identity from cert.
func Parse(cert *x509.Certificate) Info {
	info := Info{CommonName: cert.Subject.CommonName}
	for _, n := range cert.Subject.Names {
		value := fmt.Sprint(n.Value)
		switch {
		case n.Type.Equal(oidSurname):
			info.Surname = value
		case n.Type.Equal(oidGivenName):
			info.GivenName = value
		case n.Type.Equal(oidSerialNumber):
			if code, ok := strings.CutPrefix(strings.ToUpper(value), "TINIT-"); ok && fiscalCode.MatchString(code) {
				info.FiscalCode = code
			}
		}
	}
	if code, _, _ := strings.Cut(strings.ToUpper(info.CommonName), "/"); info.FiscalCode == "" && fiscalCode.MatchString(code) {
		info.FiscalCode = code
	}
	if info.GivenName != "" && info.Surname != "" {
		info.DisplayName = title(info.GivenName) + " " + title(info.Surname)
	} else {
		info.DisplayName = title(info.CommonName)
	}
	return info
}

func title(s string) string {
	words := strings.Fields(strings.ToLower(s))
	for i, w := range words {
		words[i] = capitalize(w)
	}
	return strings.Join(words, " ")
}

// capitalize uppercases the first letter of w and of each part after an apostrophe or hyphen ("d'amico" → "D'Amico").
func capitalize(w string) string {
	r := []rune(w)
	upper := true
	for i, c := range r {
		if upper {
			r[i] = []rune(strings.ToUpper(string(c)))[0]
		}
		upper = c == '\'' || c == '-'
	}
	return string(r)
}
