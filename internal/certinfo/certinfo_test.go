package certinfo

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"
)

func certificate(cn string, extra ...pkix.AttributeTypeAndValue) *x509.Certificate {
	names := []pkix.AttributeTypeAndValue{{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: cn}}
	return &x509.Certificate{Subject: pkix.Name{CommonName: cn, Names: append(names, extra...)}}
}

func TestParse(t *testing.T) {
	given := pkix.AttributeTypeAndValue{Type: oidGivenName, Value: "MARIO"}
	surname := pkix.AttributeTypeAndValue{Type: oidSurname, Value: "ROSSI"}
	serial := func(v string) pkix.AttributeTypeAndValue {
		return pkix.AttributeTypeAndValue{Type: oidSerialNumber, Value: v}
	}
	cases := []struct {
		name, fiscalCode, displayName string
		cert                          *x509.Certificate
	}{
		// The subject of a real CIE 3.0 authentication certificate (SUBCA003), with another person's data.
		{"cie", "RSSMRA80A01F205X", "Mario Rossi", certificate("RSSMRA80A01F205X/041001234567", serial("IDCIT-CA00000AA"), given, surname)},
		{"tinit", "RSSMRA80A01F205X", "Mario Rossi", certificate("MARIO ROSSI", serial("TINIT-RSSMRA80A01F205X"), given, surname)},
		{"omocodia", "RSSMRA80A01F20RX", "Mario Rossi", certificate("RSSMRA80A01F20RX/041001234567", given, surname)},
		{"none", "", "Mario Rossi", certificate("MARIO ROSSI", serial("IDCIT-CA00000AA"))},
		{"not a code", "", "041001234567/rssmra80a01f205x", certificate("041001234567/RSSMRA80A01F205X", serial("TINIT-12345"))},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			info := Parse(c.cert)
			if info.FiscalCode != c.fiscalCode || info.DisplayName != c.displayName {
				t.Fatalf("Parse = %q, %q; want %q, %q", info.FiscalCode, info.DisplayName, c.fiscalCode, c.displayName)
			}
		})
	}
}
