package ias

import (
	"encoding/hex"
	"math/big"
)

// Fixed key material of the reference implementation (italia/cie-middleware-linux, CSP/IAS.cpp and
// CSP/ExtAuthKey.cpp). These are not secrets of any citizen: the CIE specification gives every terminal the same
// card-verifiable certificate key so that the card can run DAPP with any reader software. The citizen authenticates
// with the PIN; DAPP authenticates the chip to the terminal and binds the DH exchange.

// terminalModulus and terminalPrivExp are the terminal (IFD) RSA key of the reference (IAS.cpp defModule,
// defPrivExp); its public exponent is 65537, encoded on four bytes in the CV certificate (defPubExp).
var terminalModulus = mustHex("" +
	"ba2837ab4c6bb827577bff4eb7b1e49cdde0f16614d1ef24c1b75cf70fb12cd18f4d14e2814ba4877ea800e175906076" +
	"b562ba535973c5d8b378051d8afc7407a1d919529e03c106cda18d699afb0d8ab4fddd9dc719159a50de9468f02ab103" +
	"e282a50e716ec23cda5bfc4a232b09a4b2c70745939549099b4483cbae62d0099674dbf6f39b7223a99d88e33f1a0cde" +
	"deebbdc35517abe9880aab240e1ea166283a274a9ad93b4b1d19f3679f3e8b5ff6a1e0ed736e84d5abe03c59e7346b42" +
	"18755d75366cbf4136f0a26c3dc70a69abaaf66e13a1b2faad052ca6ec9c51e2aed14d16e090254dc3f64ea2bd8a836b" +
	"ba99defacba3a613aeedd93a9615273d",
)

var terminalPrivExp = mustHex("" +
	"4716c2a38ccc7a07b415eb1a6175f2aaa0e49ceaf1ba75cba09a684b04d8111879d3e2ccd8b94d3c5cf6c55753f0ed95" +
	"87910b3c77258a01460fe84c2ede5764eebe9c37fb95cd69ceaf09f4b1357c276314ab43ec5b3cefb0403f868f688e2e" +
	"c09a4973e987756f8da7a101a2ca75a54a8c4ccf9a1b6147e4de56423af70b2067179c5eeb646867863478d752c7f412" +
	"db277541575aa0619d30bccc8d87e6170b33439a2c93f2d97e18c0a82343a6012a5bb1822808f01b5cfd85673ac0964c" +
	"5f3cfd2daf8142359764a9adb9e3f76db613461c1bc913dc9ac0ab50d365f77cb93194c98aa966d89cdd555125a5e59e" +
	"cf4fa3f0c3fd610cd3d056439338fd81",
)

// terminalPubExp is the public exponent as encoded in the CV certificate body.
var terminalPubExp = []byte{0x00, 0x01, 0x00, 0x01}

// RootPrivExp is the private exponent of the CV root key that signs the terminal certificate (ExtAuthKey.cpp,
// baExtAuth_PrivExp). The card supplies the matching modulus and public exponent.
var RootPrivExp = mustHex("" +
	"186b31488c25dcf85d953d3630c0d073ba1c6aa24581ad254f3b6719c5d72cca3e5cdc5a1e5316578d75954ff73b237b" +
	"532c9f8de4a2c4c911385a23e63e33e47ee45e66efd49b18e02cff87598c39109e8f86a66bc330249ce3fcad655dcdbf" +
	"98c9c5e479321af53b517d041061880a647bbe0ff813683470e6c50094ce81d064e204e351bd3ae0a7947d8e91c3fd5c" +
	"0a15233c349a5215a4e66e21c5d33498e71991ea24473b29f1475f6fd9be3996e19bd474fad1b41ea0dcd2fc16c9bffa" +
	"071bfec1b22415184811c1985fbfe3e7b4f44a4b3c8dfab4d90cecfc5e608d673e6762c62cb798341271149ba688162e" +
	"c7d0e3468f65a94ab4ad1ab67e37bfc1",
)

// TerminalPublicKey is the terminal's RSA public key: the card verifies DAPP's external authentication with it.
func TerminalPublicKey() (n, e *big.Int) {
	return new(big.Int).SetBytes(terminalModulus), new(big.Int).SetBytes(terminalPubExp)
}

// Application identifiers and terminal identity of the reference.
var (
	iasAID = []byte{0xA0, 0x00, 0x00, 0x00, 0x30, 0x80, 0x00, 0x00, 0x00, 0x09, 0x81, 0x60, 0x01}
	// CIEAID selects the CIE DF holding the citizen certificate and the public keys.
	CIEAID = []byte{0xA0, 0x00, 0x00, 0x00, 0x00, 0x39}
	// TerminalSerial is SN.IFD; the certificate holder reference is four zero bytes followed by it.
	TerminalSerial = []byte{0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}
	// cvOID is the reference's CV certificate algorithm OID with SHA-256 (last byte 04).
	cvOID = []byte{0x2A, 0x81, 0x22, 0xF4, 0x2A, 0x02, 0x04, 0x01, 0x04}
)

// IASAID is the IAS application of Gemalto and STM cards.
func IASAID() []byte { return append([]byte{}, iasAID...) }

// CVOID is the algorithm identifier carried in the terminal CV certificate.
func CVOID() []byte { return append([]byte{}, cvOID...) }

// cvCPI is the certificate profile identifier of the terminal CV certificate.
const cvCPI = 0x8A

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
