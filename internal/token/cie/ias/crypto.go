package ias

import (
	"crypto/cipher"
	"crypto/des"
	"crypto/subtle"
	"errors"
	"math/big"
)

// The IAS secure channel uses two-key 3DES (K1, K2, K1) in CBC mode with a zero IV for every APDU, and the ISO/IEC
// 9797-1 algorithm 3 "retail" MAC: single DES-CBC under K1, then 3DES on the last block. Both pad with ISO/IEC 9797-1
// method 2. This is the reference's CDES3 and CMAC, not AES and not AES-CMAC.

// Pad appends 0x80 and zeros up to the next multiple of 8 bytes, always adding at least one byte.
func Pad(data []byte) []byte {
	out := make([]byte, len(data)+8-len(data)%8)
	copy(out, data)
	out[len(data)] = 0x80
	return out
}

var errPadding = errors.New("bad ISO 9797 padding")

// Unpad removes the padding added by Pad.
func Unpad(data []byte) ([]byte, error) {
	for i := len(data) - 1; i >= 0; i-- {
		switch data[i] {
		case 0:
			continue
		case 0x80:
			return data[:i], nil
		}
		return nil, errPadding
	}
	return nil, errPadding
}

func tripleDES(key []byte) (cipher.Block, error) {
	if len(key) != 16 {
		return nil, errors.New("3DES key must be 16 bytes")
	}
	k := make([]byte, 24)
	copy(k, key)
	copy(k[16:], key[:8])
	return des.NewTripleDESCipher(k)
}

// Encrypt3DES encrypts block-aligned data with 3DES-CBC and a zero IV.
func Encrypt3DES(key, data []byte) ([]byte, error) {
	if len(data)%8 != 0 {
		return nil, errors.New("3DES input not block aligned")
	}
	b, err := tripleDES(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(data))
	cipher.NewCBCEncrypter(b, make([]byte, 8)).CryptBlocks(out, data)
	return out, nil
}

// Decrypt3DES decrypts block-aligned data with 3DES-CBC and a zero IV.
func Decrypt3DES(key, data []byte) ([]byte, error) {
	if len(data) == 0 || len(data)%8 != 0 {
		return nil, errors.New("3DES input not block aligned")
	}
	b, err := tripleDES(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(data))
	cipher.NewCBCDecrypter(b, make([]byte, 8)).CryptBlocks(out, data)
	return out, nil
}

// RetailMAC computes the 8-byte ISO/IEC 9797-1 algorithm 3 MAC of already padded data under a 16-byte key.
func RetailMAC(key, padded []byte) ([]byte, error) {
	if len(padded) == 0 || len(padded)%8 != 0 {
		return nil, errors.New("MAC input not block aligned")
	}
	if len(key) != 16 {
		return nil, errors.New("MAC key must be 16 bytes")
	}
	k1, err := des.NewCipher(key[:8])
	if err != nil {
		return nil, err
	}
	k2, err := des.NewCipher(key[8:16])
	if err != nil {
		return nil, err
	}
	h := make([]byte, 8)
	for i := 0; i < len(padded); i += 8 {
		subtle.XORBytes(h, h, padded[i:i+8])
		k1.Encrypt(h, h)
	}
	k2.Decrypt(h, h)
	k1.Encrypt(h, h)
	return h, nil
}

// incrementSSC adds one to a big-endian send sequence counter in place.
func incrementSSC(ssc []byte) {
	for i := len(ssc) - 1; i >= 0; i-- {
		ssc[i]++
		if ssc[i] != 0 {
			return
		}
	}
}

// RawRSA computes data^exp mod n and returns it left-padded to the size of n: the reference's RSA_PURE, used with
// public and private exponents alike (signature recovery, CV certificate and challenge signatures, DH).
func RawRSA(n, exp *big.Int, data []byte) []byte {
	m := new(big.Int).SetBytes(data)
	return new(big.Int).Exp(m, exp, n).FillBytes(make([]byte, (n.BitLen()+7)/8))
}
