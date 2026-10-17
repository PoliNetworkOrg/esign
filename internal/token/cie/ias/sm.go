package ias

import (
	"crypto/subtle"
	"errors"
)

// smState is an established secure channel: session keys and the send sequence counter.
type smState struct {
	kenc, kmac []byte
	ssc        []byte
}

// maxSMChunk is the reference's limit for protected command data (0xE7 bytes); longer data is chained, each part
// protected on its own.
const maxSMChunk = 0xE7

// Wrap protects one command as the reference's IAS::SM does. The SSC is incremented first. The data field is
// encrypted into DO 87 (even INS, with the 01 padding indicator) or DO 85 (odd INS); DO 97 carries Le, and is also
// sent (as 00) by a command with neither data nor Le; DO 8E is the MAC over the padded SSC||header followed by the
// other objects. The outer APDU has Le=00.
func (s *smState) wrap(cmd command) ([]byte, error) {
	incrementSSC(s.ssc)
	head := []byte{cmd.cla | 0x0C, cmd.ins, cmd.p1, cmd.p2}
	mac := Pad(append(append([]byte{}, s.ssc...), head...))
	var field []byte
	if len(cmd.data) > 0 {
		enc, err := Encrypt3DES(s.kenc, Pad(cmd.data))
		if err != nil {
			return nil, err
		}
		if cmd.ins&1 == 0 {
			field = append(field, EncodeTLV(0x87, append([]byte{0x01}, enc...))...)
		} else {
			field = append(field, EncodeTLV(0x85, enc)...)
		}
	}
	if cmd.le != nil || len(cmd.data) == 0 {
		var l byte
		if cmd.le != nil {
			l = *cmd.le
		}
		field = append(field, EncodeTLV(0x97, []byte{l})...)
	}
	tag, err := RetailMAC(s.kmac, Pad(append(mac, field...)))
	if err != nil {
		return nil, err
	}
	field = append(field, EncodeTLV(0x8E, tag)...)
	out := append([]byte{}, head...)
	if len(field) < 0x100 {
		out = append(out, byte(len(field)))
		out = append(out, field...)
		return append(out, 0x00), nil
	}
	out = append(out, 0x00, byte(len(field)>>8), byte(len(field)))
	out = append(out, field...)
	return append(out, 0x00, 0x00), nil
}

var errMAC = errors.New("response MAC mismatch")

// unwrap verifies and decrypts a protected response as the reference's IAS::respSM does: the SSC is incremented,
// the MAC covers SSC followed by every DO 85/87/99 in the order received, and the status word comes from DO 99.
func (s *smState) unwrap(body []byte) ([]byte, uint16, error) {
	incrementSSC(s.ssc)
	macInput := append([]byte{}, s.ssc...)
	var (
		mac, enc []byte
		sw       uint16
		haveSW   bool
	)
	rest := body
	for len(rest) > 0 {
		obj, next, err := ParseTLV(rest)
		if err != nil {
			return nil, 0, err
		}
		rest = next
		switch obj.Tag {
		case 0x99:
			if len(obj.Value) != 2 {
				return nil, 0, errors.New("DO 99 is not 2 bytes")
			}
			sw = uint16(obj.Value[0])<<8 | uint16(obj.Value[1])
			haveSW = true
			macInput = append(macInput, obj.Raw...)
		case 0x8E:
			if len(obj.Value) != 8 {
				return nil, 0, errors.New("DO 8E is not 8 bytes")
			}
			mac = obj.Value
		case 0x87:
			if len(obj.Value) < 1 || obj.Value[0] != 0x01 {
				return nil, 0, errors.New("DO 87 without padding indicator 01")
			}
			enc = obj.Value[1:]
			macInput = append(macInput, obj.Raw...)
		case 0x85:
			enc = obj.Value
			macInput = append(macInput, obj.Raw...)
		default:
			return nil, 0, errors.New("unexpected object in protected response")
		}
	}
	if mac == nil {
		return nil, 0, errors.New("protected response without MAC")
	}
	want, err := RetailMAC(s.kmac, Pad(macInput))
	if err != nil {
		return nil, 0, err
	}
	if subtle.ConstantTimeCompare(want, mac) != 1 {
		return nil, 0, errMAC
	}
	if !haveSW {
		return nil, 0, errors.New("protected response without status (DO 99)")
	}
	if len(enc) == 0 {
		return nil, sw, nil
	}
	plain, err := Decrypt3DES(s.kenc, enc)
	if err != nil {
		return nil, 0, err
	}
	data, err := Unpad(plain)
	if err != nil {
		return nil, 0, err
	}
	return data, sw, nil
}

// sendSM sends a command through the secure channel, chaining data longer than maxSMChunk like the reference (Le
// only on the last part). Responses longer than one short APDU arrive through GET RESPONSE before being verified.
// A response without data is an unprotected status: the card did not accept the protected command (for instance
// 6987/6988 for an SM error) and the counter is not advanced for it.
func (c *Card) sendSM(op string, cmd command) ([]byte, uint16, error) {
	if c.sm == nil {
		return nil, 0, protoErr(op, "no secure channel")
	}
	data := cmd.data
	for len(data) > maxSMChunk {
		part := command{cla: cmd.cla | 0x10, ins: cmd.ins, p1: cmd.p1, p2: cmd.p2, data: data[:maxSMChunk]}
		_, sw, err := c.exchangeSM(op+" (chained)", part)
		if err != nil {
			return nil, 0, err
		}
		if sw != SWOK {
			return nil, sw, &StatusError{Op: op + " (chained)", SW: sw}
		}
		data = data[maxSMChunk:]
	}
	last := command{cla: cmd.cla, ins: cmd.ins, p1: cmd.p1, p2: cmd.p2, data: data, le: cmd.le}
	resp, sw, err := c.exchangeSM(op, last)
	if err == nil && sw>>8 == 0x6C {
		last.le = le(byte(sw))
		resp, sw, err = c.exchangeSM(op, last)
	}
	return resp, sw, err
}

func (c *Card) exchangeSM(op string, cmd command) ([]byte, uint16, error) {
	apdu, err := c.sm.wrap(cmd)
	if err != nil {
		return nil, 0, err
	}
	body, sw, err := c.transmit(op, apdu)
	if err != nil {
		return nil, 0, err
	}
	body, sw, err = c.getResponse(op, body, sw)
	if err != nil {
		return nil, 0, err
	}
	if len(body) == 0 {
		if sw == SWOK {
			return nil, 0, protoErr(op, "unprotected success to a protected command")
		}
		return nil, sw, nil
	}
	data, inner, err := c.sm.unwrap(body)
	if err != nil {
		return nil, 0, &ProtocolError{Op: op, Err: err}
	}
	return data, inner, nil
}
