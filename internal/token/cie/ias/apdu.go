package ias

import (
	"errors"
	"fmt"
)

// Transport sends one command APDU to the card and returns the response APDU, data followed by SW1 SW2.
type Transport interface {
	Transmit(cmd []byte) ([]byte, error)
}

// ErrCardRemoved is wrapped by transports when the card left the reader or was reset by someone else, so the
// session's secure channel is gone.
var ErrCardRemoved = errors.New("card removed")

// Status words used by the protocol.
const (
	SWOK             = 0x9000
	SWEndOfFile      = 0x6282 // fewer bytes than requested: end of file reached
	SWWrongOffset    = 0x6B00 // offset beyond the end of the file
	SWPinLocked      = 0x6983 // authentication method blocked
	SWWrongPinNoInfo = 0x6300 // verification failed, no counter given
	SWWrongLength    = 0x6700
)

// StatusError is a status word other than the expected one.
type StatusError struct {
	Op string
	SW uint16
}

func (e *StatusError) Error() string { return fmt.Sprintf("%s: card status %04X", e.Op, e.SW) }

// ProtocolError is a malformed or unauthenticated card response: the session cannot be trusted any longer.
type ProtocolError struct {
	Op  string
	Err error
}

func (e *ProtocolError) Error() string { return fmt.Sprintf("%s: %v", e.Op, e.Err) }
func (e *ProtocolError) Unwrap() error { return e.Err }

func protoErr(op string, format string, args ...any) error {
	return &ProtocolError{Op: op, Err: fmt.Errorf(format, args...)}
}

// command is one logical command before chaining and secure messaging.
type command struct {
	cla, ins, p1, p2 byte
	data             []byte
	// le is the expected length; nil when the command has none. 0 means 256 bytes.
	le *byte
}

func le(n byte) *byte { return &n }

// maxPlainChunk is the largest unprotected data field the reference sends in one command; longer data is chained.
const maxPlainChunk = 255

// encodeShort encodes a short APDU: header, then Lc and data when present, then Le when present.
func encodeShort(cla, ins, p1, p2 byte, data []byte, le *byte) []byte {
	out := []byte{cla, ins, p1, p2}
	if len(data) > 0 {
		out = append(out, byte(len(data)))
		out = append(out, data...)
	}
	if le != nil {
		out = append(out, *le)
	}
	return out
}

// transmit sends one APDU and splits off the status word.
func (c *Card) transmit(op string, apdu []byte) ([]byte, uint16, error) {
	resp, err := c.t.Transmit(apdu)
	if err != nil {
		return nil, 0, err
	}
	if len(resp) < 2 {
		return nil, 0, protoErr(op, "response of %d bytes", len(resp))
	}
	n := len(resp) - 2
	return resp[:n], uint16(resp[n])<<8 | uint16(resp[n+1]), nil
}

// getResponse collects the rest of a response announced with 61xx through GET RESPONSE.
func (c *Card) getResponse(op string, data []byte, sw uint16) ([]byte, uint16, error) {
	for i := 0; sw>>8 == 0x61; i++ {
		if i > 64 {
			return nil, 0, protoErr(op, "too many GET RESPONSE rounds")
		}
		more, next, err := c.transmit(op, []byte{0x00, 0xC0, 0x00, 0x00, byte(sw)})
		if err != nil {
			return nil, 0, err
		}
		data = append(data, more...)
		sw = next
	}
	return data, sw, nil
}

// sendPlain sends a command without secure messaging, chaining data longer than 255 bytes like the reference
// (CLA bit 0x10 on all but the last command) and collecting 61xx continuations. A 6Cxx answer is retried once with
// the length the card asked for.
func (c *Card) sendPlain(op string, cmd command) ([]byte, uint16, error) {
	data := cmd.data
	for len(data) > maxPlainChunk {
		_, sw, err := c.transmit(op, encodeShort(cmd.cla|0x10, cmd.ins, cmd.p1, cmd.p2, data[:maxPlainChunk], cmd.le))
		if err != nil {
			return nil, 0, err
		}
		if sw != SWOK {
			return nil, sw, &StatusError{Op: op + " (chained)", SW: sw}
		}
		data = data[maxPlainChunk:]
	}
	apdu := encodeShort(cmd.cla, cmd.ins, cmd.p1, cmd.p2, data, cmd.le)
	resp, sw, err := c.transmit(op, apdu)
	if err != nil {
		return nil, 0, err
	}
	if sw>>8 == 0x6C {
		resp, sw, err = c.transmit(op, encodeShort(cmd.cla, cmd.ins, cmd.p1, cmd.p2, data, le(byte(sw))))
		if err != nil {
			return nil, 0, err
		}
	}
	return c.getResponse(op, resp, sw)
}
