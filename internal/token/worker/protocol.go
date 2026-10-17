// Package worker runs a token provider in a child process ("sign-agent worker"), so that a crashing middleware does
// not take the agent down, and so that a module built for another CPU architecture (the official macOS CIE middleware
// is x86_64 only) can be loaded by a child running under Rosetta.
//
// Parent and child speak over the child's stdin and stdout: each message is a 4-byte big-endian length followed by
// that many bytes of JSON. The parent sends one request and waits for its response; there is no pipelining.
package worker

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/PoliNetworkOrg/sign-agent/internal/token"
)

// maxFrame bounds a message: certificates and signatures are a few kilobytes.
const maxFrame = 1 << 20

// Operations.
const (
	opStatus = "status"
	opOpen   = "open"
	opSign   = "sign"
	opClose  = "close"
)

type request struct {
	Op string `json:"op"`
	// PIN is set only for opOpen.
	PIN string `json:"pin,omitempty"`
	// Digest is set only for opSign.
	Digest []byte `json:"digest,omitempty"`
}

type response struct {
	Error       *wireError    `json:"error,omitempty"`
	Status      *token.Status `json:"status,omitempty"`
	Certificate []byte        `json:"certificate,omitempty"`
	Chain       [][]byte      `json:"chain,omitempty"`
	Signature   []byte        `json:"signature,omitempty"`
}

type wireError struct {
	Code        token.Code `json:"code"`
	RetriesLeft int        `json:"retriesLeft"`
	Message     string     `json:"message"`
}

func toWire(err error) *wireError {
	w := &wireError{Code: token.CodeOf(err), RetriesLeft: -1, Message: err.Error()}
	var te *token.Error
	if errors.As(err, &te) {
		w.RetriesLeft = te.RetriesLeft
		if te.Err != nil {
			w.Message = te.Err.Error()
		}
	}
	return w
}

func (w *wireError) err() error {
	return &token.Error{Code: w.Code, RetriesLeft: w.RetriesLeft, Err: errors.New(w.Message)}
}

func writeFrame(w io.Writer, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(data) > maxFrame {
		return fmt.Errorf("message of %d bytes exceeds %d", len(data), maxFrame)
	}
	buf := make([]byte, 4+len(data))
	binary.BigEndian.PutUint32(buf, uint32(len(data)))
	copy(buf[4:], data)
	_, err = w.Write(buf)
	return err
}

func readFrame(r io.Reader, v any) error {
	var size [4]byte
	if _, err := io.ReadFull(r, size[:]); err != nil {
		return err
	}
	n := binary.BigEndian.Uint32(size[:])
	if n > maxFrame {
		return fmt.Errorf("message of %d bytes exceeds %d", n, maxFrame)
	}
	data := make([]byte, n)
	if _, err := io.ReadFull(r, data); err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}
