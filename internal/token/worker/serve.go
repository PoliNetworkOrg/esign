package worker

import (
	"context"
	"errors"
	"io"
	"os"

	"github.com/PoliNetworkOrg/esign/internal/token"
)

// Serve answers the parent's requests for provider p until in ends. It runs in the child process. At most one session
// is open at a time; it is closed when the parent closes it or goes away.
func Serve(in io.Reader, out io.Writer, p token.Provider) error {
	ctx := context.Background()
	var session token.Session
	defer func() {
		if session != nil {
			_ = session.Close()
		}
	}()
	for {
		var req request
		if err := readFrame(in, &req); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		var res response
		switch req.Op {
		case opStatus:
			if session != nil {
				res.Error = toWire(token.Errorf(token.CodeBusy, "a card session is open"))
				break
			}
			st := p.Status(ctx)
			res.Status = &st
		case opOpen:
			if session != nil {
				res.Error = toWire(token.Errorf(token.CodeBusy, "a card session is already open"))
				break
			}
			s, err := p.Open(ctx, req.PIN)
			req.PIN = ""
			if err != nil {
				res.Error = toWire(err)
				break
			}
			session = s
			res.Certificate = s.Certificate().Raw
			for _, c := range s.Chain() {
				res.Chain = append(res.Chain, c.Raw)
			}
		case opSign:
			if session == nil {
				res.Error = toWire(token.Errorf(token.CodeDevice, "no card session is open"))
				break
			}
			sig, err := session.SignDigest(ctx, req.Digest)
			if err != nil {
				res.Error = toWire(err)
				break
			}
			res.Signature = sig
		case opClose:
			if session != nil {
				err := session.Close()
				session = nil
				if err != nil {
					res.Error = toWire(err)
				}
			}
		default:
			res.Error = toWire(token.Errorf(token.CodeDevice, "unknown operation %q", req.Op))
		}
		if err := writeFrame(out, res); err != nil {
			return err
		}
	}
}

// Main is the child's entry point: it serves p on the process's stdin and stdout. PKCS#11 modules write diagnostics
// to stdout (the official CIE middleware prints with printf), which would corrupt the protocol, so the protocol keeps
// the original stdout and file descriptor 1 is pointed at stderr before p loads anything.
func Main(newProvider func() (token.Provider, error)) error {
	out, err := isolateStdout()
	if err != nil {
		return err
	}
	p, err := newProvider()
	if err != nil {
		return err
	}
	return Serve(os.Stdin, out, p)
}
