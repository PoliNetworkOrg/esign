package worker

import (
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/PoliNetworkOrg/sign-agent/internal/token"
)

// Options configures a provider that runs in a worker process.
type Options struct {
	// Name is the provider's name, as the child reports it.
	Name string
	// Command is the child's argv, e.g. {"arch", "-x86_64", exe, "worker", "--provider", "cie-mw", "--module", path}.
	Command []string
	// Env is the child's whole environment; nil inherits the agent's.
	Env []string
	// Note is appended to the status detail, e.g. "x86_64 worker".
	Note string
	// Stderr receives the child's diagnostics; os.Stderr when nil.
	Stderr io.Writer
	// Prepare, when set, runs before each start of the child, e.g. to create the directory its HOME names.
	Prepare func() error
}

// Provider is a token.Provider served by a child process. The child starts on first use and is restarted on the next
// call after it exits. A child that dies or is cancelled during an operation fails that operation with
// token.CodeDevice: the operation is never repeated, so a PIN reaches the card at most once.
type Provider struct {
	opts Options

	mu   sync.Mutex
	proc *process
}

type process struct {
	cmd  *exec.Cmd
	in   io.WriteCloser
	out  io.ReadCloser
	done chan struct{}
	err  error // set before done is closed
}

func (pr *process) exited() bool {
	select {
	case <-pr.done:
		return true
	default:
		return false
	}
}

func (pr *process) kill() {
	_ = pr.cmd.Process.Kill()
	<-pr.done
}

// New returns a provider; the child is not started until first use.
func New(opts Options) *Provider {
	if opts.Stderr == nil {
		opts.Stderr = os.Stderr
	}
	return &Provider{opts: opts}
}

func (p *Provider) Name() string { return p.opts.Name }

// start launches the child. Callers hold p.mu.
func (p *Provider) start() (*process, error) {
	if p.proc != nil && !p.proc.exited() {
		return p.proc, nil
	}
	if len(p.opts.Command) == 0 {
		return nil, fmt.Errorf("no worker command")
	}
	if p.opts.Prepare != nil {
		if err := p.opts.Prepare(); err != nil {
			return nil, err
		}
	}
	cmd := exec.Command(p.opts.Command[0], p.opts.Command[1:]...)
	cmd.Env = p.opts.Env
	cmd.Stderr = p.opts.Stderr
	hideWindow(cmd)
	in, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	pr := &process{cmd: cmd, in: in, out: out, done: make(chan struct{})}
	go func() {
		pr.err = cmd.Wait()
		close(pr.done)
	}()
	p.proc = pr
	return pr, nil
}

// roundTrip sends req to pr and waits for its response. Any failure kills the child. Callers hold p.mu.
func (p *Provider) roundTrip(ctx context.Context, pr *process, req request) (*response, error) {
	if err := writeFrame(pr.in, req); err != nil {
		pr.kill()
		return nil, token.Errorf(token.CodeDevice, "worker: %v", exitReason(pr, err))
	}
	type result struct {
		res response
		err error
	}
	ch := make(chan result, 1)
	go func() {
		var r result
		r.err = readFrame(pr.out, &r.res)
		ch <- r
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			pr.kill()
			return nil, token.Errorf(token.CodeDevice, "worker: %v", exitReason(pr, r.err))
		}
		return &r.res, nil
	case <-ctx.Done():
		pr.kill()
		return nil, token.Errorf(token.CodeDevice, "worker stopped: %v", ctx.Err())
	}
}

func exitReason(pr *process, err error) error {
	select {
	case <-pr.done:
		if pr.err != nil {
			return fmt.Errorf("exited (%v)", pr.err)
		}
		return fmt.Errorf("exited")
	case <-time.After(time.Second):
		return err
	}
}

func (p *Provider) Status(ctx context.Context) token.Status {
	p.mu.Lock()
	defer p.mu.Unlock()
	st := token.Status{Provider: p.opts.Name}
	pr, err := p.start()
	if err != nil {
		st.Detail = fmt.Sprintf("cannot start the worker: %v", err)
		return st
	}
	res, err := p.roundTrip(ctx, pr, request{Op: opStatus})
	switch {
	case err != nil:
		st.Detail = err.Error()
		return st
	case res.Error != nil:
		st.Detail = res.Error.Message
		return st
	case res.Status == nil:
		st.Detail = "worker: empty status"
		return st
	}
	st = *res.Status
	st.Provider = p.opts.Name
	if p.opts.Note != "" {
		st.Detail += " (" + p.opts.Note + ")"
	}
	return st
}

func (p *Provider) Open(ctx context.Context, pin string) (token.Session, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	pr, err := p.start()
	if err != nil {
		return nil, token.Errorf(token.CodeMiddlewareMissing, "cannot start the worker: %v", err)
	}
	res, err := p.roundTrip(ctx, pr, request{Op: opOpen, PIN: pin})
	if err != nil {
		return nil, err
	}
	if res.Error != nil {
		return nil, res.Error.err()
	}
	s := &session{p: p, proc: pr}
	fail := func(err error) (token.Session, error) {
		_, _ = p.roundTrip(ctx, pr, request{Op: opClose})
		return nil, err
	}
	if s.cert, err = x509.ParseCertificate(res.Certificate); err != nil {
		return fail(token.Errorf(token.CodeDevice, "worker certificate: %v", err))
	}
	for _, der := range res.Chain {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return fail(token.Errorf(token.CodeDevice, "worker chain: %v", err))
		}
		s.chain = append(s.chain, c)
	}
	return s, nil
}

// Close stops the child.
func (p *Provider) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.proc == nil {
		return
	}
	_ = p.proc.in.Close()
	select {
	case <-p.proc.done:
	case <-time.After(3 * time.Second):
		p.proc.kill()
	}
	p.proc = nil
}

type session struct {
	p      *Provider
	proc   *process
	cert   *x509.Certificate
	chain  []*x509.Certificate
	closed bool
}

func (s *session) Certificate() *x509.Certificate { return s.cert }
func (s *session) Chain() []*x509.Certificate     { return s.chain }

func (s *session) SignDigest(ctx context.Context, digest []byte) ([]byte, error) {
	s.p.mu.Lock()
	defer s.p.mu.Unlock()
	if s.closed || s.proc.exited() || s.p.proc != s.proc {
		return nil, token.Errorf(token.CodeDevice, "the worker holding the card session has stopped")
	}
	res, err := s.p.roundTrip(ctx, s.proc, request{Op: opSign, Digest: digest})
	if err != nil {
		return nil, err
	}
	if res.Error != nil {
		return nil, res.Error.err()
	}
	return res.Signature, nil
}

func (s *session) Close() error {
	s.p.mu.Lock()
	defer s.p.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if s.proc.exited() || s.p.proc != s.proc {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	res, err := s.p.roundTrip(ctx, s.proc, request{Op: opClose})
	if err != nil {
		return err
	}
	if res.Error != nil {
		return res.Error.err()
	}
	return nil
}
