package cie

import (
	"errors"
	"fmt"

	"github.com/ebfe/scard"

	"github.com/PoliNetworkOrg/sign-agent/internal/token/cie/ias"
)

// pcscConnector reaches the readers through PC/SC: winscard on Windows, the PCSC framework on macOS, pcsc-lite on
// Linux.
type pcscConnector struct{}

func establish() (*scard.Context, error) {
	ctx, err := scard.EstablishContext()
	if err != nil {
		if errors.Is(err, scard.ErrNoService) || errors.Is(err, scard.ErrServiceStopped) || errors.Is(err, scard.ErrNoReadersAvailable) {
			return nil, fmt.Errorf("%w: %v", ErrNoService, err)
		}
		return nil, err
	}
	return ctx, nil
}

func (pcscConnector) Readers() ([]Reader, error) {
	ctx, err := establish()
	if err != nil {
		return nil, err
	}
	defer ctx.Release()
	names, err := ctx.ListReaders()
	if errors.Is(err, scard.ErrNoReadersAvailable) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	states := make([]scard.ReaderState, len(names))
	for i, n := range names {
		states[i] = scard.ReaderState{Reader: n, CurrentState: scard.StateUnaware}
	}
	if err := ctx.GetStatusChange(states, 0); err != nil && !errors.Is(err, scard.ErrTimeout) {
		return nil, err
	}
	out := make([]Reader, len(states))
	for i, s := range states {
		out[i].Name = s.Reader
		if s.EventState&scard.StatePresent != 0 && s.EventState&scard.StateMute == 0 && len(s.Atr) > 0 {
			out[i].ATR = append([]byte{}, s.Atr...)
		}
	}
	return out, nil
}

func (pcscConnector) Connect(reader string) (Conn, error) {
	ctx, err := establish()
	if err != nil {
		return nil, err
	}
	card, err := ctx.Connect(reader, scard.ShareShared, scard.ProtocolAny)
	if err != nil {
		ctx.Release()
		return nil, removed(err)
	}
	// Start from a fresh card state, as the reference does before logging in.
	if err := card.Reconnect(scard.ShareShared, scard.ProtocolAny, scard.ResetCard); err != nil {
		_ = card.Disconnect(scard.LeaveCard)
		ctx.Release()
		return nil, removed(err)
	}
	if err := card.BeginTransaction(); err != nil {
		_ = card.Disconnect(scard.LeaveCard)
		ctx.Release()
		return nil, removed(err)
	}
	return &pcscConn{ctx: ctx, card: card}, nil
}

func (pcscConnector) Probe(reader string, apdu []byte) ([]byte, error) {
	ctx, err := establish()
	if err != nil {
		return nil, err
	}
	defer ctx.Release()
	card, err := ctx.Connect(reader, scard.ShareShared, scard.ProtocolAny)
	if err != nil {
		return nil, err
	}
	defer card.Disconnect(scard.LeaveCard)
	return card.Transmit(apdu)
}

type pcscConn struct {
	ctx  *scard.Context
	card *scard.Card
}

func (c *pcscConn) Transmit(cmd []byte) ([]byte, error) {
	resp, err := c.card.Transmit(cmd)
	if err != nil {
		return nil, removed(err)
	}
	return resp, nil
}

func (c *pcscConn) Close() error {
	_ = c.card.EndTransaction(scard.LeaveCard)
	err := c.card.Disconnect(scard.ResetCard)
	c.ctx.Release()
	return err
}

// removed marks the PC/SC errors that mean the session's card state is gone.
func removed(err error) error {
	switch {
	case errors.Is(err, scard.ErrRemovedCard), errors.Is(err, scard.ErrResetCard), errors.Is(err, scard.ErrUnpoweredCard),
		errors.Is(err, scard.ErrNoSmartcard), errors.Is(err, scard.ErrUnresponsiveCard):
		return fmt.Errorf("%w: %v", ias.ErrCardRemoved, err)
	}
	return err
}
