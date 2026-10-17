// Package cie speaks to the CIE directly over PC/SC, without any middleware.
package cie

import (
	"context"

	"github.com/PoliNetworkOrg/sign-agent/internal/token"
)

// Provider is the direct CIE provider.
type Provider struct{}

// New returns the provider.
func New() *Provider { return &Provider{} }

func (p *Provider) Name() string { return "cie" }

func (p *Provider) Status(context.Context) token.Status {
	return token.Status{Provider: p.Name(), Detail: "direct CIE access is not available yet"}
}

func (p *Provider) Open(context.Context, string) (token.Session, error) {
	return nil, token.Errorf(token.CodeCardUnsupported, "direct CIE access is not available yet")
}
