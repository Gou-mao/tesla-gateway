package proxy

import (
	"context"
	"errors"
)

// UDPProxy is a placeholder for future QUIC/HTTP3/DoQ support. It implements
// Proxy so the service lifecycle is already in place.
type UDPProxy struct {
	// Listen is retained for future use.
	Listen string
}

var _ Proxy = (*UDPProxy)(nil)

// NewUDPProxy creates a UDP proxy stub.
func NewUDPProxy(listen string) *UDPProxy {
	return &UDPProxy{Listen: listen}
}

// Start always reports that UDP proxying is not implemented yet.
func (p *UDPProxy) Start(ctx context.Context) error {
	if p == nil {
		return errors.New("udp proxy not implemented yet")
	}
	return errors.New("udp proxy not implemented yet")
}

// Stop implements Proxy.
func (p *UDPProxy) Stop() error {
	return nil
}

// Name implements Proxy.
func (p *UDPProxy) Name() string {
	return "udp"
}
