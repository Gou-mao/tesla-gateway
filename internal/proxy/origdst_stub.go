//go:build !linux

package proxy

import (
	"errors"
	"net"
	"net/netip"
)

// OriginalDst is unavailable outside Linux. It exists so the rest of the proxy
// package builds and can be tested with an injected original-destination
// function.
func OriginalDst(c *net.TCPConn) (netip.AddrPort, error) {
	return netip.AddrPort{}, errors.New("proxy: SO_ORIGINAL_DST is not supported on this platform")
}
