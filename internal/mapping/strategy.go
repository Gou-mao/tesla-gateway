// Package mapping is the single source of truth for translating addresses
// between the real network and the addresses advertised to Tesla clients.
//
// DNS, proxy, and future transports must all use Engine rather than
// implementing address translation themselves.
package mapping

import "net/netip"

// MappingStrategy translates addresses between the real network and the
// mapped address space.
//
// Translate maps a real address to a mapped address. Reverse maps a mapped
// address back to a real address. IsMapped reports whether an address belongs
// to the mapped address space. Validate checks the strategy's configuration
// and must be called at startup; an invalid strategy must fail fast.
type MappingStrategy interface {
	Translate(a netip.Addr) (netip.Addr, bool)
	Reverse(a netip.Addr) (netip.Addr, bool)
	IsMapped(a netip.Addr) bool
	Validate() error
}

// PrefixLister is implemented by strategies that can expose the mapped
// prefixes they advertise. Engine uses it to build firewall rules.
type PrefixLister interface {
	MappedPrefixes() []netip.Prefix
}
