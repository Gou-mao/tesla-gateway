package mapping

import (
	"errors"
	"net/netip"
)

// Engine is the single entry point for address translation. It delegates to a
// pluggable MappingStrategy.
type Engine struct {
	strategy MappingStrategy
}

// NewEngine wraps a mapping strategy. The strategy should be validated with
// Validate before the engine is used.
func NewEngine(strategy MappingStrategy) *Engine {
	return &Engine{strategy: strategy}
}

// Validate validates the underlying mapping strategy.
func (e *Engine) Validate() error {
	if e == nil || e.strategy == nil {
		return errors.New("mapping: engine has no strategy")
	}
	return e.strategy.Validate()
}

// Translate maps a real address to a mapped address.
func (e *Engine) Translate(a netip.Addr) (netip.Addr, bool) {
	if e == nil || e.strategy == nil {
		return netip.Addr{}, false
	}
	return e.strategy.Translate(a)
}

// Reverse maps a mapped address back to a real address.
func (e *Engine) Reverse(a netip.Addr) (netip.Addr, bool) {
	if e == nil || e.strategy == nil {
		return netip.Addr{}, false
	}
	return e.strategy.Reverse(a)
}

// IsMapped reports whether a belongs to the mapped address space.
func (e *Engine) IsMapped(a netip.Addr) bool {
	if e == nil || e.strategy == nil {
		return false
	}
	return e.strategy.IsMapped(a)
}

// MappedPrefixes returns the mapped prefixes advertised by the strategy, or
// nil if the strategy does not expose them.
func (e *Engine) MappedPrefixes() []netip.Prefix {
	if e == nil || e.strategy == nil {
		return nil
	}
	lister, ok := e.strategy.(PrefixLister)
	if !ok {
		return nil
	}
	return append([]netip.Prefix(nil), lister.MappedPrefixes()...)
}
