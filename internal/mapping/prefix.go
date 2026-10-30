package mapping

import (
	"errors"
	"fmt"
	"net/netip"
)

// localClientPrefix is reserved for Tesla clients on the local network. Mapped
// (to) prefixes must stay disjoint from it.
var localClientPrefix = netip.MustParsePrefix("100.64.0.0/24")

// PrefixMapping describes one prefix-replacement rule: every address covered
// by From is advertised as the corresponding address under To. Both prefixes
// must have the same bit length and address family.
type PrefixMapping struct {
	From netip.Prefix
	To   netip.Prefix
}

type prefixRule struct {
	from netip.Prefix
	to   netip.Prefix
}

// PrefixMappingStrategy maps real addresses to a synthetic address range by
// replacing the matched From prefix with the corresponding To prefix while
// preserving all host bits. It implements MappingStrategy.
type PrefixMappingStrategy struct {
	rules []prefixRule
	real  []netip.Prefix
}

var (
	_ MappingStrategy = (*PrefixMappingStrategy)(nil)
	_ PrefixLister    = (*PrefixMappingStrategy)(nil)
)

// PrefixOption configures a PrefixMappingStrategy.
type PrefixOption func(*PrefixMappingStrategy)

// WithRealPrefixes declares real, in-use network prefixes. Validate rejects
// mapped prefixes that overlap any of them. The local client prefix
// 100.64.0.0/24 is always checked separately.
func WithRealPrefixes(prefixes ...netip.Prefix) PrefixOption {
	copied := make([]netip.Prefix, 0, len(prefixes))
	for _, p := range prefixes {
		copied = append(copied, p.Masked())
	}
	return func(s *PrefixMappingStrategy) {
		s.real = append(s.real, copied...)
	}
}

// NewPrefixMappingStrategy compiles prefix mappings. Invalid prefixes are kept
// so that Validate can report them; masking is applied to valid prefixes.
// Call Validate before using the strategy.
func NewPrefixMappingStrategy(mappings []PrefixMapping, opts ...PrefixOption) *PrefixMappingStrategy {
	s := &PrefixMappingStrategy{
		rules: make([]prefixRule, 0, len(mappings)),
	}
	for _, m := range mappings {
		s.rules = append(s.rules, prefixRule{
			from: m.From.Masked(),
			to:   m.To.Masked(),
		})
	}
	for _, opt := range opts {
		if opt != nil {
			opt(s)
		}
	}
	return s
}

// Translate maps a real address to its mapped address using the longest
// matching From prefix.
func (s *PrefixMappingStrategy) Translate(a netip.Addr) (netip.Addr, bool) {
	if s == nil || !a.IsValid() {
		return netip.Addr{}, false
	}
	a = a.Unmap()
	rule, ok := s.match(a, true)
	if !ok {
		return netip.Addr{}, false
	}
	return replacePrefix(a, rule.from, rule.to)
}

// Reverse maps a mapped address back to its real address using the longest
// matching To prefix.
func (s *PrefixMappingStrategy) Reverse(a netip.Addr) (netip.Addr, bool) {
	if s == nil || !a.IsValid() {
		return netip.Addr{}, false
	}
	a = a.Unmap()
	rule, ok := s.match(a, false)
	if !ok {
		return netip.Addr{}, false
	}
	return replacePrefix(a, rule.to, rule.from)
}

// IsMapped reports whether a belongs to any configured mapped prefix.
func (s *PrefixMappingStrategy) IsMapped(a netip.Addr) bool {
	if s == nil || !a.IsValid() {
		return false
	}
	a = a.Unmap()
	for _, r := range s.rules {
		if r.to.IsValid() && r.to.Contains(a) {
			return true
		}
	}
	return false
}

// MappedPrefixes returns the configured mapped prefixes in configuration
// order. The returned slice is a copy.
func (s *PrefixMappingStrategy) MappedPrefixes() []netip.Prefix {
	if s == nil {
		return nil
	}
	out := make([]netip.Prefix, 0, len(s.rules))
	for _, r := range s.rules {
		if r.to.IsValid() {
			out = append(out, r.to)
		}
	}
	return out
}

// Validate implements MappingStrategy. It reports every configuration problem
// it finds: invalid prefixes, mismatched prefix lengths or address families,
// overlapping From or To prefixes, mapped prefixes overlapping the local
// client prefix, and mapped prefixes overlapping declared real in-use prefixes.
func (s *PrefixMappingStrategy) Validate() error {
	if s == nil {
		return errors.New("mapping: nil prefix mapping strategy")
	}

	var errs []error

	for i, r := range s.rules {
		fromValid := r.from.IsValid()
		toValid := r.to.IsValid()
		if !fromValid {
			errs = append(errs, fmt.Errorf("mappings[%d]: invalid from prefix", i))
		}
		if !toValid {
			errs = append(errs, fmt.Errorf("mappings[%d]: invalid to prefix", i))
		}
		if !fromValid || !toValid {
			continue
		}
		if r.from.Bits() != r.to.Bits() {
			errs = append(errs, fmt.Errorf(
				"mappings[%d]: from %s and to %s must have equal prefix lengths (%d != %d)",
				i, r.from, r.to, r.from.Bits(), r.to.Bits(),
			))
		}
		if r.from.Addr().Is4() != r.to.Addr().Is4() {
			errs = append(errs, fmt.Errorf(
				"mappings[%d]: from %s and to %s must use the same address family",
				i, r.from, r.to,
			))
		}
	}

	for i := 0; i < len(s.rules); i++ {
		for j := i + 1; j < len(s.rules); j++ {
			a, b := s.rules[i], s.rules[j]
			if a.from.IsValid() && b.from.IsValid() && a.from.Overlaps(b.from) {
				errs = append(errs, fmt.Errorf(
					"mappings[%d].from %s overlaps mappings[%d].from %s",
					i, a.from, j, b.from,
				))
			}
			if a.to.IsValid() && b.to.IsValid() && a.to.Overlaps(b.to) {
				errs = append(errs, fmt.Errorf(
					"mappings[%d].to %s overlaps mappings[%d].to %s",
					i, a.to, j, b.to,
				))
			}
		}
	}

	for i, r := range s.rules {
		if !r.to.IsValid() {
			continue
		}
		if r.to.Overlaps(localClientPrefix) {
			errs = append(errs, fmt.Errorf(
				"mappings[%d].to %s overlaps local client prefix %s",
				i, r.to, localClientPrefix,
			))
		}
		for j, real := range s.real {
			if !real.IsValid() {
				continue
			}
			if r.to.Overlaps(real) {
				errs = append(errs, fmt.Errorf(
					"mappings[%d].to %s overlaps real in-use prefix %s (real_prefixes[%d])",
					i, r.to, real, j,
				))
			}
		}
	}

	for i, real := range s.real {
		if !real.IsValid() {
			errs = append(errs, fmt.Errorf("real_prefixes[%d]: invalid prefix", i))
		}
	}

	return errors.Join(errs...)
}

// match returns the rule with the longest prefix that contains a. When
// forward is true, From prefixes are matched; otherwise To prefixes are
// matched. Overlaps are rejected by Validate, but longest-prefix matching is
// still applied defensively.
func (s *PrefixMappingStrategy) match(a netip.Addr, forward bool) (prefixRule, bool) {
	var best prefixRule
	bestBits := -1
	for _, r := range s.rules {
		if !r.from.IsValid() || !r.to.IsValid() {
			continue
		}
		p := r.to
		if forward {
			p = r.from
		}
		if !p.Contains(a) {
			continue
		}
		if p.Bits() > bestBits {
			best = r
			bestBits = p.Bits()
		}
	}
	if bestBits < 0 {
		return prefixRule{}, false
	}
	return best, true
}

// replacePrefix replaces from with to in a, preserving the host bits below the
// common prefix length.
func replacePrefix(a netip.Addr, from, to netip.Prefix) (netip.Addr, bool) {
	if !a.IsValid() || !from.IsValid() || !to.IsValid() {
		return netip.Addr{}, false
	}
	if from.Bits() != to.Bits() || from.Addr().Is4() != a.Is4() || to.Addr().Is4() != a.Is4() {
		return netip.Addr{}, false
	}

	addr := a.AsSlice()
	dst := to.Masked().Addr().AsSlice()
	hostBits := len(addr)*8 - from.Bits()
	fullBytes := hostBits / 8
	partialBits := hostBits % 8

	copy(dst[len(dst)-fullBytes:], addr[len(addr)-fullBytes:])
	if partialBits > 0 {
		i := len(dst) - fullBytes - 1
		mask := byte(1<<uint(partialBits)) - 1
		dst[i] = dst[i]&^mask | addr[i]&mask
	}

	if len(dst) == 4 {
		var v4 [4]byte
		copy(v4[:], dst)
		return netip.AddrFrom4(v4), true
	}
	var v6 [16]byte
	copy(v6[:], dst)
	return netip.AddrFrom16(v6), true
}
