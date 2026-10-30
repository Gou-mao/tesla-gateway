package mapping_test

import (
	"net/netip"
	"slices"
	"strings"
	"testing"

	"tesla-gateway/internal/mapping"
)

func mustPrefix(t *testing.T, s string) netip.Prefix {
	t.Helper()
	p, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatalf("parse prefix %q: %v", s, err)
	}
	return p
}

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("parse address %q: %v", s, err)
	}
	return a
}

func validMappings(t *testing.T) []mapping.PrefixMapping {
	t.Helper()
	return []mapping.PrefixMapping{
		{
			From: mustPrefix(t, "192.168.1.0/24"),
			To:   mustPrefix(t, "100.64.1.0/24"),
		},
		{
			From: mustPrefix(t, "10.243.0.0/16"),
			To:   mustPrefix(t, "100.66.0.0/16"),
		},
		{
			From: mustPrefix(t, "172.16.5.128/25"),
			To:   mustPrefix(t, "100.64.2.128/25"),
		},
		{
			From: mustPrefix(t, "172.32.0.0/12"),
			To:   mustPrefix(t, "100.80.0.0/12"),
		},
		{
			From: mustPrefix(t, "fd00:1::/64"),
			To:   mustPrefix(t, "fd00:2::/64"),
		},
	}
}

func TestPrefixMappingTranslateReverse(t *testing.T) {
	s := mapping.NewPrefixMappingStrategy(validMappings(t))
	if err := s.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil", err)
	}

	translateTests := []struct {
		in   string
		want string
		ok   bool
	}{
		{in: "192.168.1.251", want: "100.64.1.251", ok: true},
		{in: "192.168.1.1", want: "100.64.1.1", ok: true},
		{in: "10.243.7.9", want: "100.66.7.9", ok: true},
		// Non-byte-aligned prefix: preserve the lower 7 host bits.
		{in: "172.16.5.200", want: "100.64.2.200", ok: true},
		// Non-byte-aligned prefix: preserve the lower 20 host bits.
		{in: "172.36.5.9", want: "100.84.5.9", ok: true},
		{in: "fd00:1::abcd", want: "fd00:2::abcd", ok: true},
		{in: "192.168.2.1", ok: false},
		{in: "100.64.1.1", ok: false},
	}
	for _, tc := range translateTests {
		got, ok := s.Translate(mustAddr(t, tc.in))
		if ok != tc.ok {
			t.Errorf("Translate(%s) ok = %v, want %v", tc.in, ok, tc.ok)
			continue
		}
		if ok && got.String() != tc.want {
			t.Errorf("Translate(%s) = %s, want %s", tc.in, got, tc.want)
		}
	}

	reverseTests := []struct {
		in   string
		want string
		ok   bool
	}{
		{in: "100.64.1.251", want: "192.168.1.251", ok: true},
		{in: "100.66.7.9", want: "10.243.7.9", ok: true},
		{in: "100.64.2.200", want: "172.16.5.200", ok: true},
		{in: "100.84.5.9", want: "172.36.5.9", ok: true},
		{in: "fd00:2::abcd", want: "fd00:1::abcd", ok: true},
		{in: "100.64.3.1", ok: false},
		{in: "192.168.1.251", ok: false},
	}
	for _, tc := range reverseTests {
		got, ok := s.Reverse(mustAddr(t, tc.in))
		if ok != tc.ok {
			t.Errorf("Reverse(%s) ok = %v, want %v", tc.in, ok, tc.ok)
			continue
		}
		if ok && got.String() != tc.want {
			t.Errorf("Reverse(%s) = %s, want %s", tc.in, got, tc.want)
		}
	}

	for _, addr := range []string{"100.64.1.251", "100.66.7.9", "100.64.2.200", "100.84.5.9", "fd00:2::abcd"} {
		if !s.IsMapped(mustAddr(t, addr)) {
			t.Errorf("IsMapped(%s) = false, want true", addr)
		}
	}
	for _, addr := range []string{"100.64.0.1", "192.168.1.251", "fd00:1::abcd"} {
		if s.IsMapped(mustAddr(t, addr)) {
			t.Errorf("IsMapped(%s) = true, want false", addr)
		}
	}
}

func TestPrefixMappingMappedPrefixes(t *testing.T) {
	s := mapping.NewPrefixMappingStrategy(validMappings(t))
	want := []netip.Prefix{
		mustPrefix(t, "100.64.1.0/24"),
		mustPrefix(t, "100.66.0.0/16"),
		mustPrefix(t, "100.64.2.128/25"),
		mustPrefix(t, "100.80.0.0/12"),
		mustPrefix(t, "fd00:2::/64"),
	}
	if got := s.MappedPrefixes(); !slices.Equal(got, want) {
		t.Errorf("MappedPrefixes() = %v, want %v", got, want)
	}
}

func TestPrefixMappingLongestPrefix(t *testing.T) {
	// Validate rejects overlapping From prefixes in production. The matching
	// algorithm still uses longest-prefix match defensively, so verify it with
	// an intentionally overlapping strategy.
	s := mapping.NewPrefixMappingStrategy([]mapping.PrefixMapping{
		{
			From: mustPrefix(t, "10.0.0.0/8"),
			To:   mustPrefix(t, "100.64.1.0/8"),
		},
		{
			From: mustPrefix(t, "10.1.2.0/24"),
			To:   mustPrefix(t, "100.64.2.0/24"),
		},
	})
	if err := s.Validate(); err == nil {
		t.Fatal("Validate() = nil for overlapping prefixes, want error")
	}

	got, ok := s.Translate(mustAddr(t, "10.1.2.3"))
	if !ok || got.String() != "100.64.2.3" {
		t.Errorf("Translate(10.1.2.3) = %s, %v; want 100.64.2.3, true", got, ok)
	}
	got, ok = s.Reverse(mustAddr(t, "100.64.2.3"))
	if !ok || got.String() != "10.1.2.3" {
		t.Errorf("Reverse(100.64.2.3) = %s, %v; want 10.1.2.3, true", got, ok)
	}
}

func TestPrefixMappingValidateErrors(t *testing.T) {
	tests := []struct {
		name     string
		mappings []mapping.PrefixMapping
		real     []netip.Prefix
		want     string
	}{
		{
			name: "unequal prefix lengths",
			mappings: []mapping.PrefixMapping{
				{
					From: mustPrefix(t, "192.168.1.0/24"),
					To:   mustPrefix(t, "100.64.1.0/25"),
				},
			},
			want: "equal prefix lengths",
		},
		{
			name: "from overlap",
			mappings: []mapping.PrefixMapping{
				{
					From: mustPrefix(t, "10.0.0.0/24"),
					To:   mustPrefix(t, "100.65.0.0/24"),
				},
				{
					From: mustPrefix(t, "10.0.0.0/24"),
					To:   mustPrefix(t, "100.66.0.0/24"),
				},
			},
			want: "overlaps mappings[1].from",
		},
		{
			name: "to overlap",
			mappings: []mapping.PrefixMapping{
				{
					From: mustPrefix(t, "10.0.0.0/24"),
					To:   mustPrefix(t, "100.65.0.0/24"),
				},
				{
					From: mustPrefix(t, "10.0.1.0/24"),
					To:   mustPrefix(t, "100.65.0.0/24"),
				},
			},
			want: "overlaps mappings[1].to",
		},
		{
			name: "to falls inside local client prefix",
			mappings: []mapping.PrefixMapping{
				{
					From: mustPrefix(t, "10.0.0.0/24"),
					To:   mustPrefix(t, "100.64.0.128/25"),
				},
			},
			want: "local client prefix",
		},
		{
			name: "to contains local client prefix",
			mappings: []mapping.PrefixMapping{
				{
					From: mustPrefix(t, "10.0.0.0/16"),
					To:   mustPrefix(t, "100.64.0.0/16"),
				},
			},
			want: "local client prefix",
		},
		{
			name: "to overlaps real in-use prefix",
			mappings: []mapping.PrefixMapping{
				{
					From: mustPrefix(t, "10.0.0.0/24"),
					To:   mustPrefix(t, "192.168.9.0/24"),
				},
			},
			real: []netip.Prefix{mustPrefix(t, "192.168.0.0/16")},
			want: "real in-use prefix",
		},
		{
			name: "address family mismatch",
			mappings: []mapping.PrefixMapping{
				{
					From: mustPrefix(t, "192.168.1.0/24"),
					To:   mustPrefix(t, "fd00::/24"),
				},
			},
			want: "address family",
		},
		{
			name: "invalid from prefix",
			mappings: []mapping.PrefixMapping{
				{To: mustPrefix(t, "100.65.0.0/24")},
			},
			want: "invalid from prefix",
		},
		{
			name: "invalid real prefix",
			mappings: []mapping.PrefixMapping{
				{
					From: mustPrefix(t, "10.0.0.0/24"),
					To:   mustPrefix(t, "100.65.0.0/24"),
				},
			},
			real: []netip.Prefix{{}},
			want: "invalid prefix",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := mapping.NewPrefixMappingStrategy(tc.mappings, mapping.WithRealPrefixes(tc.real...))
			err := s.Validate()
			if err == nil {
				t.Fatal("Validate() = nil, want error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Validate() = %q, want substring %q", err, tc.want)
			}
		})
	}
}
