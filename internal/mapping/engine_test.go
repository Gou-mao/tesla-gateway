package mapping_test

import (
	"net/netip"
	"slices"
	"testing"

	"tesla-gateway/internal/mapping"
)

func TestEngineDelegatesToStrategy(t *testing.T) {
	s := mapping.NewPrefixMappingStrategy([]mapping.PrefixMapping{
		{
			From: mustPrefix(t, "192.168.1.0/24"),
			To:   mustPrefix(t, "100.64.1.0/24"),
		},
	})
	e := mapping.NewEngine(s)
	if err := e.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil", err)
	}

	got, ok := e.Translate(mustAddr(t, "192.168.1.251"))
	if !ok || got.String() != "100.64.1.251" {
		t.Errorf("Translate() = %s, %v; want 100.64.1.251, true", got, ok)
	}
	got, ok = e.Reverse(mustAddr(t, "100.64.1.251"))
	if !ok || got.String() != "192.168.1.251" {
		t.Errorf("Reverse() = %s, %v; want 192.168.1.251, true", got, ok)
	}
	if !e.IsMapped(mustAddr(t, "100.64.1.251")) {
		t.Error("IsMapped(100.64.1.251) = false, want true")
	}
	want := []netip.Prefix{mustPrefix(t, "100.64.1.0/24")}
	if gotPrefixes := e.MappedPrefixes(); !slices.Equal(gotPrefixes, want) {
		t.Errorf("MappedPrefixes() = %v, want %v", gotPrefixes, want)
	}
}

func TestNilEngine(t *testing.T) {
	var e *mapping.Engine
	if err := e.Validate(); err == nil {
		t.Error("Validate() = nil, want error")
	}
	if _, ok := e.Translate(mustAddr(t, "192.168.1.1")); ok {
		t.Error("Translate() ok = true, want false")
	}
	if _, ok := e.Reverse(mustAddr(t, "100.64.1.1")); ok {
		t.Error("Reverse() ok = true, want false")
	}
	if e.IsMapped(mustAddr(t, "100.64.1.1")) {
		t.Error("IsMapped() = true, want false")
	}
	if e.MappedPrefixes() != nil {
		t.Error("MappedPrefixes() != nil, want nil")
	}
}

func TestEngineWithoutPrefixLister(t *testing.T) {
	e := mapping.NewEngine(strategyWithoutPrefixes{})
	if e.Validate() != nil {
		t.Fatal("Validate() returned an error for a valid strategy")
	}
	if got := e.MappedPrefixes(); got != nil {
		t.Errorf("MappedPrefixes() = %v, want nil", got)
	}
}

type strategyWithoutPrefixes struct{}

func (strategyWithoutPrefixes) Translate(a netip.Addr) (netip.Addr, bool) { return a, true }
func (strategyWithoutPrefixes) Reverse(a netip.Addr) (netip.Addr, bool)   { return a, true }
func (strategyWithoutPrefixes) IsMapped(netip.Addr) bool                  { return false }
func (strategyWithoutPrefixes) Validate() error                           { return nil }
