package resolvers_test

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"

	mdns "github.com/miekg/dns"

	"tesla-gateway/internal/dns/resolvers"
)

func chainARecord(name, ip string) *mdns.A {
	return &mdns.A{
		Hdr: mdns.RR_Header{Name: name, Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 60},
		A:   net.ParseIP(ip).To4(),
	}
}

type fakeResolver struct {
	name    string
	records []mdns.RR
	hit     bool
	err     error
	calls   *int
}

func (f *fakeResolver) Name() string { return f.name }

func (f *fakeResolver) Lookup(ctx context.Context, q mdns.Question) ([]mdns.RR, bool, error) {
	if f.calls != nil {
		*f.calls++
	}
	return f.records, f.hit, f.err
}

func TestChainStopsAtFirstHit(t *testing.T) {
	var firstCalls, secondCalls, thirdCalls int
	record := chainARecord("nas.home.", "192.168.1.251")

	chain := resolvers.NewChain(
		&fakeResolver{name: "first", calls: &firstCalls},
		&fakeResolver{name: "second", records: []mdns.RR{record}, hit: true, calls: &secondCalls},
		&fakeResolver{name: "third", records: []mdns.RR{record}, hit: true, calls: &thirdCalls},
	)

	records, source, hit, err := chain.LookupSource(context.Background(), mdns.Question{
		Name: "nas.home.", Qtype: mdns.TypeA, Qclass: mdns.ClassINET,
	})
	if err != nil {
		t.Fatalf("LookupSource() = %v, want nil", err)
	}
	if !hit || len(records) != 1 {
		t.Fatalf("LookupSource() = %v, %v; want one hit", records, hit)
	}
	if source != "second" {
		t.Errorf("source = %q, want second", source)
	}
	if firstCalls != 1 || secondCalls != 1 {
		t.Errorf("calls = (%d, %d), want (1, 1)", firstCalls, secondCalls)
	}
	if thirdCalls != 0 {
		t.Errorf("third resolver calls = %d, want 0", thirdCalls)
	}
}

func TestChainCollectsErrorsUntilHit(t *testing.T) {
	var firstCalls, secondCalls, thirdCalls int
	record := chainARecord("nas.home.", "192.168.1.251")

	chain := resolvers.NewChain(
		&fakeResolver{name: "first", err: errors.New("boom"), calls: &firstCalls},
		&fakeResolver{name: "second", calls: &secondCalls},
		&fakeResolver{name: "third", records: []mdns.RR{record}, hit: true, calls: &thirdCalls},
	)
	records, source, hit, err := chain.LookupSource(context.Background(), mdns.Question{
		Name: "nas.home.", Qtype: mdns.TypeA, Qclass: mdns.ClassINET,
	})
	if err != nil || !hit || len(records) != 1 {
		t.Fatalf("LookupSource() = %v, %q, %v, %v; want third hit", records, source, hit, err)
	}
	if source != "third" {
		t.Errorf("source = %q, want third", source)
	}
	if firstCalls != 1 || secondCalls != 1 || thirdCalls != 1 {
		t.Errorf("calls = (%d, %d, %d), want all 1", firstCalls, secondCalls, thirdCalls)
	}
}

func TestChainNoHitReturnsCollectedErrors(t *testing.T) {
	chain := resolvers.NewChain(
		&fakeResolver{name: "first", err: errors.New("first failure")},
		&fakeResolver{name: "second"},
	)
	records, hit, err := chain.Lookup(context.Background(), mdns.Question{
		Name: "nas.home.", Qtype: mdns.TypeA, Qclass: mdns.ClassINET,
	})
	if hit || len(records) != 0 {
		t.Errorf("Lookup() = %v, %v; want miss", records, hit)
	}
	if err == nil || !strings.Contains(err.Error(), "first failure") {
		t.Errorf("Lookup() error = %v, want collected first failure", err)
	}

	empty := resolvers.NewChain()
	if records, hit, err := empty.Lookup(context.Background(), mdns.Question{
		Name: "nas.home.", Qtype: mdns.TypeA, Qclass: mdns.ClassINET,
	}); hit || len(records) != 0 || err != nil {
		t.Errorf("empty chain Lookup() = %v, %v, %v; want clean miss", records, hit, err)
	}
}
