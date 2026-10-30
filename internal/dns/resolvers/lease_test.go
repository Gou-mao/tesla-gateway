package resolvers_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	mdns "github.com/miekg/dns"

	"tesla-gateway/internal/dns/resolvers"
)

func TestLeaseLookupA(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	content := fmt.Sprintf(`
%d aa:bb:cc:dd:ee:01 192.168.1.50 nas.home *
%d aa:bb:cc:dd:ee:02 192.168.1.51 old.home *
%d aa:bb:cc:dd:ee:03 192.168.1.52 printer.local *
%d aa:bb:cc:dd:ee:04 192.168.1.53 * *
garbage line
`, now.Unix()+3600, now.Unix()-1, now.Unix()+600, now.Unix()+600)
	path := writeTempFile(t, "dhcp.leases", content)
	resolver := resolvers.NewLeaseResolver(path, resolvers.WithLeaseClock(func() time.Time { return now }))

	records, hit, err := resolver.Lookup(context.Background(), mdns.Question{
		Name: "NAS.Home.", Qtype: mdns.TypeA, Qclass: mdns.ClassINET,
	})
	if err != nil {
		t.Fatalf("Lookup() = %v, want nil", err)
	}
	if !hit || len(records) != 1 {
		t.Fatalf("Lookup() = %v, %v; want one hit", records, hit)
	}
	a, ok := records[0].(*mdns.A)
	if !ok || a.A.String() != "192.168.1.50" {
		t.Errorf("A record = %v, want 192.168.1.50", records[0])
	}
	if a.Hdr.Ttl != 3600 {
		t.Errorf("TTL = %d, want remaining lease time 3600", a.Hdr.Ttl)
	}

	for _, tc := range []struct {
		name  string
		qtype uint16
	}{
		{name: "old.home.", qtype: mdns.TypeA},
		{name: "unknown.home.", qtype: mdns.TypeA},
		{name: "nas.home.", qtype: mdns.TypeAAAA},
	} {
		records, hit, err := resolver.Lookup(context.Background(), mdns.Question{
			Name: tc.name, Qtype: tc.qtype, Qclass: mdns.ClassINET,
		})
		if err != nil {
			t.Errorf("Lookup(%s, %d) = %v, want nil", tc.name, tc.qtype, err)
		}
		if hit || len(records) != 0 {
			t.Errorf("Lookup(%s, %d) = %v, %v; want miss", tc.name, tc.qtype, records, hit)
		}
	}
}

func TestLeaseUnlimitedAndMissingFile(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	path := writeTempFile(t, "dhcp.leases", "0 aa:bb:cc:dd:ee:01 10.0.0.9 always.home *\n")
	resolver := resolvers.NewLeaseResolver(path, resolvers.WithLeaseClock(func() time.Time { return now }))
	records, hit, err := resolver.Lookup(context.Background(), mdns.Question{
		Name: "always.home.", Qtype: mdns.TypeA, Qclass: mdns.ClassINET,
	})
	if err != nil || !hit || len(records) != 1 {
		t.Fatalf("Lookup() = %v, %v, %v; want one hit", records, hit, err)
	}
	if records[0].Header().Ttl == 0 {
		t.Error("unlimited lease TTL = 0, want a positive default")
	}

	missing := resolvers.NewLeaseResolver(t.TempDir() + "/missing")
	if _, hit, err := missing.Lookup(context.Background(), mdns.Question{
		Name: "always.home.", Qtype: mdns.TypeA, Qclass: mdns.ClassINET,
	}); err == nil || hit {
		t.Errorf("Lookup() = hit %v, err %v; want file error", hit, err)
	}
}
