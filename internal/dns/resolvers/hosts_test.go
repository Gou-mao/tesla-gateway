package resolvers_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	mdns "github.com/miekg/dns"

	"tesla-gateway/internal/dns/resolvers"
)

func writeTempFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

func TestHostsLookupAAndAAAA(t *testing.T) {
	path := writeTempFile(t, "hosts", `
# comment
192.168.1.251 nas.home nas
2001:db8::251 nas.home nas6
192.168.1.252 printer.local
not-an-ip ignored.home
`)
	resolver := resolvers.NewHostsResolver(path)

	aRecords, hit, err := resolver.Lookup(context.Background(), mdns.Question{
		Name: "NAS.Home.", Qtype: mdns.TypeA, Qclass: mdns.ClassINET,
	})
	if err != nil {
		t.Fatalf("Lookup(A) = %v, want nil", err)
	}
	if !hit || len(aRecords) != 1 {
		t.Fatalf("Lookup(A) = %v, %v; want one hit", aRecords, hit)
	}
	a, ok := aRecords[0].(*mdns.A)
	if !ok || a.A.String() != "192.168.1.251" {
		t.Errorf("A record = %v, want 192.168.1.251", aRecords[0])
	}
	if a.Hdr.Ttl == 0 {
		t.Error("A record TTL = 0, want a positive default TTL")
	}

	aaaaRecords, hit, err := resolver.Lookup(context.Background(), mdns.Question{
		Name: "nas.home.", Qtype: mdns.TypeAAAA, Qclass: mdns.ClassINET,
	})
	if err != nil {
		t.Fatalf("Lookup(AAAA) = %v, want nil", err)
	}
	if !hit || len(aaaaRecords) != 1 {
		t.Fatalf("Lookup(AAAA) = %v, %v; want one hit", aaaaRecords, hit)
	}
	aaaa, ok := aaaaRecords[0].(*mdns.AAAA)
	if !ok || aaaa.AAAA.String() != "2001:db8::251" {
		t.Errorf("AAAA record = %v, want 2001:db8::251", aaaaRecords[0])
	}

	for _, tc := range []struct {
		name  string
		qtype uint16
	}{
		{name: "unknown.home.", qtype: mdns.TypeA},
		{name: "nas.home.", qtype: mdns.TypeTXT},
		{name: "printer.local.", qtype: mdns.TypeAAAA},
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

func TestHostsCustomTTLAndMissingFile(t *testing.T) {
	path := writeTempFile(t, "hosts", "10.0.0.1 nas.home\n")
	resolver := resolvers.NewHostsResolver(path, resolvers.WithHostsTTL(7))
	records, hit, err := resolver.Lookup(context.Background(), mdns.Question{
		Name: "nas.home.", Qtype: mdns.TypeA, Qclass: mdns.ClassINET,
	})
	if err != nil || !hit || len(records) != 1 {
		t.Fatalf("Lookup() = %v, %v, %v; want one hit", records, hit, err)
	}
	if got := records[0].Header().Ttl; got != 7 {
		t.Errorf("TTL = %d, want 7", got)
	}

	missing := resolvers.NewHostsResolver(filepath.Join(t.TempDir(), "missing"))
	if _, hit, err := missing.Lookup(context.Background(), mdns.Question{
		Name: "nas.home.", Qtype: mdns.TypeA, Qclass: mdns.ClassINET,
	}); err == nil || hit {
		t.Errorf("Lookup() = hit %v, err %v; want file error", hit, err)
	}
}
