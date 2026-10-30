package dns_test

import (
	"net"
	"net/netip"
	"testing"

	mdns "github.com/miekg/dns"

	tgdns "tesla-gateway/internal/dns"
	"tesla-gateway/internal/mapping"
)

func testEngine(t *testing.T) *mapping.Engine {
	t.Helper()
	strategy := mapping.NewPrefixMappingStrategy([]mapping.PrefixMapping{
		{
			From: netip.MustParsePrefix("192.168.1.0/24"),
			To:   netip.MustParsePrefix("100.64.1.0/24"),
		},
	})
	if err := strategy.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil", err)
	}
	return mapping.NewEngine(strategy)
}

func ip4(s string) net.IP {
	return net.ParseIP(s).To4()
}

func ip6(s string) net.IP {
	return net.ParseIP(s).To16()
}

func aRecord(name, ip string, ttl uint32) *mdns.A {
	return &mdns.A{
		Hdr: mdns.RR_Header{Name: name, Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: ttl},
		A:   ip4(ip),
	}
}

func aaaaRecord(name, ip string, ttl uint32) *mdns.AAAA {
	return &mdns.AAAA{
		Hdr:  mdns.RR_Header{Name: name, Rrtype: mdns.TypeAAAA, Class: mdns.ClassINET, Ttl: ttl},
		AAAA: ip6(ip),
	}
}

func TestRewriteARecordsAndAAAA(t *testing.T) {
	msg := new(mdns.Msg)
	msg.SetQuestion("nas.home.", mdns.TypeA)
	msg.Response = true
	msg.Answer = []mdns.RR{
		aRecord("nas.home.", "192.168.1.251", 120),
		aaaaRecord("nas.home.", "2001:db8::251", 120),
		aRecord("nas.home.", "10.0.0.5", 120),
	}

	got := tgdns.Rewrite(msg, tgdns.RewriteOptions{Engine: testEngine(t)})
	if got == msg {
		t.Fatal("Rewrite returned the input message, want a copy")
	}
	if len(got.Answer) != 3 {
		t.Fatalf("len(Answer) = %d, want 3", len(got.Answer))
	}

	first, ok := got.Answer[0].(*mdns.A)
	if !ok || first.A.String() != "100.64.1.251" {
		t.Errorf("Answer[0] = %v, want mapped A 100.64.1.251", got.Answer[0])
	}
	second, ok := got.Answer[1].(*mdns.AAAA)
	if !ok || second.AAAA.String() != "2001:db8::251" {
		t.Errorf("Answer[1] = %v, want untouched AAAA 2001:db8::251", got.Answer[1])
	}
	third, ok := got.Answer[2].(*mdns.A)
	if !ok || third.A.String() != "10.0.0.5" {
		t.Errorf("Answer[2] = %v, want untouched A 10.0.0.5", got.Answer[2])
	}

	original := msg.Answer[0].(*mdns.A)
	if original.A.String() != "192.168.1.251" {
		t.Errorf("input message was mutated: A = %s, want 192.168.1.251", original.A)
	}
}

func TestRewriteClampTTLMultiAAndCNAME(t *testing.T) {
	msg := new(mdns.Msg)
	msg.SetQuestion("nas.home.", mdns.TypeA)
	msg.Response = true
	msg.Answer = []mdns.RR{
		&mdns.CNAME{
			Hdr:    mdns.RR_Header{Name: "nas.home.", Rrtype: mdns.TypeCNAME, Class: mdns.ClassINET, Ttl: 600},
			Target: "server.home.",
		},
		aRecord("server.home.", "192.168.1.10", 500),
		aRecord("server.home.", "192.168.1.11", 900),
		aRecord("server.home.", "10.0.0.7", 100),
	}

	got := tgdns.Rewrite(msg, tgdns.RewriteOptions{
		Engine:   testEngine(t),
		ClampTTL: 300,
	})
	if len(got.Answer) != 4 {
		t.Fatalf("len(Answer) = %d, want 4 (CNAME plus three separate A records)", len(got.Answer))
	}

	cname, ok := got.Answer[0].(*mdns.CNAME)
	if !ok {
		t.Fatalf("Answer[0] = %T, want CNAME", got.Answer[0])
	}
	if cname.Target != "server.home." {
		t.Errorf("CNAME target = %q, want server.home.", cname.Target)
	}
	if cname.Hdr.Ttl != 300 {
		t.Errorf("CNAME TTL = %d, want clamp 300", cname.Hdr.Ttl)
	}

	want := []struct {
		ip  string
		ttl uint32
	}{
		{ip: "100.64.1.10", ttl: 300},
		{ip: "100.64.1.11", ttl: 300},
		{ip: "10.0.0.7", ttl: 100},
	}
	for i, tc := range want {
		record, ok := got.Answer[i+1].(*mdns.A)
		if !ok {
			t.Fatalf("Answer[%d] = %T, want A", i+1, got.Answer[i+1])
		}
		if record.A.String() != tc.ip {
			t.Errorf("Answer[%d].A = %s, want %s", i+1, record.A, tc.ip)
		}
		if record.Hdr.Ttl != tc.ttl {
			t.Errorf("Answer[%d].TTL = %d, want %d", i+1, record.Hdr.Ttl, tc.ttl)
		}
	}
}

func TestRewriteDropAAAA(t *testing.T) {
	msg := new(mdns.Msg)
	msg.SetQuestion("nas.home.", mdns.TypeAAAA)
	msg.Response = true
	msg.Answer = []mdns.RR{
		aRecord("nas.home.", "192.168.1.251", 60),
		aaaaRecord("nas.home.", "2001:db8::251", 60),
	}

	got := tgdns.Rewrite(msg, tgdns.RewriteOptions{
		Engine:   testEngine(t),
		DropAAAA: true,
	})
	if len(got.Answer) != 1 {
		t.Fatalf("len(Answer) = %d, want 1 after dropping AAAA", len(got.Answer))
	}
	if _, ok := got.Answer[0].(*mdns.A); !ok {
		t.Errorf("Answer[0] = %T, want remaining A record", got.Answer[0])
	}
	if len(msg.Answer) != 2 {
		t.Errorf("input Answer length = %d, want original 2", len(msg.Answer))
	}
}

func TestRewritePreservesEDNS0AndDNSSEC(t *testing.T) {
	msg := new(mdns.Msg)
	msg.SetQuestion("nas.home.", mdns.TypeA)
	msg.Response = true
	msg.AuthenticatedData = true
	msg.CheckingDisabled = true
	msg.SetEdns0(1232, true)
	opt := msg.IsEdns0()
	optTTL := opt.Hdr.Ttl
	msg.Answer = []mdns.RR{aRecord("nas.home.", "192.168.1.251", 600)}

	got := tgdns.Rewrite(msg, tgdns.RewriteOptions{
		Engine:   testEngine(t),
		ClampTTL: 1,
	})
	if !got.AuthenticatedData {
		t.Error("AD flag was cleared")
	}
	if !got.CheckingDisabled {
		t.Error("CD flag was cleared")
	}

	gotOpt := got.IsEdns0()
	if gotOpt == nil {
		t.Fatal("OPT record was removed")
	}
	if !gotOpt.Do() {
		t.Error("DO bit was cleared")
	}
	if gotOpt.UDPSize() != 1232 {
		t.Errorf("OPT UDP size = %d, want 1232", gotOpt.UDPSize())
	}
	if gotOpt.Hdr.Ttl != optTTL {
		t.Errorf("OPT TTL/flags = %d, want unchanged %d", gotOpt.Hdr.Ttl, optTTL)
	}
	if got.Answer[0].Header().Ttl != 1 {
		t.Errorf("A TTL = %d, want clamp 1", got.Answer[0].Header().Ttl)
	}
}

func TestRewriteTranslations(t *testing.T) {
	msg := new(mdns.Msg)
	msg.SetQuestion("nas.home.", mdns.TypeA)
	msg.Response = true
	msg.Answer = []mdns.RR{
		aRecord("nas.home.", "192.168.1.10", 60),
		aRecord("nas.home.", "192.168.1.11", 60),
	}

	got, translations := tgdns.RewriteWithTranslations(msg, tgdns.RewriteOptions{Engine: testEngine(t)})
	if len(got.Answer) != 2 {
		t.Fatalf("len(Answer) = %d, want 2", len(got.Answer))
	}
	if len(translations) != 2 {
		t.Fatalf("len(translations) = %d, want 2", len(translations))
	}
	if translations[0].Real.String() != "192.168.1.10" || translations[0].Mapped.String() != "100.64.1.10" {
		t.Errorf("translations[0] = %+v", translations[0])
	}
	if translations[1].Real.String() != "192.168.1.11" || translations[1].Mapped.String() != "100.64.1.11" {
		t.Errorf("translations[1] = %+v", translations[1])
	}
}

func TestRewriteNilMessage(t *testing.T) {
	if got := tgdns.Rewrite(nil, tgdns.RewriteOptions{}); got != nil {
		t.Errorf("Rewrite(nil) = %v, want nil", got)
	}
}
