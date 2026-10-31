package resolvers_test

import (
	"context"
	"errors"
	"net"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	mdns "github.com/miekg/dns"

	"tesla-gateway/internal/dns/resolvers"
)

func systemARecord(name, ip string) *mdns.A {
	return &mdns.A{
		Hdr: mdns.RR_Header{Name: name, Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 60},
		A:   net.ParseIP(ip).To4(),
	}
}

func startUDPAndTCP(t *testing.T, udpHandler, tcpHandler mdns.Handler) string {
	t.Helper()

	udpConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	addr := udpConn.LocalAddr().String()
	tcpListener, err := net.Listen("tcp", addr)
	if err != nil {
		_ = udpConn.Close()
		t.Fatalf("listen tcp %s: %v", addr, err)
	}

	udpReady := make(chan struct{})
	tcpReady := make(chan struct{})
	udpServer := &mdns.Server{PacketConn: udpConn, Handler: udpHandler, NotifyStartedFunc: func() { close(udpReady) }}
	tcpServer := &mdns.Server{Listener: tcpListener, Handler: tcpHandler, NotifyStartedFunc: func() { close(tcpReady) }}

	go func() { _ = udpServer.ActivateAndServe() }()
	go func() { _ = tcpServer.ActivateAndServe() }()

	for name, ready := range map[string]<-chan struct{}{"udp": udpReady, "tcp": tcpReady} {
		select {
		case <-ready:
		case <-time.After(2 * time.Second):
			t.Fatalf("%s test server did not start", name)
		}
	}

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = udpServer.ShutdownContext(ctx)
		_ = tcpServer.ShutdownContext(ctx)
	})
	return addr
}

func TestSystemResolverRetriesTCPAfterTruncation(t *testing.T) {
	var udpCalls, tcpCalls atomic.Int32

	addr := startUDPAndTCP(t,
		mdns.HandlerFunc(func(w mdns.ResponseWriter, req *mdns.Msg) {
			udpCalls.Add(1)
			resp := new(mdns.Msg)
			resp.SetReply(req)
			resp.Truncated = true
			_ = w.WriteMsg(resp)
		}),
		mdns.HandlerFunc(func(w mdns.ResponseWriter, req *mdns.Msg) {
			tcpCalls.Add(1)
			resp := new(mdns.Msg)
			resp.SetReply(req)
			resp.Answer = []mdns.RR{systemARecord(req.Question[0].Name, "192.168.1.99")}
			_ = w.WriteMsg(resp)
		}),
	)

	resolver, err := resolvers.NewSystemResolver([]string{addr}, resolvers.WithSystemTimeout(time.Second))
	if err != nil {
		t.Fatalf("NewSystemResolver() = %v", err)
	}

	records, hit, err := resolver.Lookup(context.Background(), mdns.Question{
		Name: "nas.home.", Qtype: mdns.TypeA, Qclass: mdns.ClassINET,
	})
	if err != nil {
		t.Fatalf("Lookup() = %v, want nil", err)
	}
	if !hit || len(records) != 1 {
		t.Fatalf("Lookup() = %v, %v; want one hit", records, hit)
	}
	if got := records[0].(*mdns.A).A.String(); got != "192.168.1.99" {
		t.Errorf("A = %s, want 192.168.1.99", got)
	}
	if udpCalls.Load() != 1 {
		t.Errorf("UDP calls = %d, want 1", udpCalls.Load())
	}
	if tcpCalls.Load() != 1 {
		t.Errorf("TCP calls = %d, want 1", tcpCalls.Load())
	}
}

func TestNewSystemResolverNormalizesUpstreams(t *testing.T) {
	resolver, err := resolvers.NewSystemResolver([]string{
		"223.5.5.5",
		"1.1.1.1:5353",
		"2001:4860:4860::8888",
		"[2606:4700:4700::1111]:53",
	})
	if err != nil {
		t.Fatalf("NewSystemResolver() = %v", err)
	}

	want := []string{
		"223.5.5.5:53",
		"1.1.1.1:5353",
		"[2001:4860:4860::8888]:53",
		"[2606:4700:4700::1111]:53",
	}
	if got := resolver.Upstreams(); !reflect.DeepEqual(got, want) {
		t.Errorf("Upstreams() = %v, want %v", got, want)
	}

	for _, tc := range [][]string{
		nil,
		{""},
		{"1.2.3.4:not-a-port"},
		{"2001::not-an-address"},
	} {
		if _, err := resolvers.NewSystemResolver(tc); err == nil {
			t.Errorf("NewSystemResolver(%v) = nil error, want error", tc)
		}
	}
}

func TestSystemResolverDHCPExpansionOrderAndCache(t *testing.T) {
	var calls atomic.Int32
	const dump = `{
		"interface": [
			{"interface": "lan", "up": true, "dns-server": ["192.168.1.1"]},
			{
				"interface": "stawan",
				"up": true,
				"route": [{"target": "0.0.0.0", "netmask": "0.0.0.0"}],
				"dns-server": ["10.1.1.1", "2001:db8::53"]
			}
		]
	}`

	resolver, err := resolvers.NewSystemResolver(
		[]string{"223.5.5.5", "dhcp", "119.29.29.29"},
		resolvers.WithSystemUbusDump(func() ([]byte, error) {
			calls.Add(1)
			return []byte(dump), nil
		}),
		resolvers.WithSystemDHCPCacheTTL(time.Minute),
	)
	if err != nil {
		t.Fatalf("NewSystemResolver() = %v", err)
	}

	want := []string{"223.5.5.5", "10.1.1.1", "2001:db8::53", "119.29.29.29"}
	if got := resolver.EffectiveUpstreams(); !reflect.DeepEqual(got, want) {
		t.Errorf("EffectiveUpstreams() = %v, want %v", got, want)
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("ubus calls = %d, want 1", got)
	}

	// The second call is served from the ~10s cache.
	if got := resolver.EffectiveUpstreams(); !reflect.DeepEqual(got, want) {
		t.Errorf("cached EffectiveUpstreams() = %v, want %v", got, want)
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("ubus calls after cache hit = %d, want 1", got)
	}
}

func TestSystemResolverDHCPUnavailableIsSkipped(t *testing.T) {
	var calls atomic.Int32
	resolver, err := resolvers.NewSystemResolver(
		[]string{"dhcp", "223.5.5.5"},
		resolvers.WithSystemUbusDump(func() ([]byte, error) {
			calls.Add(1)
			return nil, errors.New("ubus: not found")
		}),
	)
	if err != nil {
		t.Fatalf("NewSystemResolver() = %v", err)
	}

	want := []string{"223.5.5.5"}
	if got := resolver.EffectiveUpstreams(); !reflect.DeepEqual(got, want) {
		t.Errorf("EffectiveUpstreams() = %v, want %v", got, want)
	}
	if got := resolver.EffectiveUpstreams(); !reflect.DeepEqual(got, want) {
		t.Errorf("second EffectiveUpstreams() = %v, want %v", got, want)
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("ubus calls = %d, want 1 (errors are cached too)", got)
	}
}

func TestSystemResolverDHCPCacheExpires(t *testing.T) {
	var calls atomic.Int32
	now := time.Unix(1_700_000_000, 0)
	resolver, err := resolvers.NewSystemResolver(
		[]string{"dhcp"},
		resolvers.WithSystemClock(func() time.Time { return now }),
		resolvers.WithSystemDHCPCacheTTL(10*time.Second),
		resolvers.WithSystemUbusDump(func() ([]byte, error) {
			calls.Add(1)
			return []byte(`{"interface":[{"interface":"wan","up":true,"dns-server":["8.8.8.8"]}]}`), nil
		}),
	)
	if err != nil {
		t.Fatalf("NewSystemResolver() = %v", err)
	}

	if got := resolver.EffectiveUpstreams(); !reflect.DeepEqual(got, []string{"8.8.8.8"}) {
		t.Fatalf("EffectiveUpstreams() = %v, want [8.8.8.8]", got)
	}
	now = now.Add(9 * time.Second)
	_ = resolver.EffectiveUpstreams()
	if got := calls.Load(); got != 1 {
		t.Errorf("ubus calls before TTL = %d, want 1", got)
	}
	now = now.Add(2 * time.Second)
	_ = resolver.EffectiveUpstreams()
	if got := calls.Load(); got != 2 {
		t.Errorf("ubus calls after TTL = %d, want 2", got)
	}
}

func TestSystemResolverUsesConfiguredPriority(t *testing.T) {
	var firstCalls, secondCalls atomic.Int32
	first := startUDPAndTCP(t,
		mdns.HandlerFunc(func(w mdns.ResponseWriter, req *mdns.Msg) {
			firstCalls.Add(1)
			resp := new(mdns.Msg)
			resp.SetReply(req)
			resp.Answer = []mdns.RR{systemARecord(req.Question[0].Name, "192.0.2.1")}
			_ = w.WriteMsg(resp)
		}),
		mdns.HandlerFunc(func(w mdns.ResponseWriter, req *mdns.Msg) {
			resp := new(mdns.Msg)
			resp.SetReply(req)
			resp.Answer = []mdns.RR{systemARecord(req.Question[0].Name, "192.0.2.1")}
			_ = w.WriteMsg(resp)
		}),
	)
	second := startUDPAndTCP(t,
		mdns.HandlerFunc(func(w mdns.ResponseWriter, req *mdns.Msg) {
			secondCalls.Add(1)
			resp := new(mdns.Msg)
			resp.SetReply(req)
			resp.Answer = []mdns.RR{systemARecord(req.Question[0].Name, "192.0.2.2")}
			_ = w.WriteMsg(resp)
		}),
		mdns.HandlerFunc(func(w mdns.ResponseWriter, req *mdns.Msg) {
			resp := new(mdns.Msg)
			resp.SetReply(req)
			resp.Answer = []mdns.RR{systemARecord(req.Question[0].Name, "192.0.2.2")}
			_ = w.WriteMsg(resp)
		}),
	)

	resolver, err := resolvers.NewSystemResolver(
		[]string{first, second},
		resolvers.WithSystemTimeout(500*time.Millisecond),
	)
	if err != nil {
		t.Fatalf("NewSystemResolver() = %v", err)
	}

	records, hit, err := resolver.Lookup(context.Background(), mdns.Question{
		Name: "priority.home.", Qtype: mdns.TypeA, Qclass: mdns.ClassINET,
	})
	if err != nil || !hit || len(records) != 1 {
		t.Fatalf("Lookup() = %v, %v, %v; want one hit", records, hit, err)
	}
	if got := records[0].(*mdns.A).A.String(); got != "192.0.2.1" {
		t.Errorf("A = %s, want the first configured upstream 192.0.2.1", got)
	}
	if got := firstCalls.Load(); got != 1 {
		t.Errorf("first upstream calls = %d, want 1", got)
	}
	if got := secondCalls.Load(); got != 0 {
		t.Errorf("second upstream calls = %d, want 0", got)
	}
}

func TestSystemResolverFallsThroughToNextUpstream(t *testing.T) {
	// Bind but never answer, so the first upstream deterministically times out.
	silent, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen silent udp: %v", err)
	}
	t.Cleanup(func() { _ = silent.Close() })

	var secondCalls atomic.Int32
	second := startUDPAndTCP(t,
		mdns.HandlerFunc(func(w mdns.ResponseWriter, req *mdns.Msg) {
			secondCalls.Add(1)
			resp := new(mdns.Msg)
			resp.SetReply(req)
			resp.Answer = []mdns.RR{systemARecord(req.Question[0].Name, "192.0.2.2")}
			_ = w.WriteMsg(resp)
		}),
		mdns.HandlerFunc(func(w mdns.ResponseWriter, req *mdns.Msg) {
			resp := new(mdns.Msg)
			resp.SetReply(req)
			resp.Answer = []mdns.RR{systemARecord(req.Question[0].Name, "192.0.2.2")}
			_ = w.WriteMsg(resp)
		}),
	)

	resolver, err := resolvers.NewSystemResolver(
		[]string{silent.LocalAddr().String(), second},
		resolvers.WithSystemTimeout(150*time.Millisecond),
	)
	if err != nil {
		t.Fatalf("NewSystemResolver() = %v", err)
	}

	records, hit, err := resolver.Lookup(context.Background(), mdns.Question{
		Name: "fallback.home.", Qtype: mdns.TypeA, Qclass: mdns.ClassINET,
	})
	if err != nil || !hit || len(records) != 1 {
		t.Fatalf("Lookup() = %v, %v, %v; want one hit", records, hit, err)
	}
	if got := records[0].(*mdns.A).A.String(); got != "192.0.2.2" {
		t.Errorf("A = %s, want the fallback upstream 192.0.2.2", got)
	}
	if got := secondCalls.Load(); got != 1 {
		t.Errorf("second upstream calls = %d, want 1", got)
	}
}
