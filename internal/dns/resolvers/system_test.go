package resolvers_test

import (
	"context"
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
