package dns_test

import (
	"context"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	mdns "github.com/miekg/dns"

	tgdns "tesla-gateway/internal/dns"
	"tesla-gateway/internal/logx"
)

type staticResolver struct {
	name    string
	records []mdns.RR
	hit     bool
}

func (r *staticResolver) Name() string { return r.name }

func (r *staticResolver) Lookup(ctx context.Context, q mdns.Question) ([]mdns.RR, bool, error) {
	return r.records, r.hit, nil
}

type countingUpstream struct {
	response *mdns.Msg
	calls    atomic.Int32
}

func (r *countingUpstream) Name() string { return "system" }

func (r *countingUpstream) Lookup(ctx context.Context, q mdns.Question) ([]mdns.RR, bool, error) {
	return r.response.Answer, true, nil
}

func (r *countingUpstream) ExchangeMessage(ctx context.Context, req *mdns.Msg) (*mdns.Msg, error) {
	r.calls.Add(1)
	resp := r.response.Copy()
	resp.Id = req.Id
	resp.Question = append([]mdns.Question(nil), req.Question...)
	resp.Response = true
	return resp, nil
}

func startDNSServer(t *testing.T, local, upstream tgdns.Resolver, cache *tgdns.Cache, rewriter *tgdns.Rewriter) *tgdns.Server {
	t.Helper()
	logger, err := logx.New(logx.Config{Output: io.Discard, Module: "dns"})
	if err != nil {
		t.Fatalf("logx.New() = %v", err)
	}
	server, err := tgdns.NewServer(tgdns.ServerConfig{
		Listen:   "127.0.0.1:0",
		Local:    local,
		Upstream: upstream,
		Cache:    cache,
		Rewriter: rewriter,
		Logger:   logger,
	})
	if err != nil {
		t.Fatalf("NewServer() = %v", err)
	}
	if err := server.Start(); err != nil {
		t.Fatalf("Start() = %v", err)
	}
	t.Cleanup(func() {
		if err := server.Close(); err != nil {
			t.Errorf("Close() = %v", err)
		}
	})
	return server
}

func exchangeDNS(t *testing.T, network, addr, name string, qtype uint16, edns bool) *mdns.Msg {
	t.Helper()
	query := new(mdns.Msg)
	query.SetQuestion(name, qtype)
	if edns {
		query.SetEdns0(1232, true)
	}
	client := &mdns.Client{Net: network, Timeout: 3 * time.Second}
	resp, _, err := client.Exchange(query, addr)
	if err != nil {
		t.Fatalf("Exchange(%s, %s, %d) = %v", network, name, qtype, err)
	}
	return resp
}

func TestServerLocalMappingUDPAndTCP(t *testing.T) {
	local := &staticResolver{
		name:    "hosts",
		records: []mdns.RR{aRecord("nas.home.", "192.168.1.251", 600)},
		hit:     true,
	}
	server := startDNSServer(t, local, nil, tgdns.NewCache(16), tgdns.NewRewriter(testEngine(t), 300, false))
	addr := server.Addr()

	for _, network := range []string{"udp", "tcp"} {
		resp := exchangeDNS(t, network, addr, "nas.home.", mdns.TypeA, false)
		if resp.Rcode != mdns.RcodeSuccess {
			t.Errorf("%s rcode = %d, want NOERROR", network, resp.Rcode)
		}
		if len(resp.Answer) != 1 {
			t.Fatalf("%s answer count = %d, want 1", network, len(resp.Answer))
		}
		record, ok := resp.Answer[0].(*mdns.A)
		if !ok || record.A.String() != "100.64.1.251" {
			t.Errorf("%s A = %v, want mapped 100.64.1.251", network, resp.Answer[0])
		}
		if record.Hdr.Ttl != 300 {
			t.Errorf("%s TTL = %d, want clamp 300", network, record.Hdr.Ttl)
		}
	}
}

func TestServerCacheStoresRealAndRewritesOnOutput(t *testing.T) {
	upstream := &countingUpstream{response: positiveResponse("nas.home.", 60)}
	cache := tgdns.NewCache(16)
	server := startDNSServer(t, nil, upstream, cache, tgdns.NewRewriter(testEngine(t), 300, false))

	for i := 0; i < 2; i++ {
		resp := exchangeDNS(t, "udp", server.Addr(), "nas.home.", mdns.TypeA, false)
		record, ok := resp.Answer[0].(*mdns.A)
		if !ok || record.A.String() != "100.64.1.251" {
			t.Fatalf("query %d A = %v, want mapped 100.64.1.251", i, resp.Answer[0])
		}
	}

	if got := upstream.calls.Load(); got != 1 {
		t.Errorf("upstream calls = %d, want 1 (second query served from cache)", got)
	}

	cached, ok := cache.Get(mdns.Question{Name: "nas.home.", Qtype: mdns.TypeA, Qclass: mdns.ClassINET}, false, false)
	if !ok {
		t.Fatal("cache miss, want cached upstream response")
	}
	record := cached.Answer[0].(*mdns.A)
	if record.A.String() != "192.168.1.251" {
		t.Errorf("cached A = %s, want real 192.168.1.251", record.A)
	}
}

func TestServerUDPTruncationWithoutEDNS(t *testing.T) {
	var answers []mdns.RR
	for i := 0; i < 40; i++ {
		answers = append(answers, &mdns.TXT{
			Hdr: mdns.RR_Header{Name: "big.home.", Rrtype: mdns.TypeTXT, Class: mdns.ClassINET, Ttl: 60},
			Txt: []string{strings.Repeat("x", 40)},
		})
	}
	local := &staticResolver{name: "hosts", records: answers, hit: true}
	server := startDNSServer(t, local, nil, tgdns.NewCache(16), tgdns.NewRewriter(testEngine(t), 0, false))

	resp := exchangeDNS(t, "udp", server.Addr(), "big.home.", mdns.TypeTXT, false)
	if !resp.Truncated {
		t.Fatalf("Truncated = false, want TC=1 (response len=%d)", resp.Len())
	}

	// The same query over TCP must not be truncated.
	tcpResp := exchangeDNS(t, "tcp", server.Addr(), "big.home.", mdns.TypeTXT, false)
	if tcpResp.Truncated {
		t.Error("TCP response has TC=1, want full answer")
	}
	if len(tcpResp.Answer) != len(answers) {
		t.Errorf("TCP answer count = %d, want %d", len(tcpResp.Answer), len(answers))
	}
}

func TestServerAddressUsesSameEphemeralPortForUDPAndTCP(t *testing.T) {
	server := startDNSServer(t, &staticResolver{name: "hosts", hit: false}, nil, nil, nil)
	addr := server.Addr()
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("Addr() = %q: %v", addr, err)
	}
	if host != "127.0.0.1" || port == "0" || port == "" {
		t.Errorf("Addr() = %q, want selected 127.0.0.1 port", addr)
	}
}
