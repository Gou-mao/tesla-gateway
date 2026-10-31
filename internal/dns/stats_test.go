package dns_test

import (
	"context"
	"errors"
	"io"
	"sync/atomic"
	"testing"

	mdns "github.com/miekg/dns"

	tgdns "tesla-gateway/internal/dns"
	"tesla-gateway/internal/logx"
	"tesla-gateway/internal/stats"
)

type failingUpstream struct {
	calls atomic.Int32
	err   error
}

func (r *failingUpstream) Name() string { return "failing" }

func (r *failingUpstream) Lookup(ctx context.Context, q mdns.Question) ([]mdns.RR, bool, error) {
	r.calls.Add(1)
	return nil, false, r.err
}

func (r *failingUpstream) ExchangeMessage(ctx context.Context, req *mdns.Msg) (*mdns.Msg, error) {
	r.calls.Add(1)
	return nil, r.err
}

func startDNSServerWithStats(t *testing.T, upstream tgdns.Resolver, cache *tgdns.Cache, st *stats.Stats) *tgdns.Server {
	t.Helper()
	logger, err := logx.New(logx.Config{Output: io.Discard, Module: "dns"})
	if err != nil {
		t.Fatalf("logx.New() = %v", err)
	}
	server, err := tgdns.NewServer(tgdns.ServerConfig{
		Listen:   "127.0.0.1:0",
		Upstream: upstream,
		Cache:    cache,
		Rewriter: tgdns.NewRewriter(testEngine(t), 0, false),
		Logger:   logger,
		Stats:    st,
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

func TestServerStatsCacheAndUpstream(t *testing.T) {
	upstream := &countingUpstream{response: positiveResponse("nas.home.", 60)}
	cache := tgdns.NewCache(16)
	st := stats.New()
	st.SetCache(cache)
	server := startDNSServerWithStats(t, upstream, cache, st)

	for i := 0; i < 2; i++ {
		resp := exchangeDNS(t, "udp", server.Addr(), "nas.home.", mdns.TypeA, false)
		if resp.Rcode != mdns.RcodeSuccess {
			t.Fatalf("query %d rcode = %d, want NOERROR", i, resp.Rcode)
		}
	}

	snapshot := st.Snapshot()
	if got := snapshot.DNS.Queries; got != 2 {
		t.Errorf("DNS.Queries = %d, want 2", got)
	}
	if got := snapshot.DNS.CacheHits; got != 1 {
		t.Errorf("DNS.CacheHits = %d, want 1", got)
	}
	if got := snapshot.DNS.CacheMisses; got != 1 {
		t.Errorf("DNS.CacheMisses = %d, want 1", got)
	}
	if got := snapshot.DNS.UpstreamQueries; got != 1 {
		t.Errorf("DNS.UpstreamQueries = %d, want 1", got)
	}
	if got := snapshot.DNS.UpstreamErrors; got != 0 {
		t.Errorf("DNS.UpstreamErrors = %d, want 0", got)
	}
	if got := snapshot.DNS.CacheEntries; got != 1 {
		t.Errorf("DNS.CacheEntries = %d, want 1", got)
	}
	if got := upstream.calls.Load(); got != 1 {
		t.Errorf("upstream calls = %d, want 1", got)
	}
}

func TestServerStatsUpstreamError(t *testing.T) {
	upstream := &failingUpstream{err: errors.New("upstream unavailable")}
	cache := tgdns.NewCache(16)
	st := stats.New()
	st.SetCache(cache)
	server := startDNSServerWithStats(t, upstream, cache, st)

	resp := exchangeDNS(t, "udp", server.Addr(), "nas.home.", mdns.TypeA, false)
	if resp.Rcode != mdns.RcodeServerFailure {
		t.Fatalf("rcode = %d, want SERVFAIL", resp.Rcode)
	}

	snapshot := st.Snapshot()
	if got := snapshot.DNS.Queries; got != 1 {
		t.Errorf("DNS.Queries = %d, want 1", got)
	}
	if got := snapshot.DNS.CacheHits; got != 0 {
		t.Errorf("DNS.CacheHits = %d, want 0", got)
	}
	if got := snapshot.DNS.CacheMisses; got != 1 {
		t.Errorf("DNS.CacheMisses = %d, want 1", got)
	}
	if got := snapshot.DNS.UpstreamQueries; got != 1 {
		t.Errorf("DNS.UpstreamQueries = %d, want 1", got)
	}
	if got := snapshot.DNS.UpstreamErrors; got != 1 {
		t.Errorf("DNS.UpstreamErrors = %d, want 1", got)
	}
	if got := snapshot.DNS.CacheEntries; got != 0 {
		t.Errorf("DNS.CacheEntries = %d, want 0", got)
	}
	if got := upstream.calls.Load(); got != 1 {
		t.Errorf("upstream calls = %d, want 1", got)
	}
}
