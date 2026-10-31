package stats_test

import (
	"sync"
	"testing"

	"tesla-gateway/internal/stats"
)

type testCacheSizer struct {
	size int
}

func (c *testCacheSizer) Size() int { return c.size }

func TestSnapshotCounters(t *testing.T) {
	cache := &testCacheSizer{size: 2}
	st := stats.New()
	st.SetCache(cache)

	for i := 0; i < 10; i++ {
		st.IncDNSQueries()
	}
	for i := 0; i < 4; i++ {
		st.IncDNSCacheHits()
	}
	for i := 0; i < 6; i++ {
		st.IncDNSCacheMisses()
	}
	st.IncDNSUpstreamQueries()
	st.IncDNSUpstreamQueries()
	st.IncDNSUpstreamErrors()

	st.IncProxyActiveConns()
	st.IncProxyActiveConns()
	st.DecProxyActiveConns()
	st.IncProxyTotalConns()
	st.IncProxyTotalConns()
	st.IncProxyTotalConns()
	st.AddProxyBytesClientToUpstream(123)
	st.AddProxyBytesUpstreamToClient(456)
	st.IncProxyRejectedNoMapping()

	snapshot := st.Snapshot()
	if got := snapshot.DNS.Queries; got != 10 {
		t.Errorf("DNS.Queries = %d, want 10", got)
	}
	if got := snapshot.DNS.CacheHits; got != 4 {
		t.Errorf("DNS.CacheHits = %d, want 4", got)
	}
	if got := snapshot.DNS.CacheMisses; got != 6 {
		t.Errorf("DNS.CacheMisses = %d, want 6", got)
	}
	if got := snapshot.DNS.UpstreamQueries; got != 2 {
		t.Errorf("DNS.UpstreamQueries = %d, want 2", got)
	}
	if got := snapshot.DNS.UpstreamErrors; got != 1 {
		t.Errorf("DNS.UpstreamErrors = %d, want 1", got)
	}
	if got := snapshot.DNS.CacheEntries; got != 2 {
		t.Errorf("DNS.CacheEntries = %d, want 2", got)
	}
	if got := snapshot.Proxy.ActiveConns; got != 1 {
		t.Errorf("Proxy.ActiveConns = %d, want 1", got)
	}
	if got := snapshot.Proxy.TotalConns; got != 3 {
		t.Errorf("Proxy.TotalConns = %d, want 3", got)
	}
	if got := snapshot.Proxy.BytesClientToUpstream; got != 123 {
		t.Errorf("Proxy.BytesClientToUpstream = %d, want 123", got)
	}
	if got := snapshot.Proxy.BytesUpstreamToClient; got != 456 {
		t.Errorf("Proxy.BytesUpstreamToClient = %d, want 456", got)
	}
	if got := snapshot.Proxy.RejectedNoMapping; got != 1 {
		t.Errorf("Proxy.RejectedNoMapping = %d, want 1", got)
	}

	// CacheEntries is sampled from the cache on every snapshot.
	cache.size = 5
	if got := st.Snapshot().DNS.CacheEntries; got != 5 {
		t.Errorf("DNS.CacheEntries after cache change = %d, want 5", got)
	}
}

func TestSnapshotConcurrentUpdates(t *testing.T) {
	const (
		workers    = 8
		iterations = 1000
	)
	st := stats.New()

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				st.IncDNSQueries()
				st.IncProxyActiveConns()
				st.DecProxyActiveConns()
				st.AddProxyBytesClientToUpstream(1)
				st.AddProxyBytesUpstreamToClient(2)
				_ = st.Snapshot()
			}
		}()
	}
	wg.Wait()

	snapshot := st.Snapshot()
	if want := uint64(workers * iterations); snapshot.DNS.Queries != want {
		t.Errorf("DNS.Queries = %d, want %d", snapshot.DNS.Queries, want)
	}
	if got := snapshot.Proxy.ActiveConns; got != 0 {
		t.Errorf("Proxy.ActiveConns = %d, want 0", got)
	}
	if want := uint64(workers * iterations); snapshot.Proxy.BytesClientToUpstream != want {
		t.Errorf("Proxy.BytesClientToUpstream = %d, want %d", snapshot.Proxy.BytesClientToUpstream, want)
	}
	if want := uint64(2 * workers * iterations); snapshot.Proxy.BytesUpstreamToClient != want {
		t.Errorf("Proxy.BytesUpstreamToClient = %d, want %d", snapshot.Proxy.BytesUpstreamToClient, want)
	}
}

func TestNilStatsIsSafe(t *testing.T) {
	var st *stats.Stats
	st.IncDNSQueries()
	st.SetCache(&testCacheSizer{size: 1})
	if got := st.Snapshot(); got != (stats.Snapshot{}) {
		t.Errorf("nil Snapshot() = %+v, want zero value", got)
	}
}
