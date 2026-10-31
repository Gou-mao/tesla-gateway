// Package stats tracks runtime counters for the DNS server and the TCP proxy.
// Snapshots are consumed by writer.go, which publishes them as JSON for local
// management frontends such as LuCI.
package stats

import (
	"sync"
	"sync/atomic"
	"time"
)

// CacheSizer reports the number of currently valid cache entries. It is
// implemented by dns.Cache; the interface keeps this package decoupled from
// the DNS implementation.
type CacheSizer interface {
	Size() int
}

// Stats is the set of runtime counters shared by the DNS server and the TCP
// proxy. All methods are safe for concurrent use and are no-ops on nil, so
// components can treat stats as optional.
type Stats struct {
	startedAt time.Time

	dnsQueries         atomic.Uint64
	dnsCacheHits       atomic.Uint64
	dnsCacheMisses     atomic.Uint64
	dnsUpstreamQueries atomic.Uint64
	dnsUpstreamErrors  atomic.Uint64

	proxyActiveConns           atomic.Int64
	proxyTotalConns            atomic.Uint64
	proxyBytesClientToUpstream atomic.Uint64
	proxyBytesUpstreamToClient atomic.Uint64
	proxyRejectedNoMapping     atomic.Uint64

	cacheMu sync.RWMutex
	cache   CacheSizer
}

// DNSSnapshot is one consistent-enough read of the DNS counters.
type DNSSnapshot struct {
	Queries         uint64 `json:"queries"`
	CacheHits       uint64 `json:"cache_hits"`
	CacheMisses     uint64 `json:"cache_misses"`
	UpstreamQueries uint64 `json:"upstream_queries"`
	UpstreamErrors  uint64 `json:"upstream_errors"`
	CacheEntries    int    `json:"cache_entries"`
}

// ProxySnapshot is one consistent-enough read of the proxy counters.
type ProxySnapshot struct {
	ActiveConns           int64  `json:"active_conns"`
	TotalConns            uint64 `json:"total_conns"`
	BytesClientToUpstream uint64 `json:"bytes_client_to_upstream"`
	BytesUpstreamToClient uint64 `json:"bytes_upstream_to_client"`
	RejectedNoMapping     uint64 `json:"rejected_no_mapping"`
}

// Snapshot is a plain data copy of the counters. It has no pointers into the
// live Stats value and can safely be marshalled after the caller returns.
type Snapshot struct {
	DNS   DNSSnapshot   `json:"dns"`
	Proxy ProxySnapshot `json:"proxy"`
}

// New creates a Stats value and records the process start time used for the
// uptime field in published snapshots. An optional cache may be supplied to
// enable cache entry reporting.
func New(caches ...CacheSizer) *Stats {
	s := &Stats{startedAt: time.Now()}
	if len(caches) > 0 {
		s.cache = caches[0]
	}
	return s
}

// StartedAt returns the time at which the stats collector was created.
func (s *Stats) StartedAt() time.Time {
	if s == nil {
		return time.Time{}
	}
	return s.startedAt
}

// SetCache installs the DNS cache whose valid entry count is included in every
// snapshot. Passing nil disables cache entry reporting.
func (s *Stats) SetCache(cache CacheSizer) {
	if s == nil {
		return
	}
	s.cacheMu.Lock()
	s.cache = cache
	s.cacheMu.Unlock()
}

// Snapshot returns a plain copy of all counters. CacheEntries is sampled from
// the configured cache at call time.
func (s *Stats) Snapshot() Snapshot {
	if s == nil {
		return Snapshot{}
	}

	s.cacheMu.RLock()
	cache := s.cache
	s.cacheMu.RUnlock()

	cacheEntries := 0
	if cache != nil {
		cacheEntries = cache.Size()
	}

	return Snapshot{
		DNS: DNSSnapshot{
			Queries:         s.dnsQueries.Load(),
			CacheHits:       s.dnsCacheHits.Load(),
			CacheMisses:     s.dnsCacheMisses.Load(),
			UpstreamQueries: s.dnsUpstreamQueries.Load(),
			UpstreamErrors:  s.dnsUpstreamErrors.Load(),
			CacheEntries:    cacheEntries,
		},
		Proxy: ProxySnapshot{
			ActiveConns:           s.proxyActiveConns.Load(),
			TotalConns:            s.proxyTotalConns.Load(),
			BytesClientToUpstream: s.proxyBytesClientToUpstream.Load(),
			BytesUpstreamToClient: s.proxyBytesUpstreamToClient.Load(),
			RejectedNoMapping:     s.proxyRejectedNoMapping.Load(),
		},
	}
}

// IncDNSQueries counts one handled DNS query.
func (s *Stats) IncDNSQueries() {
	if s != nil {
		s.dnsQueries.Add(1)
	}
}

// IncDNSCacheHits counts one DNS query answered from the cache.
func (s *Stats) IncDNSCacheHits() {
	if s != nil {
		s.dnsCacheHits.Add(1)
	}
}

// IncDNSCacheMisses counts one DNS query that was not answered from the cache.
func (s *Stats) IncDNSCacheMisses() {
	if s != nil {
		s.dnsCacheMisses.Add(1)
	}
}

// IncDNSUpstreamQueries counts one query sent to the upstream resolver.
func (s *Stats) IncDNSUpstreamQueries() {
	if s != nil {
		s.dnsUpstreamQueries.Add(1)
	}
}

// IncDNSUpstreamErrors counts one failed upstream resolver query.
func (s *Stats) IncDNSUpstreamErrors() {
	if s != nil {
		s.dnsUpstreamErrors.Add(1)
	}
}

// IncProxyActiveConns counts a newly relayed upstream connection.
func (s *Stats) IncProxyActiveConns() {
	if s != nil {
		s.proxyActiveConns.Add(1)
	}
}

// DecProxyActiveConns marks one relayed upstream connection as finished.
func (s *Stats) DecProxyActiveConns() {
	if s != nil {
		s.proxyActiveConns.Add(-1)
	}
}

// IncProxyTotalConns counts one successfully established upstream connection.
func (s *Stats) IncProxyTotalConns() {
	if s != nil {
		s.proxyTotalConns.Add(1)
	}
}

// AddProxyBytesClientToUpstream adds bytes relayed from clients to upstreams.
func (s *Stats) AddProxyBytesClientToUpstream(n uint64) {
	if s != nil && n > 0 {
		s.proxyBytesClientToUpstream.Add(n)
	}
}

// AddProxyBytesUpstreamToClient adds bytes relayed from upstreams to clients.
func (s *Stats) AddProxyBytesUpstreamToClient(n uint64) {
	if s != nil && n > 0 {
		s.proxyBytesUpstreamToClient.Add(n)
	}
}

// IncProxyRejectedNoMapping counts connections rejected because the original
// destination had no reverse mapping.
func (s *Stats) IncProxyRejectedNoMapping() {
	if s != nil {
		s.proxyRejectedNoMapping.Add(1)
	}
}

// Short aliases keep call sites readable where the namespace is already clear.
// They behave exactly like the explicit IncDNS*/IncProxy* methods above.

func (s *Stats) IncQueries()         { s.IncDNSQueries() }
func (s *Stats) IncCacheHits()       { s.IncDNSCacheHits() }
func (s *Stats) IncCacheMisses()     { s.IncDNSCacheMisses() }
func (s *Stats) IncUpstreamQueries() { s.IncDNSUpstreamQueries() }
func (s *Stats) IncUpstreamErrors()  { s.IncDNSUpstreamErrors() }
func (s *Stats) IncActiveConns()     { s.IncProxyActiveConns() }
func (s *Stats) DecActiveConns()     { s.DecProxyActiveConns() }
func (s *Stats) IncTotalConns()      { s.IncProxyTotalConns() }
func (s *Stats) IncRejectedNoMapping() {
	s.IncProxyRejectedNoMapping()
}
func (s *Stats) AddBytesClientToUpstream(n uint64) {
	s.AddProxyBytesClientToUpstream(n)
}
func (s *Stats) AddBytesUpstreamToClient(n uint64) {
	s.AddProxyBytesUpstreamToClient(n)
}
