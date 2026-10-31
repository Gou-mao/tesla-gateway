package dns_test

import (
	"testing"
	"time"

	mdns "github.com/miekg/dns"

	tgdns "tesla-gateway/internal/dns"
)

func cacheQuestion(name string, qtype uint16) mdns.Question {
	return mdns.Question{Name: name, Qtype: qtype, Qclass: mdns.ClassINET}
}

func positiveResponse(name string, ttl uint32) *mdns.Msg {
	msg := new(mdns.Msg)
	msg.SetQuestion(mdns.Fqdn(name), mdns.TypeA)
	msg.Response = true
	msg.Answer = []mdns.RR{aRecord(mdns.Fqdn(name), "192.168.1.251", ttl)}
	return msg
}

func negativeResponse(name string, rcode int, soa *mdns.SOA) *mdns.Msg {
	msg := new(mdns.Msg)
	msg.SetQuestion(mdns.Fqdn(name), mdns.TypeA)
	msg.Response = true
	msg.Rcode = rcode
	if soa != nil {
		msg.Ns = []mdns.RR{soa}
	}
	return msg
}

func TestCacheTTLExpiryAndUnrewrittenData(t *testing.T) {
	now := time.Unix(1000, 0)
	cache := tgdns.NewCache(10, tgdns.WithCacheClock(func() time.Time { return now }))
	q := cacheQuestion("Nas.Home.", mdns.TypeA)

	cache.Put(q, positiveResponse("nas.home.", 2))
	now = now.Add(time.Second)

	got, ok := cache.Get(cacheQuestion("nas.home.", mdns.TypeA))
	if !ok {
		t.Fatal("Get() = miss after 1s, want hit (TTL 2s)")
	}
	record := got.Answer[0].(*mdns.A)
	if record.A.String() != "192.168.1.251" {
		t.Errorf("cached A = %s, want real 192.168.1.251 (cache stores unrewritten data)", record.A)
	}
	if record.Hdr.Ttl != 1 {
		t.Errorf("cached TTL = %d, want 1 remaining second", record.Hdr.Ttl)
	}

	now = now.Add(time.Second)
	if _, ok := cache.Get(q); ok {
		t.Error("Get() = hit at expiry, want miss")
	}
	if cache.Len() != 0 {
		t.Errorf("Len() = %d after expired lookup, want 0", cache.Len())
	}
}

func TestCacheNegativeNXDOMAIN(t *testing.T) {
	now := time.Unix(1000, 0)
	cache := tgdns.NewCache(10, tgdns.WithCacheClock(func() time.Time { return now }))
	q := cacheQuestion("missing.home.", mdns.TypeA)

	soa := &mdns.SOA{
		Hdr:     mdns.RR_Header{Name: "home.", Rrtype: mdns.TypeSOA, Class: mdns.ClassINET, Ttl: 60},
		Ns:      "ns.home.",
		Mbox:    "hostmaster.home.",
		Minttl:  5,
		Refresh: 3600,
		Retry:   600,
		Expire:  86400,
	}
	cache.Put(q, negativeResponse("missing.home.", mdns.RcodeNameError, soa))

	now = now.Add(4 * time.Second)
	got, ok := cache.Get(q)
	if !ok {
		t.Fatal("Get() = miss after 4s, want negative cache hit")
	}
	if got.Rcode != mdns.RcodeNameError {
		t.Errorf("cached rcode = %d, want NXDOMAIN", got.Rcode)
	}
	if len(got.Ns) != 1 {
		t.Fatalf("cached authority = %d records, want SOA", len(got.Ns))
	}

	now = now.Add(2 * time.Second)
	if _, ok := cache.Get(q); ok {
		t.Error("Get() = hit after SOA minimum expired, want miss")
	}
}

func TestCacheNegativeNODATADefaultTTL(t *testing.T) {
	now := time.Unix(1000, 0)
	cache := tgdns.NewCache(10, tgdns.WithCacheClock(func() time.Time { return now }))
	q := cacheQuestion("empty.home.", mdns.TypeA)

	cache.Put(q, negativeResponse("empty.home.", mdns.RcodeSuccess, nil))

	now = now.Add(29 * time.Second)
	if _, ok := cache.Get(q); !ok {
		t.Error("Get() = miss after 29s, want default 30s negative cache hit")
	}
	now = now.Add(2 * time.Second)
	if _, ok := cache.Get(q); ok {
		t.Error("Get() = hit after default 30s, want miss")
	}
}

func TestCacheLRUEviction(t *testing.T) {
	now := time.Unix(1000, 0)
	cache := tgdns.NewCache(2, tgdns.WithCacheClock(func() time.Time { return now }))

	cache.Put(cacheQuestion("one.home.", mdns.TypeA), positiveResponse("one.home.", 60))
	cache.Put(cacheQuestion("two.home.", mdns.TypeA), positiveResponse("two.home.", 60))
	cache.Put(cacheQuestion("three.home.", mdns.TypeA), positiveResponse("three.home.", 60))

	if _, ok := cache.Get(cacheQuestion("one.home.", mdns.TypeA)); ok {
		t.Error("oldest entry was not evicted")
	}
	if _, ok := cache.Get(cacheQuestion("two.home.", mdns.TypeA)); !ok {
		t.Error("second entry missing after eviction")
	}
	if _, ok := cache.Get(cacheQuestion("three.home.", mdns.TypeA)); !ok {
		t.Error("newest entry missing")
	}
}

func TestCacheKeyIsCaseInsensitiveAndQTypeSpecific(t *testing.T) {
	now := time.Unix(1000, 0)
	cache := tgdns.NewCache(10, tgdns.WithCacheClock(func() time.Time { return now }))

	cache.Put(cacheQuestion("NAS.Home.", mdns.TypeA), positiveResponse("nas.home.", 60))
	if _, ok := cache.Get(cacheQuestion("nas.home.", mdns.TypeA)); !ok {
		t.Error("case-insensitive A lookup missed")
	}
	if _, ok := cache.Get(cacheQuestion("nas.home.", mdns.TypeAAAA)); ok {
		t.Error("AAAA lookup hit an A cache entry")
	}
}

func TestCacheSizeCountsOnlyValidEntries(t *testing.T) {
	now := time.Unix(1000, 0)
	cache := tgdns.NewCache(10, tgdns.WithCacheClock(func() time.Time { return now }))

	cache.Put(cacheQuestion("short.home.", mdns.TypeA), positiveResponse("short.home.", 1))
	cache.Put(cacheQuestion("long.home.", mdns.TypeA), positiveResponse("long.home.", 60))
	if got := cache.Size(); got != 2 {
		t.Errorf("Size() = %d, want 2", got)
	}

	now = now.Add(2 * time.Second)
	if got := cache.Size(); got != 1 {
		t.Errorf("Size() after expiry = %d, want 1", got)
	}
	if got := cache.Len(); got != 1 {
		t.Errorf("Len() after Size cleanup = %d, want 1", got)
	}
	if _, ok := cache.Get(cacheQuestion("long.home.", mdns.TypeA)); !ok {
		t.Error("valid entry was removed by Size")
	}
}

func TestCacheClear(t *testing.T) {
	now := time.Unix(1000, 0)
	cache := tgdns.NewCache(10, tgdns.WithCacheClock(func() time.Time { return now }))
	cache.Put(cacheQuestion("nas.home.", mdns.TypeA), positiveResponse("nas.home.", 60))
	cache.Clear()
	if cache.Len() != 0 {
		t.Errorf("Len() = %d after Clear, want 0", cache.Len())
	}
}
