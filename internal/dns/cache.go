package dns

import (
	"container/list"
	"strconv"
	"strings"
	"sync"
	"time"

	mdns "github.com/miekg/dns"
)

const (
	defaultCacheMax    = 4096
	defaultNegativeTTL = 30 * time.Second
)

// Cache is a concurrency-safe LRU cache with per-entry TTL and RFC 2308
// negative caching. It stores real (unrewritten) responses; mapping is applied
// by the server on the way out.
type Cache struct {
	mu    sync.Mutex
	max   int
	now   func() time.Time
	lru   *list.List
	items map[string]*list.Element
}

// CacheOption configures a Cache.
type CacheOption func(*Cache)

// WithCacheClock replaces the cache clock. It is primarily useful in tests.
func WithCacheClock(now func() time.Time) CacheOption {
	return func(c *Cache) {
		if now != nil {
			c.now = now
		}
	}
}

type cacheEntry struct {
	key    string
	msg    *mdns.Msg
	stored time.Time
	expiry time.Time
}

// NewCache creates a cache holding at most max responses. A non-positive max
// uses the default of 4096 entries.
func NewCache(max int, opts ...CacheOption) *Cache {
	if max <= 0 {
		max = defaultCacheMax
	}
	c := &Cache{
		max:   max,
		now:   time.Now,
		lru:   list.New(),
		items: make(map[string]*list.Element),
	}
	for _, opt := range opts {
		if opt != nil {
			opt(c)
		}
	}
	return c
}

// Len returns the number of cached entries, including not-yet-evicted expired
// entries.
func (c *Cache) Len() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lru.Len()
}

// Size returns the number of currently valid (unexpired) entries. Expired
// entries encountered while counting are removed from the cache.
func (c *Cache) Size() int {
	if c == nil {
		return 0
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	now := c.now()
	for element := c.lru.Back(); element != nil; {
		previous := element.Prev()
		entry := element.Value.(*cacheEntry)
		if !now.Before(entry.expiry) {
			c.removeElement(element)
		}
		element = previous
	}
	return c.lru.Len()
}

// Clear removes all entries.
func (c *Cache) Clear() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lru.Init()
	c.items = make(map[string]*list.Element)
}

// Get returns a deep copy of the cached response. Expired entries are treated
// as misses. TTLs in the returned copy are reduced by the time spent in the
// cache. do and cd are the request's EDNS0 DNSSEC-OK and CheckingDisabled bits;
// they are part of the key because they change the upstream response.
func (c *Cache) Get(q mdns.Question, do, cd bool) (*mdns.Msg, bool) {
	if c == nil {
		return nil, false
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	element, ok := c.items[cacheKey(q, do, cd)]
	if !ok {
		return nil, false
	}

	entry := element.Value.(*cacheEntry)
	now := c.now()
	if !now.Before(entry.expiry) {
		c.removeElement(element)
		return nil, false
	}

	c.lru.MoveToFront(element)
	out := entry.msg.Copy()
	if elapsed := now.Sub(entry.stored); elapsed > 0 {
		decrementTTLs(out, uint32(elapsed/time.Second))
	}
	return out, true
}

// Put stores a real response if it is cacheable. Positive answers expire after
// the smallest answer TTL. NXDOMAIN and NODATA responses expire according to
// the SOA minimum (or 30 seconds when no SOA is present). Other rcodes and
// zero-TTL responses are not cached. OPT records are not stored. do and cd
// distinguish responses obtained with different DNSSEC request flags.
func (c *Cache) Put(q mdns.Question, msg *mdns.Msg, do, cd bool) {
	if c == nil || msg == nil {
		return
	}

	ttl, ok := cacheTTL(msg, q.Qtype)
	if !ok || ttl <= 0 {
		return
	}

	now := c.now()
	stored := msg.Copy()
	stored.Extra = withoutOPT(stored.Extra)

	entry := &cacheEntry{
		key:    cacheKey(q, do, cd),
		msg:    stored,
		stored: now,
		expiry: now.Add(ttl),
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if element, exists := c.items[entry.key]; exists {
		element.Value = entry
		c.lru.MoveToFront(element)
		return
	}

	element := c.lru.PushFront(entry)
	c.items[entry.key] = element
	for c.lru.Len() > c.max {
		c.removeElement(c.lru.Back())
	}
}

func (c *Cache) removeElement(element *list.Element) {
	if element == nil {
		return
	}
	entry := element.Value.(*cacheEntry)
	delete(c.items, entry.key)
	c.lru.Remove(element)
}

func cacheKey(q mdns.Question, do, cd bool) string {
	name := strings.ToLower(mdns.Fqdn(q.Name))
	return name + "\x00" +
		strconv.FormatUint(uint64(q.Qtype), 10) + "\x00" +
		strconv.FormatBool(do) + "\x00" +
		strconv.FormatBool(cd)
}

func cacheTTL(msg *mdns.Msg, qtype uint16) (time.Duration, bool) {
	switch msg.Rcode {
	case mdns.RcodeSuccess:
		if !hasAnswerType(msg.Answer, qtype) {
			return negativeTTL(msg)
		}
	case mdns.RcodeNameError:
		return negativeTTL(msg)
	default:
		return 0, false
	}

	ttl := minTTL(msg.Answer)
	if ttl == 0 {
		return 0, false
	}
	return time.Duration(ttl) * time.Second, true
}

func hasAnswerType(rrs []mdns.RR, qtype uint16) bool {
	for _, rr := range rrs {
		if rr == nil {
			continue
		}
		if rr.Header().Rrtype == mdns.TypeOPT {
			continue
		}
		if qtype == mdns.TypeANY || rr.Header().Rrtype == qtype {
			return true
		}
	}
	return false
}

func minTTL(rrs []mdns.RR) uint32 {
	var min uint32
	found := false
	for _, rr := range rrs {
		if rr == nil || rr.Header().Rrtype == mdns.TypeOPT {
			continue
		}
		ttl := rr.Header().Ttl
		if !found || ttl < min {
			min = ttl
			found = true
		}
	}
	if !found {
		return 0
	}
	return min
}

func negativeTTL(msg *mdns.Msg) (time.Duration, bool) {
	soa := findSOA(msg.Ns)
	if soa == nil {
		soa = findSOA(msg.Answer)
	}
	if soa == nil {
		return defaultNegativeTTL, true
	}

	// RFC 2308: the negative TTL is the minimum of the SOA minimum field and
	// the SOA record's own TTL.
	ttl := soa.Minttl
	if soa.Hdr.Ttl < ttl {
		ttl = soa.Hdr.Ttl
	}
	if ttl == 0 {
		return 0, false
	}
	return time.Duration(ttl) * time.Second, true
}

func findSOA(rrs []mdns.RR) *mdns.SOA {
	for _, rr := range rrs {
		if soa, ok := rr.(*mdns.SOA); ok {
			return soa
		}
	}
	return nil
}

func withoutOPT(rrs []mdns.RR) []mdns.RR {
	if len(rrs) == 0 {
		return rrs
	}
	out := make([]mdns.RR, 0, len(rrs))
	for _, rr := range rrs {
		if rr == nil || rr.Header().Rrtype == mdns.TypeOPT {
			continue
		}
		out = append(out, rr)
	}
	return out
}

func decrementTTLs(msg *mdns.Msg, elapsed uint32) {
	if elapsed == 0 {
		return
	}
	for _, section := range [][]mdns.RR{msg.Answer, msg.Ns, msg.Extra} {
		for _, rr := range section {
			if rr == nil || rr.Header().Rrtype == mdns.TypeOPT {
				continue
			}
			if rr.Header().Ttl > elapsed {
				rr.Header().Ttl -= elapsed
			} else {
				rr.Header().Ttl = 0
			}
		}
	}
}
