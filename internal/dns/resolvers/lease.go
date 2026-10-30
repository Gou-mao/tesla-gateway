package resolvers

import (
	"context"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	mdns "github.com/miekg/dns"

	tgdns "tesla-gateway/internal/dns"
)

const (
	// DefaultLeasePath is the default dnsmasq DHCP lease file.
	DefaultLeasePath = "/tmp/dhcp.leases"
	defaultLeaseTTL  = 60
)

// LeaseResolver answers A questions from a dnsmasq lease file with the format:
//
//	expiry mac ip hostname clientid
//
// Expired leases are ignored. The record TTL is the remaining lease time (or
// a small default for an unlimited lease).
type LeaseResolver struct {
	path string
	now  func() time.Time
}

// LeaseOption configures a LeaseResolver.
type LeaseOption func(*LeaseResolver)

// WithLeaseClock replaces the lease resolver clock. It is primarily useful in
// tests.
func WithLeaseClock(now func() time.Time) LeaseOption {
	return func(r *LeaseResolver) {
		if now != nil {
			r.now = now
		}
	}
}

// NewLeaseResolver creates a dnsmasq lease resolver. An empty path uses
// /tmp/dhcp.leases.
func NewLeaseResolver(path string, opts ...LeaseOption) *LeaseResolver {
	if strings.TrimSpace(path) == "" {
		path = DefaultLeasePath
	}
	r := &LeaseResolver{path: path, now: time.Now}
	for _, opt := range opts {
		if opt != nil {
			opt(r)
		}
	}
	return r
}

// Name implements tgdns.Resolver.
func (r *LeaseResolver) Name() string { return "lease" }

// Path returns the configured lease file path.
func (r *LeaseResolver) Path() string {
	if r == nil {
		return ""
	}
	return r.path
}

// Lookup implements tgdns.Resolver.
func (r *LeaseResolver) Lookup(ctx context.Context, q mdns.Question) ([]mdns.RR, bool, error) {
	if r == nil {
		return nil, false, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	if q.Qtype != mdns.TypeA {
		return nil, false, nil
	}
	if q.Qclass != mdns.ClassINET && q.Qclass != mdns.ClassANY {
		return nil, false, nil
	}

	data, err := os.ReadFile(r.path)
	if err != nil {
		return nil, false, err
	}

	records := parseLeases(data, q.Name, r.now())
	if len(records) == 0 {
		return nil, false, nil
	}
	return records, true, nil
}

func parseLeases(data []byte, qname string, now time.Time) []mdns.RR {
	want := strings.TrimSuffix(qname, ".")
	nowUnix := now.Unix()
	var records []mdns.RR

	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		expiry, err := strconv.ParseInt(fields[0], 10, 64)
		if err != nil {
			continue
		}
		hostname := strings.TrimSuffix(fields[3], ".")
		if hostname == "" || hostname == "*" || !strings.EqualFold(hostname, want) {
			continue
		}
		if expiry > 0 && expiry <= nowUnix {
			continue
		}

		addr, err := netip.ParseAddr(fields[2])
		if err != nil || !addr.Is4() {
			continue
		}

		ttl := uint32(defaultLeaseTTL)
		if expiry > nowUnix {
			if remaining := expiry - nowUnix; remaining > 0 {
				ttl = uint32(remaining)
			}
		}

		records = append(records, &mdns.A{
			Hdr: mdns.RR_Header{
				Name:   mdns.Fqdn(qname),
				Rrtype: mdns.TypeA,
				Class:  mdns.ClassINET,
				Ttl:    ttl,
			},
			A: net.IP(addr.AsSlice()),
		})
	}
	return records
}

var _ tgdns.Resolver = (*LeaseResolver)(nil)
