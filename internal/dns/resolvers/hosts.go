// Package resolvers implements the DNS resolver providers used by the
// intelligent DNS service: hosts, DHCP leases, system upstreams, and a chain
// that tries them in order.
package resolvers

import (
	"context"
	"net"
	"net/netip"
	"os"
	"strings"

	mdns "github.com/miekg/dns"

	tgdns "tesla-gateway/internal/dns"
)

const (
	// DefaultHostsPath is the default hosts file path.
	DefaultHostsPath = "/etc/hosts"
	defaultHostsTTL  = 60
)

// HostsResolver answers A and AAAA questions from a hosts file. It re-reads
// the file on every lookup so updates are visible without a restart.
type HostsResolver struct {
	path string
	ttl  uint32
}

// HostsOption configures a HostsResolver.
type HostsOption func(*HostsResolver)

// WithHostsTTL overrides the TTL used for hosts records.
func WithHostsTTL(ttl uint32) HostsOption {
	return func(r *HostsResolver) {
		r.ttl = ttl
	}
}

// NewHostsResolver creates a hosts-file resolver. An empty path uses
// /etc/hosts.
func NewHostsResolver(path string, opts ...HostsOption) *HostsResolver {
	if strings.TrimSpace(path) == "" {
		path = DefaultHostsPath
	}
	r := &HostsResolver{path: path, ttl: defaultHostsTTL}
	for _, opt := range opts {
		if opt != nil {
			opt(r)
		}
	}
	return r
}

// Name implements tgdns.Resolver.
func (r *HostsResolver) Name() string { return "hosts" }

// Path returns the configured hosts file path.
func (r *HostsResolver) Path() string {
	if r == nil {
		return ""
	}
	return r.path
}

// Lookup implements tgdns.Resolver.
func (r *HostsResolver) Lookup(ctx context.Context, q mdns.Question) ([]mdns.RR, bool, error) {
	if r == nil {
		return nil, false, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	if q.Qtype != mdns.TypeA && q.Qtype != mdns.TypeAAAA {
		return nil, false, nil
	}
	if q.Qclass != mdns.ClassINET && q.Qclass != mdns.ClassANY {
		return nil, false, nil
	}

	data, err := os.ReadFile(r.path)
	if err != nil {
		return nil, false, err
	}

	records := parseHosts(data, q.Name, q.Qtype, r.ttl)
	if len(records) == 0 {
		return nil, false, nil
	}
	return records, true, nil
}

func parseHosts(data []byte, qname string, qtype uint16, ttl uint32) []mdns.RR {
	want := strings.TrimSuffix(qname, ".")
	var records []mdns.RR

	for _, line := range strings.Split(string(data), "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		addr, err := netip.ParseAddr(fields[0])
		if err != nil || addr.Zone() != "" {
			continue
		}

		nameMatches := false
		for _, name := range fields[1:] {
			if strings.EqualFold(strings.TrimSuffix(name, "."), want) {
				nameMatches = true
				break
			}
		}
		if !nameMatches {
			continue
		}

		switch qtype {
		case mdns.TypeA:
			if !addr.Is4() {
				continue
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
		case mdns.TypeAAAA:
			if !addr.Is6() {
				continue
			}
			records = append(records, &mdns.AAAA{
				Hdr: mdns.RR_Header{
					Name:   mdns.Fqdn(qname),
					Rrtype: mdns.TypeAAAA,
					Class:  mdns.ClassINET,
					Ttl:    ttl,
				},
				AAAA: net.IP(addr.AsSlice()),
			})
		}
	}
	return records
}

var _ tgdns.Resolver = (*HostsResolver)(nil)
