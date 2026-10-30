package resolvers

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	mdns "github.com/miekg/dns"

	tgdns "tesla-gateway/internal/dns"
)

const defaultUpstreamTimeout = 5 * time.Second

// SystemResolver forwards questions to a list of upstream DNS servers. UDP is
// tried first; a truncated response is retried over TCP. If an upstream fails,
// the next one is tried.
type SystemResolver struct {
	upstream []string
	timeout  time.Duration
}

// SystemOption configures a SystemResolver.
type SystemOption func(*SystemResolver)

// WithSystemTimeout sets the per-upstream exchange timeout.
func WithSystemTimeout(timeout time.Duration) SystemOption {
	return func(r *SystemResolver) {
		if timeout > 0 {
			r.timeout = timeout
		}
	}
}

// NewSystemResolver creates a forwarding resolver. Upstreams may be bare IP
// addresses (port 53 is assumed), hostnames, or host:port pairs.
func NewSystemResolver(upstream []string, opts ...SystemOption) (*SystemResolver, error) {
	normalized := make([]string, 0, len(upstream))
	for i, raw := range upstream {
		addr, err := normalizeUpstream(raw)
		if err != nil {
			return nil, fmt.Errorf("dns: upstream[%d] %q: %w", i, raw, err)
		}
		normalized = append(normalized, addr)
	}
	if len(normalized) == 0 {
		return nil, errors.New("dns: system resolver requires at least one upstream")
	}

	r := &SystemResolver{
		upstream: normalized,
		timeout:  defaultUpstreamTimeout,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(r)
		}
	}
	return r, nil
}

// Name implements tgdns.Resolver.
func (r *SystemResolver) Name() string { return "system" }

// Upstreams returns the normalized upstream addresses.
func (r *SystemResolver) Upstreams() []string {
	if r == nil {
		return nil
	}
	return append([]string(nil), r.upstream...)
}

// Lookup implements tgdns.Resolver. Any valid upstream response is considered
// terminal, including NXDOMAIN/NODATA, so the chain does not fall through to
// another provider after the system resolver has answered.
func (r *SystemResolver) Lookup(ctx context.Context, q mdns.Question) ([]mdns.RR, bool, error) {
	if r == nil {
		return nil, false, nil
	}

	req := new(mdns.Msg)
	req.SetQuestion(mdns.Fqdn(q.Name), q.Qtype)
	req.Question[0].Qclass = q.Qclass

	resp, err := r.ExchangeMessage(ctx, req)
	if err != nil {
		return nil, false, err
	}
	return resp.Answer, true, nil
}

// ExchangeMessage implements tgdns.MessageResolver. It copies req for each
// upstream attempt, assigns a fresh message ID, and preserves EDNS0 and DNSSEC
// flags from the original query.
func (r *SystemResolver) ExchangeMessage(ctx context.Context, req *mdns.Msg) (*mdns.Msg, error) {
	if r == nil {
		return nil, errors.New("dns: nil system resolver")
	}
	if req == nil || len(req.Question) == 0 {
		return nil, errors.New("dns: upstream query has no question")
	}

	var errs []error
	for _, upstream := range r.upstream {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		resp, err := r.exchange(ctx, req, upstream, "udp")
		if err != nil {
			errs = append(errs, fmt.Errorf("%s udp: %w", upstream, err))
			continue
		}

		if resp.Truncated {
			tcpResp, tcpErr := r.exchange(ctx, req, upstream, "tcp")
			if tcpErr != nil {
				errs = append(errs, fmt.Errorf("%s tcp after truncation: %w", upstream, tcpErr))
				continue
			}
			resp = tcpResp
		}

		switch resp.Rcode {
		case mdns.RcodeServerFailure, mdns.RcodeRefused:
			errs = append(errs, fmt.Errorf("%s: response %s", upstream, mdns.RcodeToString[resp.Rcode]))
			continue
		}
		return resp, nil
	}

	if len(errs) == 0 {
		return nil, errors.New("dns: no upstream resolvers configured")
	}
	return nil, fmt.Errorf("dns: all upstream resolvers failed: %w", errors.Join(errs...))
}

func (r *SystemResolver) exchange(ctx context.Context, req *mdns.Msg, upstream, network string) (*mdns.Msg, error) {
	query := req.Copy()
	query.Id = mdns.Id()
	query.Response = false
	query.Compress = true

	client := &mdns.Client{
		Net:         network,
		Timeout:     r.timeout,
		DialTimeout: r.timeout,
	}
	resp, _, err := client.ExchangeContext(ctx, query, upstream)
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, errors.New("empty upstream response")
	}
	return resp, nil
}

func normalizeUpstream(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", errors.New("empty upstream address")
	}

	if host, port, err := net.SplitHostPort(s); err == nil {
		if strings.TrimSpace(host) == "" {
			return "", errors.New("missing upstream host")
		}
		if err := validatePort(port); err != nil {
			return "", err
		}
		return net.JoinHostPort(host, port), nil
	}

	// Bare IPv6 addresses (and scoped IPv6) need brackets before adding :53.
	if addr, err := netip.ParseAddr(s); err == nil {
		return net.JoinHostPort(addr.String(), "53"), nil
	}
	if strings.Contains(s, ":") {
		return "", fmt.Errorf("invalid upstream address %q", raw)
	}
	return net.JoinHostPort(s, "53"), nil
}

func validatePort(port string) error {
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("invalid upstream port %q", port)
	}
	return nil
}

var (
	_ tgdns.Resolver        = (*SystemResolver)(nil)
	_ tgdns.MessageResolver = (*SystemResolver)(nil)
)
