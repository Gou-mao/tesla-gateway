package resolvers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	mdns "github.com/miekg/dns"

	tgdns "tesla-gateway/internal/dns"
	"tesla-gateway/internal/logx"
)

const (
	defaultUpstreamTimeout = 5 * time.Second
	defaultQueryBudget     = 10 * time.Second
	minUpstreamAttempt     = time.Second
	defaultDHCPCacheTTL    = 10 * time.Second
	ubusDumpTimeout        = 3 * time.Second

	upstreamSourceCustom = "custom"
	upstreamSourceDHCP   = "dhcp"
)

// ubusDump runs the OpenWrt ubus query used to discover DHCP-provided DNS
// servers. It is a variable so tests can replace it with a fixture.
var ubusDump = runUbusDump

// upstreamEntry is one configured or dynamically expanded upstream server.
// DHCP entries are expanded to zero or more IP entries when queried.
type upstreamEntry struct {
	address string
	display string
	source  string
}

// SystemResolver forwards questions to an ordered list of upstream DNS
// servers. UDP is tried first; a truncated response is retried over TCP. If an
// upstream fails, the next one is tried. The "dhcp" (alias "auto") keyword is
// expanded in place to the DNS servers currently assigned to the upstream
// interface, as reported by ubus.
type SystemResolver struct {
	upstream []upstreamEntry
	timeout  time.Duration

	ubusDump func() ([]byte, error)
	now      func() time.Time
	dhcpTTL  time.Duration
	logger   *logx.Logger

	dhcpMu        sync.Mutex
	dhcpServers   []string
	dhcpInterface string
	dhcpCachedAt  time.Time
	dhcpCached    bool

	logMu  sync.Mutex
	logged map[string]struct{}
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

// WithSystemUbusDump injects the ubus dump command. It is primarily useful in
// tests, where a fixture can stand in for an OpenWrt system.
func WithSystemUbusDump(dump func() ([]byte, error)) SystemOption {
	return func(r *SystemResolver) {
		if dump != nil {
			r.ubusDump = dump
		}
	}
}

// WithSystemDHCPCacheTTL overrides how long a DHCP DNS lookup is cached.
func WithSystemDHCPCacheTTL(ttl time.Duration) SystemOption {
	return func(r *SystemResolver) {
		if ttl > 0 {
			r.dhcpTTL = ttl
		}
	}
}

// WithSystemClock injects the clock used by the DHCP cache.
func WithSystemClock(now func() time.Time) SystemOption {
	return func(r *SystemResolver) {
		if now != nil {
			r.now = now
		}
	}
}

// WithSystemLogger sets the logger used to record DHCP expansion and the
// upstream actually selected for a query.
func WithSystemLogger(logger *logx.Logger) SystemOption {
	return func(r *SystemResolver) {
		if logger != nil {
			r.logger = logger
		}
	}
}

// NewSystemResolver creates a forwarding resolver. Upstreams are kept in the
// configured order. Each item may be a bare IP address (port 53 is assumed),
// a host:port pair, or the keyword "dhcp" (alias "auto"). The keyword expands
// to the DHCP-provided DNS servers of the current upstream interface.
func NewSystemResolver(upstream []string, opts ...SystemOption) (*SystemResolver, error) {
	entries := make([]upstreamEntry, 0, len(upstream))
	for i, raw := range upstream {
		value := strings.TrimSpace(raw)
		if isDHCPUpstream(value) {
			entries = append(entries, upstreamEntry{source: upstreamSourceDHCP})
			continue
		}

		addr, err := normalizeUpstream(value)
		if err != nil {
			return nil, fmt.Errorf("dns: upstream[%d] %q: %w", i, raw, err)
		}
		entries = append(entries, upstreamEntry{
			address: addr,
			display: displayUpstream(addr),
			source:  upstreamSourceCustom,
		})
	}
	if len(entries) == 0 {
		return nil, errors.New("dns: system resolver requires at least one upstream")
	}

	r := &SystemResolver{
		upstream: entries,
		timeout:  defaultUpstreamTimeout,
		ubusDump: ubusDump,
		now:      time.Now,
		dhcpTTL:  defaultDHCPCacheTTL,
		logged:   make(map[string]struct{}),
	}
	for _, opt := range opts {
		if opt != nil {
			opt(r)
		}
	}
	return r, nil
}

func isDHCPUpstream(raw string) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "dhcp", "auto":
		return true
	default:
		return false
	}
}

// Name implements tgdns.Resolver.
func (r *SystemResolver) Name() string { return "system" }

// Upstreams returns the normalized configured upstream addresses. DHCP
// keywords are returned as the literal "dhcp" placeholder; use
// EffectiveUpstreams to see the current expansion.
func (r *SystemResolver) Upstreams() []string {
	if r == nil {
		return nil
	}
	upstream := make([]string, 0, len(r.upstream))
	for _, entry := range r.upstream {
		if entry.source == upstreamSourceDHCP {
			upstream = append(upstream, upstreamSourceDHCP)
			continue
		}
		upstream = append(upstream, entry.address)
	}
	return upstream
}

// EffectiveUpstreams returns the ordered IP list currently used for queries,
// with every "dhcp" entry expanded in place. It returns an empty slice when
// only DHCP entries are configured and none can be resolved (for example on a
// development machine without ubus).
func (r *SystemResolver) EffectiveUpstreams() []string {
	if r == nil {
		return nil
	}
	entries := r.effectiveUpstreams()
	effective := make([]string, 0, len(entries))
	for _, entry := range entries {
		effective = append(effective, entry.display)
	}
	return effective
}

func (r *SystemResolver) effectiveUpstreams() []upstreamEntry {
	entries := make([]upstreamEntry, 0, len(r.upstream))
	now := r.now()
	for _, entry := range r.upstream {
		if entry.source != upstreamSourceDHCP {
			entries = append(entries, entry)
			continue
		}

		for _, server := range r.dhcpDNSServers(now) {
			addr, err := normalizeUpstream(server)
			if err != nil {
				continue
			}
			entries = append(entries, upstreamEntry{
				address: addr,
				display: displayUpstream(addr),
				source:  upstreamSourceDHCP,
			})
		}
	}
	return entries
}

// DHCPStatus returns the DHCP DNS servers currently used to expand the "dhcp"
// upstream placeholder and the interface they were learned from. It shares the
// regular DHCP cache, so the lookup runs at most once per dhcpTTL regardless of
// how often callers (for example the stats writer) read the status.
func (r *SystemResolver) DHCPStatus() ([]string, string) {
	if r == nil || !r.hasDHCPUpstream() {
		return nil, ""
	}

	now := r.now()
	r.dhcpMu.Lock()
	defer r.dhcpMu.Unlock()

	r.refreshDHCPDNSLocked(now)
	return append([]string(nil), r.dhcpServers...), r.dhcpInterface
}

func (r *SystemResolver) hasDHCPUpstream() bool {
	for _, entry := range r.upstream {
		if entry.source == upstreamSourceDHCP {
			return true
		}
	}
	return false
}

// dhcpDNSServers returns the cached DHCP DNS list, refreshing it at most once
// per dhcpTTL. Errors and empty results are cached too, so a non-OpenWrt host
// does not run ubus on every DNS query.
func (r *SystemResolver) dhcpDNSServers(now time.Time) []string {
	r.dhcpMu.Lock()
	defer r.dhcpMu.Unlock()

	r.refreshDHCPDNSLocked(now)
	return append([]string(nil), r.dhcpServers...)
}

// refreshDHCPDNSLocked refreshes the cache when it is expired. The caller must
// hold dhcpMu.
func (r *SystemResolver) refreshDHCPDNSLocked(now time.Time) {
	if r.dhcpCached && now.Sub(r.dhcpCachedAt) < r.dhcpTTL {
		return
	}

	servers, iface := r.fetchDHCPDNS()
	r.dhcpCached = true
	r.dhcpCachedAt = now
	r.dhcpServers = append([]string(nil), servers...)
	r.dhcpInterface = iface

	switch {
	case len(servers) > 0:
		r.logger.Info("dns dhcp upstream resolved", logx.Fields{
			"interface": iface,
			"servers":   servers,
			"cache_ttl": r.dhcpTTL.String(),
		})
	default:
		r.logger.Debug("dns dhcp upstream unavailable; skipping dhcp entry", logx.Fields{
			"interface": iface,
		})
	}
}

func (r *SystemResolver) fetchDHCPDNS() ([]string, string) {
	if r.ubusDump == nil {
		return nil, ""
	}
	data, err := r.ubusDump()
	if err != nil {
		r.logger.Debug("dns dhcp lookup failed; skipping dhcp entry", logx.Fields{
			"error": err.Error(),
		})
		return nil, ""
	}
	servers, iface, err := parseUbusDNSServers(data)
	if err != nil {
		r.logger.Debug("dns dhcp dump parse failed; skipping dhcp entry", logx.Fields{
			"error": err.Error(),
		})
		return nil, ""
	}
	return servers, iface
}

func (r *SystemResolver) logSelected(entry upstreamEntry) {
	if r.logger == nil {
		return
	}
	key := entry.source + "|" + entry.display

	r.logMu.Lock()
	_, seen := r.logged[key]
	if !seen {
		r.logged[key] = struct{}{}
	}
	r.logMu.Unlock()

	fields := logx.Fields{
		"upstream": entry.display,
		"source":   entry.source,
	}
	if seen {
		r.logger.Debug("dns upstream selected", fields)
		return
	}
	r.logger.Info("dns upstream selected", fields)
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

	upstreams := r.effectiveUpstreams()
	if len(upstreams) == 0 {
		return nil, errors.New("dns: no upstream resolvers configured")
	}

	// Keep the whole exchange within one budget even when the caller supplies a
	// longer (or no) deadline. A shorter caller deadline is preserved.
	if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > defaultQueryBudget {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, defaultQueryBudget)
		defer cancel()
	}
	deadline, _ := ctx.Deadline()

	var errs []error
	for i, upstream := range upstreams {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		remaining := time.Until(deadline)
		if remaining <= 0 {
			errs = append(errs, fmt.Errorf("query budget exhausted: %w", context.DeadlineExceeded))
			break
		}

		// Divide what is left fairly between this upstream and all later ones,
		// so an unresponsive server cannot consume the entire budget.
		attemptTimeout := r.attemptTimeout(remaining, len(upstreams)-i)
		attemptCtx, cancel := context.WithTimeout(ctx, attemptTimeout)
		resp, err := r.exchange(attemptCtx, req, upstream.address, "udp")
		if err != nil {
			cancel()
			errs = append(errs, fmt.Errorf("%s (%s) udp: %w", upstream.display, upstream.source, err))
			continue
		}

		if resp.Truncated {
			tcpResp, tcpErr := r.exchange(attemptCtx, req, upstream.address, "tcp")
			if tcpErr != nil {
				cancel()
				errs = append(errs, fmt.Errorf(
					"%s (%s) tcp after truncation: %w",
					upstream.display, upstream.source, tcpErr,
				))
				continue
			}
			resp = tcpResp
		}
		cancel()

		switch resp.Rcode {
		case mdns.RcodeServerFailure, mdns.RcodeRefused:
			errs = append(errs, fmt.Errorf(
				"%s (%s): response %s",
				upstream.display, upstream.source, mdns.RcodeToString[resp.Rcode],
			))
			continue
		}
		r.logSelected(upstream)
		return resp, nil
	}

	if len(errs) == 0 {
		return nil, errors.New("dns: no upstream resolvers configured")
	}
	return nil, fmt.Errorf("dns: all upstream resolvers failed: %w", errors.Join(errs...))
}

// attemptTimeout returns the time to give one upstream. It starts from an even
// share of the remaining query budget, is capped by the configured per-upstream
// timeout, and keeps a small floor when doing so cannot starve later upstreams.
func (r *SystemResolver) attemptTimeout(remaining time.Duration, remainingUpstreams int) time.Duration {
	if remaining <= 0 || remainingUpstreams <= 0 {
		return remaining
	}

	timeout := remaining / time.Duration(remainingUpstreams)
	if r.timeout > 0 && timeout > r.timeout {
		timeout = r.timeout
	}

	floor := minUpstreamAttempt
	if r.timeout > 0 && r.timeout < floor {
		floor = r.timeout
	}
	if timeout < floor && floor*time.Duration(remainingUpstreams) <= remaining {
		timeout = floor
	}
	if timeout <= 0 || timeout > remaining {
		timeout = remaining
	}
	return timeout
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

// runUbusDump queries OpenWrt for the current network interface state. On a
// non-OpenWrt system (or when ubus is not installed) it returns an error and
// the resolver simply skips the DHCP entry.
func runUbusDump() ([]byte, error) {
	path, err := exec.LookPath("ubus")
	if err != nil {
		return nil, fmt.Errorf("ubus is not available: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), ubusDumpTimeout)
	defer cancel()

	data, err := exec.CommandContext(ctx, path, "call", "network.interface", "dump").Output()
	if err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("ubus call timed out: %w", ctx.Err())
		}
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			if detail := strings.TrimSpace(string(exitErr.Stderr)); detail != "" {
				return nil, fmt.Errorf("ubus call failed: %s", detail)
			}
		}
		return nil, fmt.Errorf("ubus call failed: %w", err)
	}
	return data, nil
}

type ubusDumpDocument struct {
	Interfaces ubusInterfaceList `json:"interface"`
}

type ubusInterface struct {
	Interface    ubusScalar     `json:"interface"`
	Up           ubusBool       `json:"up"`
	DNSServers   ubusStringList `json:"dns-server"`
	Route        ubusRouteList  `json:"route"`
	DefaultRoute ubusStringList `json:"default_route"`
}

// ubusRoute keeps only the fields needed for default-route detection plus
// mask. OpenWrt emits route mask as a numeric prefix length on current
// releases, while older dumps used a string. Other route fields (table,
// metric, mtu, source, ...) are intentionally not declared: encoding/json
// ignores unknown fields, so their varying types cannot break the parse.
type ubusRoute struct {
	Target  ubusScalar `json:"target"`
	Netmask ubusScalar `json:"netmask"`
	Mask    ubusScalar `json:"mask"`
}

// ubusScalar decodes any JSON scalar into its textual form. OpenWrt field types
// are not stable across releases and protocols (for example route mask/table
// are numbers while netmask/source are strings), so a single unexpected type
// must not fail the whole dump. Non-scalar values decode to the empty string.
type ubusScalar string

func (s *ubusScalar) UnmarshalJSON(data []byte) error {
	*s = ubusScalar(ubusScalarText(data))
	return nil
}

func (s ubusScalar) String() string { return string(s) }

func ubusScalarText(data []byte) string {
	value := strings.TrimSpace(string(data))
	if value == "" || value == "null" {
		return ""
	}

	if value[0] == '"' {
		var text string
		if err := json.Unmarshal([]byte(value), &text); err == nil {
			return text
		}
		return ""
	}
	if value == "true" || value == "false" {
		return value
	}

	var number json.Number
	if err := json.Unmarshal([]byte(value), &number); err == nil {
		return number.String()
	}
	return ""
}

// ubusBool accepts booleans as well as the numeric and string spellings some
// OpenWrt versions use for "up".
type ubusBool bool

func (b *ubusBool) UnmarshalJSON(data []byte) error {
	switch strings.ToLower(ubusScalarText(data)) {
	case "true", "1", "yes", "on", "up":
		*b = true
	default:
		*b = false
	}
	return nil
}

// ubusStringList accepts a JSON string, number, or an array of such values.
// OpenWrt normally emits arrays of strings for dns-server, but accepting
// scalars and skipping unusable elements keeps older or hand-written fixtures
// working. It never returns a type error: dns-server is advisory data.
type ubusStringList []string

func (l *ubusStringList) UnmarshalJSON(data []byte) error {
	*l = nil

	var items []json.RawMessage
	if err := json.Unmarshal(data, &items); err == nil {
		for _, item := range items {
			if value := ubusScalarText(item); value != "" {
				*l = append(*l, value)
			}
		}
		return nil
	}

	if value := ubusScalarText(data); value != "" {
		*l = []string{value}
	}
	return nil
}

// ubusRouteList tolerates route entries with an unexpected shape by skipping
// them instead of failing the entire interface dump.
type ubusRouteList []ubusRoute

func (l *ubusRouteList) UnmarshalJSON(data []byte) error {
	*l = nil

	var items []json.RawMessage
	if err := json.Unmarshal(data, &items); err != nil {
		return nil
	}
	for _, item := range items {
		var route ubusRoute
		if err := json.Unmarshal(item, &route); err != nil {
			continue
		}
		*l = append(*l, route)
	}
	return nil
}

// ubusInterfaceList tolerates interface entries with an unexpected shape by
// skipping them instead of failing the entire dump.
type ubusInterfaceList []ubusInterface

func (l *ubusInterfaceList) UnmarshalJSON(data []byte) error {
	*l = nil

	var items []json.RawMessage
	if err := json.Unmarshal(data, &items); err != nil {
		return nil
	}
	for _, item := range items {
		var iface ubusInterface
		if err := json.Unmarshal(item, &iface); err != nil {
			continue
		}
		*l = append(*l, iface)
	}
	return nil
}

// parseUbusDNSServers extracts the DHCP-provided DNS servers from an OpenWrt
// `ubus call network.interface dump` response. Interfaces with a default route
// win; otherwise the first up interface with usable dns-server values is used.
// The returned interface name is informational and may be empty.
func parseUbusDNSServers(data []byte) ([]string, string, error) {
	var document ubusDumpDocument
	if err := json.Unmarshal(data, &document); err != nil {
		return nil, "", fmt.Errorf("parse ubus network.interface dump: %w", err)
	}

	var fallbackServers []string
	var fallbackInterface string

	for i := range document.Interfaces {
		iface := &document.Interfaces[i]
		if !iface.Up {
			continue
		}

		servers := normalizeDNSServers(iface.DNSServers)
		if len(servers) == 0 {
			continue
		}

		if hasDefaultRoute(*iface) {
			return servers, iface.Interface.String(), nil
		}
		if fallbackServers == nil {
			fallbackServers = servers
			fallbackInterface = iface.Interface.String()
		}
	}

	if fallbackServers != nil {
		return fallbackServers, fallbackInterface, nil
	}
	return nil, "", nil
}

func normalizeDNSServers(values []string) []string {
	servers := make([]string, 0, len(values))
	for _, raw := range values {
		value := strings.TrimSpace(raw)
		if value == "" {
			continue
		}
		addr, err := netip.ParseAddr(value)
		if err != nil {
			continue
		}
		servers = append(servers, addr.String())
	}
	return servers
}

func hasDefaultRoute(iface ubusInterface) bool {
	for _, route := range iface.DefaultRoute {
		switch strings.TrimSpace(route) {
		case "0.0.0.0/0", "::/0":
			return true
		}
	}

	for _, route := range iface.Route {
		// Use the textual target/netmask pair only. route.mask is a numeric
		// prefix length in real OpenWrt dumps and must not drive this check.
		target := strings.TrimSpace(route.Target.String())
		netmask := strings.TrimSpace(route.Netmask.String())

		switch target {
		case "0.0.0.0/0", "::/0", "default":
			return true
		case "0.0.0.0":
			if netmask == "0.0.0.0" {
				return true
			}
		case "::":
			if netmask == "::" {
				return true
			}
		}
	}
	return false
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

func displayUpstream(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	if port == "53" {
		return host
	}
	return net.JoinHostPort(host, port)
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
