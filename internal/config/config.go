// Package config loads and validates the Tesla Gateway YAML configuration.
package config

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"tesla-gateway/internal/mapping"
)

const (
	// DefaultPath is the default configuration file path.
	DefaultPath = "/etc/tesla-gateway/config.yaml"
	// DefaultStatsPath is the default runtime statistics file published for
	// management frontends such as LuCI.
	DefaultStatsPath = "/var/run/tesla-gateway/stats.json"
)

// DefaultLocalClientPrefix is the local Tesla client network. It is excluded
// from the nftables redirect set so local clients are never intercepted.
const DefaultLocalClientPrefix = "100.64.0.0/24"

// Config is the top-level Tesla Gateway configuration.
type Config struct {
	// MappingStrategy selects the mapping implementation. Empty means prefix.
	MappingStrategy string `yaml:"mapping_strategy"`
	// Mappings is the list of real-to-mapped prefix replacements.
	Mappings []Mapping `yaml:"mappings"`
	// RealPrefixes declares real, in-use network prefixes. Mapped (to)
	// prefixes must not overlap them.
	RealPrefixes []string `yaml:"real_prefixes"`
	// StatsPath is where runtime statistics are published as JSON. Empty uses
	// DefaultStatsPath.
	StatsPath string `yaml:"stats_path"`

	DNS   DNSConfig   `yaml:"dns"`
	Proxy ProxyConfig `yaml:"proxy"`
	Log   LogConfig   `yaml:"log"`

	// Strategy is compiled and validated by Load. It is not part of YAML.
	Strategy mapping.MappingStrategy `yaml:"-"`

	// dnsUpstreamSet records whether dns.upstream was present in the YAML,
	// even when it was an explicit empty list.
	dnsUpstreamSet bool
}

// Mapping is one real-to-mapped prefix pair in CIDR notation.
type Mapping struct {
	From string `yaml:"from"`
	To   string `yaml:"to"`
}

// DNSConfig configures the DNS service.
type DNSConfig struct {
	Listen    string   `yaml:"listen"`
	Resolvers []string `yaml:"resolvers"`
	// Upstream is an ordered priority list. Each item is either an IPv4/IPv6
	// address or the keyword "dhcp" (alias "auto"), which expands in place to
	// the DNS servers currently handed out by DHCP on the upstream interface.
	Upstream []string `yaml:"upstream"`
	// HostsPath and LeasePath default to /etc/hosts and /tmp/dhcp.leases.
	HostsPath string `yaml:"hosts_path"`
	LeasePath string `yaml:"lease_path"`
	ClampTTL  int    `yaml:"clamp_ttl"`
	CacheMax  int    `yaml:"cache_max"`
	DropAAAA  bool   `yaml:"drop_aaaa"`
}

// ProxyConfig configures the transparent proxy.
type ProxyConfig struct {
	Mode        string        `yaml:"mode"`
	TCPListen   string        `yaml:"tcp_listen"`
	KeepAlive   time.Duration `yaml:"-"`
	MaxConns    int           `yaml:"max_conns"`
	IdleTimeout time.Duration `yaml:"-"`
	// ApplyNft installs the nftables redirect rules at startup and removes
	// them on shutdown. It is off by default so local development leaves the
	// host firewall untouched.
	ApplyNft bool `yaml:"apply_nft"`
	// LocalClientPrefix is excluded from the nft redirect set. Empty uses
	// DefaultLocalClientPrefix.
	LocalClientPrefix string `yaml:"local_client_prefix"`
}

// LogConfig configures structured logging.
type LogConfig struct {
	Format string `yaml:"format"`
	Level  string `yaml:"level"`
}

// Load reads, parses, compiles, and validates the configuration at path.
// An empty path uses DefaultPath.
func Load(path string) (*Config, error) {
	if strings.TrimSpace(path) == "" {
		path = DefaultPath
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}
	cfg, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("config: %s: %w", path, err)
	}
	return cfg, nil
}

// Parse parses and validates a YAML configuration document. It builds the
// configured mapping strategy and calls Validate on it.
func Parse(data []byte) (*Config, error) {
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse yaml: %w", err)
	}
	cfg.dnsUpstreamSet = dnsUpstreamPresent(data)
	cfg.StatsPath = strings.TrimSpace(cfg.StatsPath)
	if cfg.StatsPath == "" {
		cfg.StatsPath = DefaultStatsPath
	}
	cfg.Proxy.applyDefaults()
	if err := cfg.validateDNSUpstream(); err != nil {
		return nil, err
	}
	if err := cfg.compileMapping(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// dnsUpstreamPresent reports whether the YAML document explicitly contains
// dns.upstream. This lets an omitted list stay optional for configurations
// that disable DNS, while an explicit empty list is still rejected.
func dnsUpstreamPresent(data []byte) bool {
	var document struct {
		DNS struct {
			Upstream yaml.Node `yaml:"upstream"`
		} `yaml:"dns"`
	}
	if err := yaml.Unmarshal(data, &document); err != nil {
		return false
	}
	return document.DNS.Upstream.Kind != 0
}

func isDHCPUpstream(raw string) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "dhcp", "auto":
		return true
	default:
		return false
	}
}

func (c *Config) validateDNSUpstream() error {
	if len(c.DNS.Upstream) == 0 {
		// An explicit empty list is always invalid. An omitted list is only
		// required when the DNS listener is enabled.
		if c.dnsUpstreamSet || strings.TrimSpace(c.DNS.Listen) != "" {
			return errors.New(`dns.upstream: at least one IPv4/IPv6 address or "dhcp" is required`)
		}
		return nil
	}

	valid := 0
	for i, raw := range c.DNS.Upstream {
		value := strings.TrimSpace(raw)
		if value == "" {
			return fmt.Errorf(`dns.upstream[%d]: empty item; use an IPv4/IPv6 address or "dhcp"`, i)
		}
		if !isDHCPUpstream(value) {
			if _, err := netip.ParseAddr(value); err != nil {
				return fmt.Errorf(
					`dns.upstream[%d] %q: must be an IPv4/IPv6 address or "dhcp" (alias "auto"): %w`,
					i, raw, err,
				)
			}
		}
		c.DNS.Upstream[i] = value
		valid++
	}
	if valid == 0 {
		return errors.New(`dns.upstream: at least one IPv4/IPv6 address or "dhcp" is required`)
	}
	return nil
}

func (p *ProxyConfig) applyDefaults() {
	if strings.TrimSpace(p.LocalClientPrefix) == "" {
		p.LocalClientPrefix = DefaultLocalClientPrefix
	} else {
		p.LocalClientPrefix = strings.TrimSpace(p.LocalClientPrefix)
	}
}

// UnmarshalYAML decodes ProxyConfig, accepting durations such as "15s" as well
// as bare second counts such as 0.
func (p *ProxyConfig) UnmarshalYAML(value *yaml.Node) error {
	var raw struct {
		Mode              string    `yaml:"mode"`
		TCPListen         string    `yaml:"tcp_listen"`
		KeepAlive         yaml.Node `yaml:"keepalive"`
		MaxConns          int       `yaml:"max_conns"`
		IdleTimeout       yaml.Node `yaml:"idle_timeout"`
		ApplyNft          bool      `yaml:"apply_nft"`
		LocalClientPrefix string    `yaml:"local_client_prefix"`
	}
	if err := value.Decode(&raw); err != nil {
		return err
	}

	keepAlive, err := decodeDurationNode(raw.KeepAlive)
	if err != nil {
		return fmt.Errorf("proxy.keepalive: %w", err)
	}
	idleTimeout, err := decodeDurationNode(raw.IdleTimeout)
	if err != nil {
		return fmt.Errorf("proxy.idle_timeout: %w", err)
	}

	*p = ProxyConfig{
		Mode:              raw.Mode,
		TCPListen:         raw.TCPListen,
		KeepAlive:         keepAlive,
		MaxConns:          raw.MaxConns,
		IdleTimeout:       idleTimeout,
		ApplyNft:          raw.ApplyNft,
		LocalClientPrefix: strings.TrimSpace(raw.LocalClientPrefix),
	}
	p.applyDefaults()
	return nil
}

// MarshalYAML makes ProxyConfig round-trippable, encoding durations as
// strings.
func (p ProxyConfig) MarshalYAML() (any, error) {
	type encoded struct {
		Mode              string `yaml:"mode"`
		TCPListen         string `yaml:"tcp_listen"`
		KeepAlive         string `yaml:"keepalive"`
		MaxConns          int    `yaml:"max_conns"`
		IdleTimeout       string `yaml:"idle_timeout"`
		ApplyNft          bool   `yaml:"apply_nft"`
		LocalClientPrefix string `yaml:"local_client_prefix"`
	}
	return encoded{
		Mode:              p.Mode,
		TCPListen:         p.TCPListen,
		KeepAlive:         p.KeepAlive.String(),
		MaxConns:          p.MaxConns,
		IdleTimeout:       p.IdleTimeout.String(),
		ApplyNft:          p.ApplyNft,
		LocalClientPrefix: p.LocalClientPrefix,
	}, nil
}

func decodeDurationNode(n yaml.Node) (time.Duration, error) {
	if n.Kind == 0 {
		return 0, nil
	}
	if n.Kind != yaml.ScalarNode {
		return 0, fmt.Errorf("must be a scalar")
	}
	switch n.Tag {
	case "!!null":
		return 0, nil
	case "!!int":
		var seconds int64
		if err := n.Decode(&seconds); err != nil {
			return 0, fmt.Errorf("invalid duration %q: %w", n.Value, err)
		}
		return time.Duration(seconds) * time.Second, nil
	case "!!str":
		d, err := time.ParseDuration(n.Value)
		if err != nil {
			return 0, fmt.Errorf("invalid duration %q: %w", n.Value, err)
		}
		return d, nil
	default:
		return 0, fmt.Errorf("invalid duration %q", n.Value)
	}
}

func (c *Config) compileMapping() error {
	strategy := strings.ToLower(strings.TrimSpace(c.MappingStrategy))
	if strategy == "" {
		strategy = "prefix"
	}

	switch strategy {
	case "prefix":
		mappings := make([]mapping.PrefixMapping, 0, len(c.Mappings))
		for i, m := range c.Mappings {
			from, err := netip.ParsePrefix(strings.TrimSpace(m.From))
			if err != nil {
				return fmt.Errorf("mappings[%d].from %q: %w", i, m.From, err)
			}
			to, err := netip.ParsePrefix(strings.TrimSpace(m.To))
			if err != nil {
				return fmt.Errorf("mappings[%d].to %q: %w", i, m.To, err)
			}
			mappings = append(mappings, mapping.PrefixMapping{From: from, To: to})
		}

		realPrefixes := make([]netip.Prefix, 0, len(c.RealPrefixes))
		for i, raw := range c.RealPrefixes {
			p, err := netip.ParsePrefix(strings.TrimSpace(raw))
			if err != nil {
				return fmt.Errorf("real_prefixes[%d] %q: %w", i, raw, err)
			}
			realPrefixes = append(realPrefixes, p)
		}

		s := mapping.NewPrefixMappingStrategy(mappings, mapping.WithRealPrefixes(realPrefixes...))
		if err := s.Validate(); err != nil {
			return fmt.Errorf("mapping validation failed: %w", err)
		}
		c.MappingStrategy = strategy
		c.Strategy = s
		return nil

	default:
		return fmt.Errorf("unsupported mapping_strategy %q", c.MappingStrategy)
	}
}
