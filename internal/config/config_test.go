package config_test

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tesla-gateway/internal/config"
)

const sampleConfig = `
mapping_strategy: prefix
mappings:
  - { from: "192.168.1.0/24", to: "100.64.1.0/24" }
real_prefixes:
  - "192.168.0.0/16"
stats_path: "/tmp/tesla-gateway-stats.json"
dns:
  listen: "0.0.0.0:53"
  resolvers: [hosts, lease, system]
  upstream: ["223.5.5.5", "119.29.29.29"]
  clamp_ttl: 300
  cache_max: 4096
  drop_aaaa: false
proxy:
  mode: nat
  tcp_listen: ":16464"
  keepalive: 15s
  max_conns: 1024
  idle_timeout: 0
  apply_nft: true
  local_client_prefix: "100.64.0.0/24"
log:
  format: json
  level: info
`

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(sampleConfig), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load() = %v, want nil", err)
	}

	if cfg.MappingStrategy != "prefix" {
		t.Errorf("MappingStrategy = %q, want prefix", cfg.MappingStrategy)
	}
	if len(cfg.Mappings) != 1 || cfg.Mappings[0].From != "192.168.1.0/24" {
		t.Errorf("Mappings = %+v, want one 192.168.1.0/24 mapping", cfg.Mappings)
	}
	if cfg.StatsPath != "/tmp/tesla-gateway-stats.json" {
		t.Errorf("StatsPath = %q, want /tmp/tesla-gateway-stats.json", cfg.StatsPath)
	}
	if cfg.DNS.Listen != "0.0.0.0:53" || cfg.DNS.ClampTTL != 300 || cfg.DNS.CacheMax != 4096 {
		t.Errorf("DNS config = %+v", cfg.DNS)
	}
	if len(cfg.DNS.Resolvers) != 3 || cfg.DNS.Resolvers[2] != "system" {
		t.Errorf("DNS.Resolvers = %v", cfg.DNS.Resolvers)
	}
	if cfg.Proxy.KeepAlive != 15*time.Second {
		t.Errorf("Proxy.KeepAlive = %v, want 15s", cfg.Proxy.KeepAlive)
	}
	if cfg.Proxy.IdleTimeout != 0 {
		t.Errorf("Proxy.IdleTimeout = %v, want 0", cfg.Proxy.IdleTimeout)
	}
	if !cfg.Proxy.ApplyNft {
		t.Error("Proxy.ApplyNft = false, want true")
	}
	if cfg.Proxy.LocalClientPrefix != "100.64.0.0/24" {
		t.Errorf("Proxy.LocalClientPrefix = %q, want 100.64.0.0/24", cfg.Proxy.LocalClientPrefix)
	}
	if cfg.Log.Format != "json" || cfg.Log.Level != "info" {
		t.Errorf("Log config = %+v", cfg.Log)
	}
	if cfg.Strategy == nil {
		t.Fatal("Strategy = nil, want compiled prefix strategy")
	}
	if err := cfg.Strategy.Validate(); err != nil {
		t.Errorf("Strategy.Validate() = %v, want nil", err)
	}
	got, ok := cfg.Strategy.Translate(mustAddr(t, "192.168.1.42"))
	if !ok || got.String() != "100.64.1.42" {
		t.Errorf("Translate(192.168.1.42) = %s, %v; want 100.64.1.42, true", got, ok)
	}
}

func TestLoadMissingFile(t *testing.T) {
	_, err := config.Load(filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	if err == nil || !strings.Contains(err.Error(), "read") {
		t.Fatalf("Load() = %v, want read error", err)
	}
}

func TestExampleConfig(t *testing.T) {
	cfg, err := config.Load(filepath.Join("..", "..", "configs", "config.example.yaml"))
	if err != nil {
		t.Fatalf("Load(example config) = %v, want nil", err)
	}
	if cfg.StatsPath != config.DefaultStatsPath {
		t.Errorf("StatsPath = %q, want %q", cfg.StatsPath, config.DefaultStatsPath)
	}
	if cfg.Strategy == nil {
		t.Fatal("Strategy = nil, want compiled mapping strategy")
	}
	if err := cfg.Strategy.Validate(); err != nil {
		t.Fatalf("Strategy.Validate() = %v, want nil", err)
	}
}

func TestOpenWrtSampleConfig(t *testing.T) {
	cfg, err := config.Load(filepath.Join("..", "..", "files", "etc", "tesla-gateway", "config.yaml"))
	if err != nil {
		t.Fatalf("Load(OpenWrt sample) = %v, want nil", err)
	}
	if !cfg.Proxy.ApplyNft {
		t.Error("Proxy.ApplyNft = false, want true")
	}
	if cfg.StatsPath != config.DefaultStatsPath {
		t.Errorf("StatsPath = %q, want %q", cfg.StatsPath, config.DefaultStatsPath)
	}
	if cfg.Proxy.LocalClientPrefix != "100.64.0.0/24" {
		t.Errorf("Proxy.LocalClientPrefix = %q, want 100.64.0.0/24", cfg.Proxy.LocalClientPrefix)
	}
	if cfg.DNS.Listen != "0.0.0.0:53" {
		t.Errorf("DNS.Listen = %q, want 0.0.0.0:53", cfg.DNS.Listen)
	}
	if cfg.Proxy.TCPListen != ":16464" {
		t.Errorf("Proxy.TCPListen = %q, want :16464", cfg.Proxy.TCPListen)
	}
	got, ok := cfg.Strategy.Translate(mustAddr(t, "192.168.1.42"))
	if !ok || got.String() != "100.64.1.42" {
		t.Errorf("Translate(192.168.1.42) = %s, %v; want 100.64.1.42, true", got, ok)
	}
}

func TestParseIntegerDurationsAndDefaults(t *testing.T) {
	cfg, err := config.Parse([]byte(`
mappings:
  - { from: "10.0.0.0/24", to: "100.65.0.0/24" }
proxy:
  keepalive: 15
  idle_timeout: 0
`))
	if err != nil {
		t.Fatalf("Parse() = %v, want nil", err)
	}
	if cfg.MappingStrategy != "prefix" {
		t.Errorf("MappingStrategy = %q, want default prefix", cfg.MappingStrategy)
	}
	if cfg.Proxy.KeepAlive != 15*time.Second {
		t.Errorf("KeepAlive = %v, want 15s", cfg.Proxy.KeepAlive)
	}
	if cfg.Proxy.IdleTimeout != 0 {
		t.Errorf("IdleTimeout = %v, want 0", cfg.Proxy.IdleTimeout)
	}
	if cfg.Proxy.ApplyNft {
		t.Error("ApplyNft = true, want default false")
	}
	if cfg.StatsPath != config.DefaultStatsPath {
		t.Errorf("StatsPath = %q, want default %q", cfg.StatsPath, config.DefaultStatsPath)
	}
	if cfg.Proxy.LocalClientPrefix != config.DefaultLocalClientPrefix {
		t.Errorf(
			"LocalClientPrefix = %q, want default %q",
			cfg.Proxy.LocalClientPrefix,
			config.DefaultLocalClientPrefix,
		)
	}
}

func TestDefaultLocalClientPrefixWhenProxySectionMissing(t *testing.T) {
	cfg, err := config.Parse([]byte(`
mappings:
  - { from: "10.0.0.0/24", to: "100.65.0.0/24" }
`))
	if err != nil {
		t.Fatalf("Parse() = %v, want nil", err)
	}
	if cfg.Proxy.LocalClientPrefix != config.DefaultLocalClientPrefix {
		t.Errorf("LocalClientPrefix = %q, want %q", cfg.Proxy.LocalClientPrefix, config.DefaultLocalClientPrefix)
	}
	if cfg.Proxy.ApplyNft {
		t.Error("ApplyNft = true, want false")
	}
}

func TestParseErrors(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want string
	}{
		{
			name: "unsupported strategy",
			yaml: "mapping_strategy: custom\nmappings: []\n",
			want: "unsupported mapping_strategy",
		},
		{
			name: "bad from prefix",
			yaml: `
mappings:
  - { from: "not-a-cidr", to: "100.65.0.0/24" }
`,
			want: "mappings[0].from",
		},
		{
			name: "unequal prefix lengths",
			yaml: `
mappings:
  - { from: "10.0.0.0/24", to: "100.65.0.0/25" }
`,
			want: "equal prefix lengths",
		},
		{
			name: "mapped prefix in local client range",
			yaml: `
mappings:
  - { from: "10.0.0.0/24", to: "100.64.0.128/25" }
`,
			want: "local client prefix",
		},
		{
			name: "bad duration",
			yaml: `
mappings:
  - { from: "10.0.0.0/24", to: "100.65.0.0/24" }
proxy:
  keepalive: "not-a-duration"
`,
			want: "proxy.keepalive",
		},
		{
			name: "bad real prefix",
			yaml: `
mappings:
  - { from: "10.0.0.0/24", to: "100.65.0.0/24" }
real_prefixes: ["nope"]
`,
			want: "real_prefixes[0]",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := config.Parse([]byte(tc.yaml))
			if err == nil {
				t.Fatal("Parse() = nil, want error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Parse() = %q, want substring %q", err, tc.want)
			}
		})
	}
}

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("parse address %q: %v", s, err)
	}
	return a
}
