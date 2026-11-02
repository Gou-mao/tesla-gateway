package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	mdns "github.com/miekg/dns"

	"tesla-gateway/internal/config"
	tgdns "tesla-gateway/internal/dns"
	"tesla-gateway/internal/logx"
	"tesla-gateway/internal/mapping"
	"tesla-gateway/internal/stats"
)

func TestParseProxyPort(t *testing.T) {
	tests := []struct {
		listen  string
		want    int
		wantErr bool
	}{
		{listen: ":16464", want: 16464},
		{listen: "0.0.0.0:16464", want: 16464},
		{listen: "[::]:16464", want: 16464},
		{listen: " 127.0.0.1:8080 ", want: 8080},
		{listen: "", wantErr: true},
		{listen: "16464", wantErr: true},
		{listen: ":0", wantErr: true},
		{listen: ":http", wantErr: true},
		{listen: ":65536", wantErr: true},
	}
	for _, tc := range tests {
		got, err := parseProxyPort(tc.listen)
		if tc.wantErr {
			if err == nil {
				t.Errorf("parseProxyPort(%q) = %d, nil; want error", tc.listen, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseProxyPort(%q) = %v, want %d", tc.listen, err, tc.want)
			continue
		}
		if got != tc.want {
			t.Errorf("parseProxyPort(%q) = %d, want %d", tc.listen, got, tc.want)
		}
	}
}

func TestStatsMetaFromConfig(t *testing.T) {
	cfg, err := config.Parse([]byte(`
mapping_strategy: prefix
mappings:
  - { from: "192.168.1.0/24", to: "100.64.1.0/24" }
dns:
  listen: "0.0.0.0:53"
  upstream: ["223.5.5.5", "dhcp", "119.29.29.29"]
`))
	if err != nil {
		t.Fatalf("config.Parse() = %v", err)
	}

	meta := statsMeta(cfg, "test-version", stats.Listeners{
		DNS:   "0.0.0.0:53",
		Proxy: "[::]:16464",
	})

	if meta.Version != "test-version" {
		t.Errorf("Version = %q, want test-version", meta.Version)
	}
	if meta.Listeners.DNS != "0.0.0.0:53" || meta.Listeners.Proxy != "[::]:16464" {
		t.Errorf("Listeners = %+v, want DNS 0.0.0.0:53 and proxy [::]:16464", meta.Listeners)
	}
	if meta.MappingStrategy != "prefix" {
		t.Errorf("MappingStrategy = %q, want prefix", meta.MappingStrategy)
	}
	wantMappings := []stats.Mapping{{From: "192.168.1.0/24", To: "100.64.1.0/24"}}
	if !reflect.DeepEqual(meta.Mappings, wantMappings) {
		t.Errorf("Mappings = %v, want %v", meta.Mappings, wantMappings)
	}
	if meta.DNSListen != "0.0.0.0:53" {
		t.Errorf("DNSListen = %q, want 0.0.0.0:53", meta.DNSListen)
	}
	wantUpstream := []string{"223.5.5.5", "dhcp", "119.29.29.29"}
	if !reflect.DeepEqual(meta.DNSUpstream, wantUpstream) {
		t.Errorf("DNSUpstream = %v, want %v", meta.DNSUpstream, wantUpstream)
	}
	wantEffective := []string{"223.5.5.5", "119.29.29.29"}
	if !reflect.DeepEqual(meta.DNSUpstreamEffective, wantEffective) {
		t.Errorf("DNSUpstreamEffective = %v, want %v", meta.DNSUpstreamEffective, wantEffective)
	}
}

func TestParseUpstreamItems(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    []string
		wantErr bool
	}{
		{
			name: "ordered list",
			raw:  " 223.5.5.5, dhcp, 119.29.29.29 ",
			want: []string{"223.5.5.5", "dhcp", "119.29.29.29"},
		},
		{
			name: "keywords case insensitive, aliases and duplicates removed",
			raw:  "DHCP, 223.5.5.5, auto, 223.5.5.5, AUTO",
			want: []string{"dhcp", "223.5.5.5"},
		},
		{
			name: "auto alias keeps first spelling",
			raw:  "AUTO, dhcp",
			want: []string{"auto"},
		},
		{
			name: "equivalent IPv6 spellings deduplicated",
			raw:  "2001:0db8:0:0:0:0:0:1, 2001:db8::1, fe80::1%eth0",
			want: []string{"2001:0db8:0:0:0:0:0:1", "fe80::1%eth0"},
		},
		{name: "empty list", raw: "   ", wantErr: true},
		{name: "empty item", raw: "1.1.1.1, , 8.8.8.8", wantErr: true},
		{name: "hostname", raw: "dns.google", wantErr: true},
		{name: "address with port", raw: "1.1.1.1:53", wantErr: true},
		{name: "CIDR", raw: "1.1.1.0/24", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseUpstreamItems(tc.raw)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parseUpstreamItems(%q) = %v, nil; want error", tc.raw, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseUpstreamItems(%q) = %v", tc.raw, err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("parseUpstreamItems(%q) = %v, want %v", tc.raw, got, tc.want)
			}
		})
	}
}

func TestReplaceUpstreamLinePreservesEverythingElse(t *testing.T) {
	input := "# keep this comment\n" +
		"dns:\n" +
		"  # upstream: [\"commented-out\"]\n" +
		"  resolvers: [hosts, system]\n" +
		"  upstream: [\"old\", \"values\"]\n" +
		"  hosts_path: \"/etc/hosts\"\n" +
		"\n" +
		"proxy:\n" +
		"  tcp_listen: \":16464\"\n"

	want := "# keep this comment\n" +
		"dns:\n" +
		"  # upstream: [\"commented-out\"]\n" +
		"  resolvers: [hosts, system]\n" +
		"  upstream: [\"1.1.1.1\", \"2001:db8::1\", \"dhcp\"]\n" +
		"  hosts_path: \"/etc/hosts\"\n" +
		"\n" +
		"proxy:\n" +
		"  tcp_listen: \":16464\"\n"

	got, err := replaceUpstreamLine([]byte(input), []string{"1.1.1.1", "2001:db8::1", "dhcp"})
	if err != nil {
		t.Fatalf("replaceUpstreamLine() = %v", err)
	}
	if string(got) != want {
		t.Errorf("replaceUpstreamLine() =\n%s\nwant:\n%s", got, want)
	}
}

func TestReplaceUpstreamLinePreservesIndentAndCRLF(t *testing.T) {
	input := "dns:\r\n\tupstream: [\"old\"]\r\n"
	want := "dns:\r\n\tupstream: [\"dhcp\"]\r\n"

	got, err := replaceUpstreamLine([]byte(input), []string{"dhcp"})
	if err != nil {
		t.Fatalf("replaceUpstreamLine() = %v", err)
	}
	if string(got) != want {
		t.Errorf("replaceUpstreamLine() = %q, want %q", got, want)
	}
}

func TestReplaceUpstreamLineMissingKey(t *testing.T) {
	_, err := replaceUpstreamLine([]byte("dns:\n  listen: \":53\"\n"), []string{"1.1.1.1"})
	if err == nil {
		t.Fatal("replaceUpstreamLine() = nil; want error")
	}
}

func TestReplaceUpstreamLineConsumesBlockList(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name: "LF",
			input: "# keep this comment\n" +
				"dns:\n" +
				"  resolvers: [hosts, system]\n" +
				"  upstream:\n" +
				"    - \"dhcp\"\n" +
				"    - \"1.1.1.1\"\n" +
				"  hosts_path: \"/etc/hosts\"\n" +
				"proxy:\n" +
				"  tcp_listen: \":16464\"\n",
			want: "# keep this comment\n" +
				"dns:\n" +
				"  resolvers: [hosts, system]\n" +
				"  upstream: [\"8.8.8.8\", \"2001:db8::1\"]\n" +
				"  hosts_path: \"/etc/hosts\"\n" +
				"proxy:\n" +
				"  tcp_listen: \":16464\"\n",
		},
		{
			name: "CRLF",
			input: "dns:\r\n" +
				"  upstream:\r\n" +
				"    - \"dhcp\"\r\n" +
				"    - \"1.1.1.1\"\r\n" +
				"proxy:\r\n" +
				"  tcp_listen: \":16464\"\r\n",
			want: "dns:\r\n" +
				"  upstream: [\"8.8.8.8\", \"2001:db8::1\"]\r\n" +
				"proxy:\r\n" +
				"  tcp_listen: \":16464\"\r\n",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := replaceUpstreamLine([]byte(tc.input), []string{"8.8.8.8", "2001:db8::1"})
			if err != nil {
				t.Fatalf("replaceUpstreamLine() = %v", err)
			}
			if string(got) != tc.want {
				t.Fatalf("replaceUpstreamLine() =\n%s\nwant:\n%s", got, tc.want)
			}

			cfg, err := config.Parse(got)
			if err != nil {
				t.Fatalf("config.Parse(updated) = %v, want valid YAML", err)
			}
			wantItems := []string{"8.8.8.8", "2001:db8::1"}
			if !reflect.DeepEqual(cfg.DNS.Upstream, wantItems) {
				t.Errorf("parsed dns.upstream = %v, want %v", cfg.DNS.Upstream, wantItems)
			}
		})
	}
}

func TestUpdateConfigUpstream(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	input := "# keep this comment\n" +
		"dns:\n" +
		"  upstream: [\"old\"]\n" +
		"  listen: \"0.0.0.0:53\"\n"
	want := "# keep this comment\n" +
		"dns:\n" +
		"  upstream: [\"8.8.8.8\", \"dhcp\", \"2001:db8::1\"]\n" +
		"  listen: \"0.0.0.0:53\"\n"

	if err := os.WriteFile(path, []byte(input), 0o640); err != nil {
		t.Fatalf("os.WriteFile() = %v", err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatalf("os.Chmod() = %v", err)
	}

	if err := updateConfigUpstream(path, "8.8.8.8, DHCP, 8.8.8.8, 2001:db8::1"); err != nil {
		t.Fatalf("updateConfigUpstream() = %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("os.ReadFile() = %v", err)
	}
	if string(got) != want {
		t.Errorf("config =\n%s\nwant:\n%s", got, want)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("os.Stat() = %v", err)
	}
	if info.Mode().Perm() != 0o640 {
		t.Errorf("mode = %o, want 640", info.Mode().Perm())
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("os.ReadDir() = %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "config.yaml" {
		t.Errorf("directory entries = %v, want only config.yaml", entries)
	}
}

func TestUpdateConfigUpstreamRejectsInvalidWithoutWriting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	input := "dns:\n  upstream: [\"old\"]\n"
	if err := os.WriteFile(path, []byte(input), 0o644); err != nil {
		t.Fatalf("os.WriteFile() = %v", err)
	}

	if err := updateConfigUpstream(path, "8.8.8.8, not-an-ip"); err == nil {
		t.Fatal("updateConfigUpstream() = nil; want error")
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("os.ReadFile() = %v", err)
	}
	if string(got) != input {
		t.Errorf("config changed after invalid update: %q", got)
	}
}

func TestUpdateConfigUpstreamRejectsInvalidUpdatedConfigWithoutWriting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	input := "mapping_strategy: prefix\n" +
		"mappings:\n" +
		"  - { from: \"not-a-prefix\", to: \"100.64.1.0/24\" }\n" +
		"dns:\n" +
		"  listen: \"0.0.0.0:53\"\n" +
		"  upstream:\n" +
		"    - \"old\"\n"
	if err := os.WriteFile(path, []byte(input), 0o644); err != nil {
		t.Fatalf("os.WriteFile() = %v", err)
	}

	err := updateConfigUpstream(path, "8.8.8.8")
	if err == nil {
		t.Fatal("updateConfigUpstream() = nil; want validation error")
	}
	if !strings.Contains(err.Error(), "invalid") {
		t.Errorf("updateConfigUpstream() error = %q, want invalid configuration", err)
	}

	got, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatalf("os.ReadFile() = %v", readErr)
	}
	if string(got) != input {
		t.Errorf("config changed after invalid updated config: %q", got)
	}
}

type captureResponseWriter struct {
	msg *mdns.Msg
}

func (w *captureResponseWriter) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53}
}

func (w *captureResponseWriter) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
}

func (w *captureResponseWriter) WriteMsg(msg *mdns.Msg) error {
	w.msg = msg.Copy()
	return nil
}

func (w *captureResponseWriter) Write(p []byte) (int, error) { return len(p), nil }
func (w *captureResponseWriter) Close() error                { return nil }
func (w *captureResponseWriter) TsigStatus() error           { return nil }
func (w *captureResponseWriter) TsigTimersOnly(bool)         {}
func (w *captureResponseWriter) Hijack()                     {}

func writeReloadConfig(t *testing.T, path, hostsPath, mapTo, upstream string) {
	t.Helper()

	text := fmt.Sprintf(`mapping_strategy: prefix
mappings:
  - { from: "192.168.1.0/24", to: %q }
dns:
  listen: "127.0.0.1:0"
  resolvers: [hosts, system]
  hosts_path: %q
  upstream: [%q]
  clamp_ttl: 30
`, mapTo, hostsPath, upstream)
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatalf("os.WriteFile(%s) = %v", path, err)
	}
}

func newReloadTestServer(t *testing.T, cfg *config.Config, logger *logx.Logger) (*tgdns.Server, *tgdns.Cache) {
	t.Helper()

	engine := mapping.NewEngine(cfg.Strategy)
	runtime, err := buildDNSRuntime(cfg, engine, logger)
	if err != nil {
		t.Fatalf("buildDNSRuntime() = %v", err)
	}
	cache := tgdns.NewCache(8)
	server, err := tgdns.NewServer(tgdns.ServerConfig{
		Listen:   cfg.DNS.Listen,
		Local:    runtime.local,
		Upstream: runtime.upstream,
		Cache:    cache,
		Rewriter: runtime.rewriter,
		Logger:   logger,
	})
	if err != nil {
		t.Fatalf("tgdns.NewServer() = %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })
	return server, cache
}

func queryMappedA(t *testing.T, server *tgdns.Server) *mdns.A {
	t.Helper()

	request := new(mdns.Msg)
	request.SetQuestion("nas.home.", mdns.TypeA)

	writer := &captureResponseWriter{}
	server.ServeDNS(writer, request)
	if writer.msg == nil {
		t.Fatal("ServeDNS() did not write a response")
	}
	if len(writer.msg.Answer) != 1 {
		t.Fatalf("answer count = %d, want 1: %v", len(writer.msg.Answer), writer.msg.Answer)
	}
	record, ok := writer.msg.Answer[0].(*mdns.A)
	if !ok {
		t.Fatalf("answer = %T, want *dns.A", writer.msg.Answer[0])
	}
	return record
}

func TestReloadAppliesDNSUpstreamAndKeepsRewriter(t *testing.T) {
	dir := t.TempDir()
	hostsPath := filepath.Join(dir, "hosts")
	configPath := filepath.Join(dir, "config.yaml")

	if err := os.WriteFile(hostsPath, []byte("192.168.1.251 nas.home\n"), 0o600); err != nil {
		t.Fatalf("os.WriteFile(hosts) = %v", err)
	}
	writeReloadConfig(t, configPath, hostsPath, "100.64.1.0/24", "8.8.8.8")

	current, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("config.Load() = %v", err)
	}
	logger, err := logx.New(logx.Config{Output: io.Discard, Module: "test"})
	if err != nil {
		t.Fatalf("logx.New() = %v", err)
	}
	server, cache := newReloadTestServer(t, current, logger)

	record := queryMappedA(t, server)
	if record.A.String() != "100.64.1.251" || record.Hdr.Ttl != 30 {
		t.Fatalf("before reload A = %s TTL %d, want 100.64.1.251 TTL 30", record.A, record.Hdr.Ttl)
	}

	// Only dns.upstream changes; this is safe to apply in place.
	writeReloadConfig(t, configPath, hostsPath, "100.64.1.0/24", "1.1.1.1")

	cachedQuestion := mdns.Question{Name: "cached.home.", Qtype: mdns.TypeA, Qclass: mdns.ClassINET}
	cached := new(mdns.Msg)
	cached.SetQuestion(cachedQuestion.Name, cachedQuestion.Qtype)
	cached.Response = true
	cached.Answer = []mdns.RR{&mdns.A{
		Hdr: mdns.RR_Header{Name: cachedQuestion.Name, Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 30},
		A:   net.IPv4(192, 0, 2, 1),
	}}
	cache.Put(cachedQuestion, cached, false, false)

	if err := reload(configPath, current, server, cache, nil, nil, logger); err != nil {
		t.Fatalf("reload() = %v, want nil", err)
	}
	if !reflect.DeepEqual(current.DNS.Upstream, []string{"1.1.1.1"}) {
		t.Errorf("current.DNS.Upstream = %v, want [1.1.1.1]", current.DNS.Upstream)
	}
	if _, hit := cache.Get(cachedQuestion, false, false); hit {
		t.Error("cache still contains the old response after reload")
	}

	record = queryMappedA(t, server)
	if record.A.String() != "100.64.1.251" {
		t.Errorf("after reload A = %s, want rewriter mapping 100.64.1.251", record.A)
	}
	if record.Hdr.Ttl != 30 {
		t.Errorf("after reload TTL = %d, want rewriter clamp 30", record.Hdr.Ttl)
	}
}

func TestReloadRejectsMappingChangeAndKeepsOldRuntime(t *testing.T) {
	dir := t.TempDir()
	hostsPath := filepath.Join(dir, "hosts")
	configPath := filepath.Join(dir, "config.yaml")

	if err := os.WriteFile(hostsPath, []byte("192.168.1.251 nas.home\n"), 0o600); err != nil {
		t.Fatalf("os.WriteFile(hosts) = %v", err)
	}
	writeReloadConfig(t, configPath, hostsPath, "100.64.1.0/24", "8.8.8.8")

	current, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("config.Load() = %v", err)
	}
	logger, err := logx.New(logx.Config{Output: io.Discard, Module: "test"})
	if err != nil {
		t.Fatalf("logx.New() = %v", err)
	}
	server, cache := newReloadTestServer(t, current, logger)
	before := *current

	// Mapping changes affect DNS, the TCP proxy, and nft together, so a
	// SIGHUP reload must be rejected instead of applying only the DNS half.
	writeReloadConfig(t, configPath, hostsPath, "100.64.2.0/24", "8.8.8.8")
	err = reload(configPath, current, server, cache, nil, nil, logger)
	if err == nil {
		t.Fatal("reload() = nil, want error for changed mappings")
	}
	if !strings.Contains(err.Error(), "mappings") || !strings.Contains(err.Error(), "restart") {
		t.Errorf("reload() error = %q, want mappings and restart", err)
	}
	if !reflect.DeepEqual(before, *current) {
		t.Errorf("current config changed after rejected reload:\nbefore %+v\nafter  %+v", before, *current)
	}

	record := queryMappedA(t, server)
	if record.A.String() != "100.64.1.251" {
		t.Errorf("after rejected reload A = %s, want old mapping 100.64.1.251", record.A)
	}
}
