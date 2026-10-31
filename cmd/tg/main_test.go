package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"tesla-gateway/internal/config"
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
