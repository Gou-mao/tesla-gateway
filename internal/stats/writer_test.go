package stats_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"tesla-gateway/internal/stats"
)

func readFileSnapshot(t *testing.T, path string) stats.FileSnapshot {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read stats file: %v", err)
	}
	var document stats.FileSnapshot
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatalf("unmarshal stats file %q: %v\n%s", path, err, data)
	}
	return document
}

func TestWriterWritesValidAtomicJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "stats.json")

	cache := &testCacheSizer{size: 2}
	st := stats.New()
	st.SetCache(cache)
	st.IncDNSQueries()
	st.IncDNSCacheHits()
	st.IncDNSUpstreamQueries()
	st.IncProxyActiveConns()
	st.IncProxyTotalConns()
	st.AddProxyBytesClientToUpstream(123)
	st.AddProxyBytesUpstreamToClient(456)
	st.IncProxyRejectedNoMapping()

	started := time.Now().UTC().Add(-90 * time.Second).Truncate(time.Second)
	effectiveUpstream := []string{"223.5.5.5", "8.8.8.8"}
	writer, err := stats.NewWriter(stats.WriterConfig{
		Path:      path,
		PID:       4242,
		StartedAt: started,
		Meta: stats.Meta{
			Version: "test-version",
			Listeners: stats.Listeners{
				DNS:   "[::]:53",
				Proxy: "[::]:16464",
			},
			Mappings: []stats.Mapping{
				{From: "192.168.1.0/24", To: "100.64.1.0/24"},
				{From: "10.243.0.0/16", To: "100.66.0.0/16"},
			},
			MappingStrategy: "prefix",
			DNSListen:       "0.0.0.0:53",
			DNSUpstream:     []string{"223.5.5.5", "dhcp"},
		},
		EffectiveUpstream: func() []string { return effectiveUpstream },
	}, st, nil)
	if err != nil {
		t.Fatalf("NewWriter() = %v", err)
	}
	if writer.Path() != path {
		t.Errorf("Path() = %q, want %q", writer.Path(), path)
	}
	if writer.Interval() != stats.DefaultInterval {
		t.Errorf("Interval() = %v, want %v", writer.Interval(), stats.DefaultInterval)
	}

	if err := writer.Write(); err != nil {
		t.Fatalf("Write() = %v", err)
	}
	if _, err := os.Stat(path + ".tmp"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("temporary file still exists after Write: %v", err)
	}

	document := readFileSnapshot(t, path)
	if document.Version != "test-version" {
		t.Errorf("version = %q, want test-version", document.Version)
	}
	if document.PID != 4242 {
		t.Errorf("pid = %d, want 4242", document.PID)
	}
	if want := started.Format(time.RFC3339); document.StartedAt != want {
		t.Errorf("started_at = %q, want %q", document.StartedAt, want)
	}
	if document.UptimeSec < 89 {
		t.Errorf("uptime_sec = %d, want at least 89", document.UptimeSec)
	}
	if document.Listeners.DNS != "[::]:53" || document.Listeners.Proxy != "[::]:16464" {
		t.Errorf("listeners = %+v, want DNS [::]:53 and proxy [::]:16464", document.Listeners)
	}
	if document.MappingStrategy != "prefix" {
		t.Errorf("mapping_strategy = %q, want prefix", document.MappingStrategy)
	}
	if document.DNSListen != "0.0.0.0:53" {
		t.Errorf("dns_listen = %q, want 0.0.0.0:53", document.DNSListen)
	}
	wantMappings := []stats.Mapping{
		{From: "192.168.1.0/24", To: "100.64.1.0/24"},
		{From: "10.243.0.0/16", To: "100.66.0.0/16"},
	}
	if len(document.Mappings) != len(wantMappings) {
		t.Fatalf("mappings = %v, want %v", document.Mappings, wantMappings)
	}
	for i := range wantMappings {
		if document.Mappings[i] != wantMappings[i] {
			t.Errorf("mappings[%d] = %+v, want %+v", i, document.Mappings[i], wantMappings[i])
		}
	}
	wantUpstream := []string{"223.5.5.5", "dhcp"}
	if len(document.DNSUpstream) != len(wantUpstream) {
		t.Fatalf("dns_upstream = %v, want %v", document.DNSUpstream, wantUpstream)
	}
	for i := range wantUpstream {
		if document.DNSUpstream[i] != wantUpstream[i] {
			t.Errorf("dns_upstream[%d] = %q, want %q", i, document.DNSUpstream[i], wantUpstream[i])
		}
	}
	wantEffective := []string{"223.5.5.5", "8.8.8.8"}
	if len(document.DNSUpstreamEffective) != len(wantEffective) {
		t.Fatalf("dns_upstream_effective = %v, want %v", document.DNSUpstreamEffective, wantEffective)
	}
	for i := range wantEffective {
		if document.DNSUpstreamEffective[i] != wantEffective[i] {
			t.Errorf(
				"dns_upstream_effective[%d] = %q, want %q",
				i, document.DNSUpstreamEffective[i], wantEffective[i],
			)
		}
	}
	if got := document.DNS.Queries; got != 1 {
		t.Errorf("dns.queries = %d, want 1", got)
	}
	if got := document.DNS.CacheHits; got != 1 {
		t.Errorf("dns.cache_hits = %d, want 1", got)
	}
	if got := document.DNS.CacheEntries; got != 2 {
		t.Errorf("dns.cache_entries = %d, want 2", got)
	}
	if got := document.DNS.UpstreamQueries; got != 1 {
		t.Errorf("dns.upstream_queries = %d, want 1", got)
	}
	if got := document.Proxy.ActiveConns; got != 1 {
		t.Errorf("proxy.active_conns = %d, want 1", got)
	}
	if got := document.Proxy.TotalConns; got != 1 {
		t.Errorf("proxy.total_conns = %d, want 1", got)
	}
	if got := document.Proxy.BytesClientToUpstream; got != 123 {
		t.Errorf("proxy.bytes_client_to_upstream = %d, want 123", got)
	}
	if got := document.Proxy.BytesUpstreamToClient; got != 456 {
		t.Errorf("proxy.bytes_upstream_to_client = %d, want 456", got)
	}
	if got := document.Proxy.RejectedNoMapping; got != 1 {
		t.Errorf("proxy.rejected_no_mapping = %d, want 1", got)
	}

	// The file is replaced atomically on every write.
	st.IncDNSQueries()
	effectiveUpstream = []string{"223.5.5.5", "1.1.1.1"}
	if err := writer.Write(); err != nil {
		t.Fatalf("second Write() = %v", err)
	}
	second := readFileSnapshot(t, path)
	if got := second.DNS.Queries; got != 2 {
		t.Errorf("dns.queries after second write = %d, want 2", got)
	}
	wantEffective = []string{"223.5.5.5", "1.1.1.1"}
	if len(second.DNSUpstreamEffective) != len(wantEffective) {
		t.Fatalf("effective upstream after second write = %v, want %v", second.DNSUpstreamEffective, wantEffective)
	}
	for i := range wantEffective {
		if second.DNSUpstreamEffective[i] != wantEffective[i] {
			t.Errorf("effective upstream[%d] after second write = %q, want %q",
				i, second.DNSUpstreamEffective[i], wantEffective[i])
		}
	}
}

func TestWriterPublishesEmptyMetaArrays(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stats.json")
	writer, err := stats.NewWriter(stats.WriterConfig{Path: path}, stats.New(), nil)
	if err != nil {
		t.Fatalf("NewWriter() = %v", err)
	}
	if err := writer.Write(); err != nil {
		t.Fatalf("Write() = %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read stats file: %v", err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal stats file: %v", err)
	}
	if got := string(raw["mappings"]); got != "[]" {
		t.Errorf("mappings = %s, want []", got)
	}
	if got := string(raw["dns_upstream"]); got != "[]" {
		t.Errorf("dns_upstream = %s, want []", got)
	}
	if got := string(raw["dns_upstream_effective"]); got != "[]" {
		t.Errorf("dns_upstream_effective = %s, want []", got)
	}
	if got := string(raw["version"]); got != `"dev"` {
		t.Errorf("version = %s, want \"dev\"", got)
	}
}

func TestWriterRunWritesImmediatelyPeriodicallyAndOnCancel(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stats.json")
	st := stats.New()
	writer, err := stats.NewWriter(stats.WriterConfig{
		Path:     path,
		Interval: 20 * time.Millisecond,
		Meta: stats.Meta{
			Version: "run-test",
		},
	}, st, nil)
	if err != nil {
		t.Fatalf("NewWriter() = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		writer.Run(ctx)
	}()

	waitForStatsCondition(t, 2*time.Second, func() bool {
		_, err := os.Stat(path)
		return err == nil
	}, "initial stats file")

	st.IncDNSQueries()
	waitForStatsCondition(t, 2*time.Second, func() bool {
		data, err := os.ReadFile(path)
		if err != nil {
			return false
		}
		var document stats.FileSnapshot
		if err := json.Unmarshal(data, &document); err != nil {
			return false
		}
		return document.DNS.Queries == 1
	}, "periodic stats update")

	st.IncDNSQueries()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not stop after context cancellation")
	}

	if got := readFileSnapshot(t, path).DNS.Queries; got != 2 {
		t.Errorf("dns.queries in final snapshot = %d, want 2", got)
	}
	if _, err := os.Stat(path + ".tmp"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("temporary file still exists after Run: %v", err)
	}
}

func waitForStatsCondition(t *testing.T, timeout time.Duration, condition func() bool, description string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", description)
}
