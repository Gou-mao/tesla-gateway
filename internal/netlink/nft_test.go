package netlink

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"
)

func mustPrefix(t *testing.T, s string) netip.Prefix {
	t.Helper()
	p, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatalf("parse prefix %q: %v", s, err)
	}
	return p
}

func mustPrefixes(t *testing.T, values ...string) []netip.Prefix {
	t.Helper()
	out := make([]netip.Prefix, 0, len(values))
	for _, v := range values {
		out = append(out, mustPrefix(t, v))
	}
	return out
}

func elements(t *testing.T, ruleset string) []string {
	t.Helper()
	const marker = "elements = { "
	start := strings.Index(ruleset, marker)
	if start < 0 {
		t.Fatalf("ruleset has no elements line:\n%s", ruleset)
	}
	start += len(marker)
	end := strings.Index(ruleset[start:], " }")
	if end < 0 {
		t.Fatalf("ruleset has an unterminated elements line:\n%s", ruleset)
	}
	raw := strings.TrimSpace(ruleset[start : start+end])
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		out = append(out, strings.TrimSpace(p))
	}
	return out
}

func TestBuildRuleset(t *testing.T) {
	ruleset, err := BuildRuleset(
		mustPrefixes(t, "100.64.1.0/24"),
		16464,
		mustPrefix(t, "100.64.0.0/24"),
	)
	if err != nil {
		t.Fatalf("BuildRuleset() = %v, want nil", err)
	}

	wants := []string{
		"table ip teslagateway {",
		"set mapped {",
		"type ipv4_addr",
		"flags interval",
		"auto-merge",
		"elements = { 100.64.1.0/24 }",
		"chain prerouting {",
		"type nat hook prerouting priority dstnat; policy accept;",
		"ip daddr @mapped tcp dport 1-65535 redirect to :16464",
	}
	for _, want := range wants {
		if !strings.Contains(ruleset, want) {
			t.Errorf("ruleset does not contain %q:\n%s", want, ruleset)
		}
	}

	got := elements(t, ruleset)
	if !slices.Equal(got, []string{"100.64.1.0/24"}) {
		t.Errorf("elements = %v, want [100.64.1.0/24]", got)
	}
}

func TestBuildRulesetSortsAndDeduplicates(t *testing.T) {
	ruleset, err := BuildRuleset(
		mustPrefixes(t, "100.66.1.0/24", "100.64.1.0/24", "100.64.1.0/24"),
		16464,
		mustPrefix(t, "100.64.0.0/24"),
	)
	if err != nil {
		t.Fatalf("BuildRuleset() = %v, want nil", err)
	}
	want := []string{"100.64.1.0/24", "100.66.1.0/24"}
	if got := elements(t, ruleset); !slices.Equal(got, want) {
		t.Errorf("elements = %v, want %v", got, want)
	}
}

func TestBuildRulesetSubtractsLocalPrefix(t *testing.T) {
	tests := []struct {
		name    string
		prefix  string
		local   string
		want    []string
		wantErr bool
	}{
		{
			name:   "local at start of larger prefix",
			prefix: "100.64.0.0/16",
			local:  "100.64.0.0/24",
			want: []string{
				"100.64.1.0/24",
				"100.64.2.0/23",
				"100.64.4.0/22",
				"100.64.8.0/21",
				"100.64.16.0/20",
				"100.64.32.0/19",
				"100.64.64.0/18",
				"100.64.128.0/17",
			},
		},
		{
			name:   "local in the middle of larger prefix",
			prefix: "100.64.0.0/22",
			local:  "100.64.1.0/24",
			want:   []string{"100.64.0.0/24", "100.64.2.0/23"},
		},
		{
			name:   "no overlap",
			prefix: "100.64.1.0/24",
			local:  "100.64.0.0/24",
			want:   []string{"100.64.1.0/24"},
		},
		{
			name:    "prefix fully covered by local",
			prefix:  "100.64.0.0/24",
			local:   "100.64.0.0/16",
			wantErr: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ruleset, err := BuildRuleset(
				mustPrefixes(t, tc.prefix),
				16464,
				mustPrefix(t, tc.local),
			)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("BuildRuleset() = nil error, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("BuildRuleset() = %v, want nil", err)
			}
			if got := elements(t, ruleset); !slices.Equal(got, tc.want) {
				t.Errorf("elements = %v, want %v", got, tc.want)
			}
			if strings.Contains(ruleset, tc.local) {
				t.Errorf("ruleset still contains local prefix %s:\n%s", tc.local, ruleset)
			}
		})
	}
}

func TestBuildRulesetSkipsCoveredPrefix(t *testing.T) {
	ruleset, err := BuildRuleset(
		mustPrefixes(t, "100.64.0.0/24", "100.65.0.0/24"),
		16464,
		mustPrefix(t, "100.64.0.0/24"),
	)
	if err != nil {
		t.Fatalf("BuildRuleset() = %v, want nil", err)
	}
	if got := elements(t, ruleset); !slices.Equal(got, []string{"100.65.0.0/24"}) {
		t.Errorf("elements = %v, want [100.65.0.0/24]", got)
	}
}

func TestBuildRulesetErrors(t *testing.T) {
	tests := []struct {
		name     string
		prefixes []netip.Prefix
		port     int
		local    netip.Prefix
		want     string
	}{
		{
			name:  "empty input",
			port:  16464,
			local: mustPrefix(t, "100.64.0.0/24"),
			want:  "no mapped prefixes",
		},
		{
			name:     "all prefixes covered by local",
			prefixes: mustPrefixes(t, "100.64.0.0/24"),
			port:     16464,
			local:    mustPrefix(t, "100.64.0.0/24"),
			want:     "no mapped prefixes remain",
		},
		{
			name:     "invalid port",
			prefixes: mustPrefixes(t, "100.64.1.0/24"),
			port:     0,
			local:    mustPrefix(t, "100.64.0.0/24"),
			want:     "invalid proxy port",
		},
		{
			name:     "port too large",
			prefixes: mustPrefixes(t, "100.64.1.0/24"),
			port:     65536,
			local:    mustPrefix(t, "100.64.0.0/24"),
			want:     "invalid proxy port",
		},
		{
			name:     "invalid local prefix",
			prefixes: mustPrefixes(t, "100.64.1.0/24"),
			port:     16464,
			want:     "invalid local client prefix",
		},
		{
			name:     "IPv6 prefix",
			prefixes: mustPrefixes(t, "2001:db8::/64"),
			port:     16464,
			local:    mustPrefix(t, "100.64.0.0/24"),
			want:     "only IPv4",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := BuildRuleset(tc.prefixes, tc.port, tc.local)
			if err == nil {
				t.Fatal("BuildRuleset() = nil error, want error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("BuildRuleset() = %q, want substring %q", err, tc.want)
			}
		})
	}
}

func TestApplyIsIdempotent(t *testing.T) {
	ruleset, err := BuildRuleset(
		mustPrefixes(t, "100.64.1.0/24"),
		16464,
		mustPrefix(t, "100.64.0.0/24"),
	)
	if err != nil {
		t.Fatalf("BuildRuleset() = %v, want nil", err)
	}

	var scripts []string
	runner := func(_ context.Context, script string) error {
		scripts = append(scripts, script)
		return nil
	}
	for i := 0; i < 2; i++ {
		if err := Apply(context.Background(), ruleset, runner); err != nil {
			t.Fatalf("Apply() call %d = %v, want nil", i+1, err)
		}
	}
	if len(scripts) != 2 {
		t.Fatalf("runner called %d times, want 2", len(scripts))
	}
	for i, script := range scripts {
		deleteAt := strings.Index(script, "delete table ip teslagateway")
		addAt := strings.Index(script, "table ip teslagateway {")
		if deleteAt < 0 {
			t.Fatalf("script %d has no delete:\n%s", i+1, script)
		}
		if addAt < 0 {
			t.Fatalf("script %d has no table definition:\n%s", i+1, script)
		}
		if deleteAt > addAt {
			t.Errorf("script %d deletes the table after adding it:\n%s", i+1, script)
		}
		for _, want := range []string{
			"add table ip teslagateway",
			"elements = { 100.64.1.0/24 }",
			"redirect to :16464",
		} {
			if !strings.Contains(script, want) {
				t.Errorf("script %d does not contain %q:\n%s", i+1, want, script)
			}
		}
	}
	if scripts[0] != scripts[1] {
		t.Errorf("Apply scripts differ between calls:\nfirst:\n%s\nsecond:\n%s", scripts[0], scripts[1])
	}
}

func TestApplyPropagatesRunnerError(t *testing.T) {
	wantErr := errors.New("nft failed")
	err := Apply(context.Background(), "table ip teslagateway {\n}\n", func(context.Context, string) error {
		return wantErr
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("Apply() = %v, want wrapped %v", err, wantErr)
	}
}

func TestApplyRejectsEmptyRuleset(t *testing.T) {
	if err := Apply(context.Background(), " \n", nil); err == nil {
		t.Fatal("Apply(empty) = nil, want error")
	}
}

func TestCleanup(t *testing.T) {
	var scripts []string
	runner := func(_ context.Context, script string) error {
		scripts = append(scripts, script)
		return nil
	}
	for i := 0; i < 2; i++ {
		if err := Cleanup(runner); err != nil {
			t.Fatalf("Cleanup() call %d = %v, want nil", i+1, err)
		}
	}
	want := "delete table ip teslagateway\n"
	if len(scripts) != 2 {
		t.Fatalf("runner called %d times, want 2", len(scripts))
	}
	for i, script := range scripts {
		if script != want {
			t.Errorf("cleanup script %d = %q, want %q", i+1, script, want)
		}
	}
}

func TestCleanupPropagatesRunnerError(t *testing.T) {
	wantErr := errors.New("nft failed")
	err := Cleanup(func(context.Context, string) error { return wantErr })
	if !errors.Is(err, wantErr) {
		t.Fatalf("Cleanup() = %v, want wrapped %v", err, wantErr)
	}
}

func TestSubtractPrefix(t *testing.T) {
	tests := []struct {
		name    string
		prefix  string
		exclude string
		want    []string
	}{
		{
			name:    "disjoint",
			prefix:  "100.64.1.0/24",
			exclude: "100.64.0.0/24",
			want:    []string{"100.64.1.0/24"},
		},
		{
			name:    "exclude contains prefix",
			prefix:  "100.64.0.0/24",
			exclude: "100.64.0.0/16",
		},
		{
			name:    "prefix contains exclude",
			prefix:  "100.64.0.0/22",
			exclude: "100.64.1.0/24",
			want:    []string{"100.64.0.0/24", "100.64.2.0/23"},
		},
		{
			name:    "whole IPv4 space minus half",
			prefix:  "0.0.0.0/0",
			exclude: "0.0.0.0/1",
			want:    []string{"128.0.0.0/1"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			prefix := mustPrefix(t, tc.prefix)
			exclude := mustPrefix(t, tc.exclude)
			got := subtractPrefix(prefix, exclude)
			gotStrings := make([]string, 0, len(got))
			for _, p := range got {
				gotStrings = append(gotStrings, p.String())
			}
			if !slices.Equal(gotStrings, tc.want) {
				t.Fatalf("subtractPrefix(%s, %s) = %v, want %v", prefix, exclude, gotStrings, tc.want)
			}
			for _, p := range got {
				if p.Overlaps(exclude) {
					t.Errorf("result %s overlaps excluded %s", p, exclude)
				}
			}
		})
	}
}
