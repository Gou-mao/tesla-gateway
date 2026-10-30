package logx_test

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"

	"tesla-gateway/internal/logx"
)

func TestJSONOutputAndLevelFiltering(t *testing.T) {
	var buf bytes.Buffer
	logger, err := logx.New(logx.Config{
		Level:  "info",
		Format: "json",
		Output: &buf,
		Module: "dns",
	})
	if err != nil {
		t.Fatalf("New() = %v, want nil", err)
	}

	logger.Debug("ignored", logx.Fields{"host": "should-not-appear"})
	logger.Info("translated", logx.Fields{
		"host":       "nas.home",
		"real":       netip.MustParseAddr("192.168.1.251"),
		"mapped":     netip.MustParseAddr("100.64.1.251"),
		"latency_ms": 1.5,
	})

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("got %d log lines, want 1: %q", len(lines), buf.String())
	}

	var record map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &record); err != nil {
		t.Fatalf("log line is not valid JSON: %v: %q", err, lines[0])
	}
	if record["level"] != "info" {
		t.Errorf("level = %v, want info", record["level"])
	}
	if record["msg"] != "translated" {
		t.Errorf("msg = %v, want translated", record["msg"])
	}
	if record["module"] != "dns" {
		t.Errorf("module = %v, want dns", record["module"])
	}
	if record["host"] != "nas.home" {
		t.Errorf("host = %v, want nas.home", record["host"])
	}
	if record["real"] != "192.168.1.251" {
		t.Errorf("real = %v, want 192.168.1.251", record["real"])
	}
	if record["mapped"] != "100.64.1.251" {
		t.Errorf("mapped = %v, want 100.64.1.251", record["mapped"])
	}
	if record["latency_ms"] != 1.5 {
		t.Errorf("latency_ms = %v, want 1.5", record["latency_ms"])
	}
	if _, ok := record["time"]; !ok {
		t.Error("time field missing")
	}
}

func TestWithFields(t *testing.T) {
	var buf bytes.Buffer
	logger, err := logx.New(logx.Config{Output: &buf})
	if err != nil {
		t.Fatalf("New() = %v, want nil", err)
	}

	child := logger.With(logx.Fields{"host": "printer.local"}).WithModule("proxy")
	child.Warn("reverse failed", logx.Fields{"error": "not mapped"})

	var record map[string]any
	if err := json.Unmarshal(buf.Bytes(), &record); err != nil {
		t.Fatalf("log line is not valid JSON: %v: %q", err, buf.String())
	}
	if record["level"] != "warn" || record["module"] != "proxy" || record["host"] != "printer.local" {
		t.Errorf("record = %v", record)
	}
}

func TestNewErrors(t *testing.T) {
	if _, err := logx.New(logx.Config{Level: "verbose"}); err == nil {
		t.Error("New() with invalid level = nil, want error")
	}
	if _, err := logx.New(logx.Config{Format: "text"}); err == nil {
		t.Error("New() with unsupported format = nil, want error")
	}
}

func TestParseLevel(t *testing.T) {
	tests := map[string]logx.Level{
		"":        logx.LevelInfo,
		"DEBUG":   logx.LevelDebug,
		"info":    logx.LevelInfo,
		"warning": logx.LevelWarn,
		"error":   logx.LevelError,
	}
	for input, want := range tests {
		got, err := logx.ParseLevel(input)
		if err != nil {
			t.Errorf("ParseLevel(%q) = %v", input, err)
			continue
		}
		if got != want {
			t.Errorf("ParseLevel(%q) = %v, want %v", input, got, want)
		}
	}
}
