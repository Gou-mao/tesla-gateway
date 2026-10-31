package stats

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"tesla-gateway/internal/logx"
)

const (
	// DefaultPath is the default location of the published stats snapshot.
	DefaultPath = "/var/run/tesla-gateway/stats.json"
	// DefaultInterval is the normal publication interval.
	DefaultInterval = 2 * time.Second
	// DefaultVersion is reported when no build version is supplied.
	DefaultVersion = "dev"
)

// Listeners contains the bound listener addresses reported to management
// frontends. An empty string means that the corresponding service is disabled.
type Listeners struct {
	DNS   string `json:"dns"`
	Proxy string `json:"proxy"`
}

// Mapping is one real-to-Tesla-visible prefix pair. Both values are the CIDR
// strings from the configuration, kept verbatim so the UI can explain the
// forwarding relationship without reimplementing prefix parsing.
type Mapping struct {
	From string `json:"from"`
	To   string `json:"to"`
}

// Meta is the static configuration metadata published alongside the runtime
// counters. It contains no secrets and changes only when the process restarts
// with a different configuration.
type Meta struct {
	Version              string    `json:"version"`
	Listeners            Listeners `json:"listeners"`
	Mappings             []Mapping `json:"mappings"`
	MappingStrategy      string    `json:"mapping_strategy"`
	DNSListen            string    `json:"dns_listen"`
	DNSUpstream          []string  `json:"dns_upstream"`
	DNSUpstreamEffective []string  `json:"dns_upstream_effective"`
}

// WriterConfig configures a stats file Writer.
type WriterConfig struct {
	// Path is the destination JSON file. Empty uses DefaultPath.
	Path string
	// Interval is the periodic publication interval. Zero uses 2s.
	Interval time.Duration
	// PID is the process id reported in the file. Zero uses os.Getpid().
	PID int
	// StartedAt is the process start time. Zero uses Stats.StartedAt().
	StartedAt time.Time
	// Meta is the static configuration metadata merged into every snapshot.
	Meta Meta
	// EffectiveUpstream optionally reports the resolver's current effective
	// upstream IP list. It is called on every write so DHCP expansions are
	// reflected without a restart. When nil, Meta.DNSUpstreamEffective is
	// published as-is.
	EffectiveUpstream func() []string
}

// FileSnapshot is the top-level JSON document written by Writer. The static
// meta fields and the dynamic DNS/proxy counters are merged into one object.
type FileSnapshot struct {
	Version              string        `json:"version"`
	PID                  int           `json:"pid"`
	StartedAt            string        `json:"started_at"`
	UptimeSec            int64         `json:"uptime_sec"`
	Listeners            Listeners     `json:"listeners"`
	Mappings             []Mapping     `json:"mappings"`
	MappingStrategy      string        `json:"mapping_strategy"`
	DNSListen            string        `json:"dns_listen"`
	DNSUpstream          []string      `json:"dns_upstream"`
	DNSUpstreamEffective []string      `json:"dns_upstream_effective"`
	DNS                  DNSSnapshot   `json:"dns"`
	Proxy                ProxySnapshot `json:"proxy"`
}

// Writer periodically publishes Stats as a JSON file. Writes are serialized and
// each file replacement is atomic (write to path+".tmp", then rename).
type Writer struct {
	cfg    WriterConfig
	stats  *Stats
	logger *logx.Logger

	mu sync.Mutex
}

// NewWriter creates a stats file writer. It does not touch the filesystem until
// Write or Run is called, so an unwritable directory is reported as a warning
// by Run rather than as a fatal startup error.
func NewWriter(cfg WriterConfig, st *Stats, logger *logx.Logger) (*Writer, error) {
	if st == nil {
		return nil, errors.New("stats: writer requires a non-nil Stats")
	}

	if strings.TrimSpace(cfg.Path) == "" {
		cfg.Path = DefaultPath
	} else {
		cfg.Path = strings.TrimSpace(cfg.Path)
	}
	if cfg.Interval <= 0 {
		cfg.Interval = DefaultInterval
	}
	cfg.Meta = normalizeMeta(cfg.Meta)
	if cfg.PID <= 0 {
		cfg.PID = os.Getpid()
	}
	if cfg.StartedAt.IsZero() {
		cfg.StartedAt = st.StartedAt()
		if cfg.StartedAt.IsZero() {
			cfg.StartedAt = time.Now()
		}
	}

	return &Writer{
		cfg:    cfg,
		stats:  st,
		logger: logger,
	}, nil
}

func normalizeMeta(meta Meta) Meta {
	meta.Version = strings.TrimSpace(meta.Version)
	if meta.Version == "" {
		meta.Version = DefaultVersion
	}
	meta.MappingStrategy = strings.TrimSpace(meta.MappingStrategy)
	meta.DNSListen = strings.TrimSpace(meta.DNSListen)

	// Always publish arrays rather than null so LuCI can iterate them without
	// a separate presence check.
	mappings := make([]Mapping, 0, len(meta.Mappings))
	mappings = append(mappings, meta.Mappings...)
	meta.Mappings = mappings

	upstream := make([]string, 0, len(meta.DNSUpstream))
	upstream = append(upstream, meta.DNSUpstream...)
	meta.DNSUpstream = upstream

	effective := make([]string, 0, len(meta.DNSUpstreamEffective))
	effective = append(effective, meta.DNSUpstreamEffective...)
	meta.DNSUpstreamEffective = effective

	return meta
}

// Path returns the configured destination path.
func (w *Writer) Path() string {
	if w == nil {
		return ""
	}
	return w.cfg.Path
}

// Interval returns the configured publication interval.
func (w *Writer) Interval() time.Duration {
	if w == nil {
		return 0
	}
	return w.cfg.Interval
}

// Write publishes one snapshot immediately. The write is atomic from a
// reader's point of view: data goes to path+".tmp" and is then renamed over
// path.
func (w *Writer) Write() error {
	if w == nil {
		return errors.New("stats: nil writer")
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	snapshot := w.stats.Snapshot()
	now := time.Now()
	uptime := int64(now.Sub(w.cfg.StartedAt) / time.Second)
	if uptime < 0 {
		uptime = 0
	}

	effectiveUpstream := w.cfg.Meta.DNSUpstreamEffective
	if w.cfg.EffectiveUpstream != nil {
		effectiveUpstream = w.cfg.EffectiveUpstream()
	}
	effectiveUpstream = append([]string{}, effectiveUpstream...)

	document := FileSnapshot{
		Version:              w.cfg.Meta.Version,
		PID:                  w.cfg.PID,
		StartedAt:            w.cfg.StartedAt.UTC().Format(time.RFC3339),
		UptimeSec:            uptime,
		Listeners:            w.cfg.Meta.Listeners,
		Mappings:             append([]Mapping{}, w.cfg.Meta.Mappings...),
		MappingStrategy:      w.cfg.Meta.MappingStrategy,
		DNSListen:            w.cfg.Meta.DNSListen,
		DNSUpstream:          append([]string{}, w.cfg.Meta.DNSUpstream...),
		DNSUpstreamEffective: effectiveUpstream,
		DNS:                  snapshot.DNS,
		Proxy:                snapshot.Proxy,
	}

	data, err := json.Marshal(document)
	if err != nil {
		return fmt.Errorf("stats: marshal snapshot: %w", err)
	}
	data = append(data, '\n')

	if err := writeFileAtomic(w.cfg.Path, data); err != nil {
		return err
	}
	return nil
}

// Run publishes one snapshot immediately, then one every Interval, and writes
// a final snapshot when ctx is cancelled. Write failures are logged as
// warnings and never stop the loop.
func (w *Writer) Run(ctx context.Context) {
	if w == nil {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}

	w.writeAndLog()

	ticker := time.NewTicker(w.cfg.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			w.writeAndLog()
			return
		case <-ticker.C:
			w.writeAndLog()
		}
	}
}

func (w *Writer) writeAndLog() {
	if err := w.Write(); err != nil {
		w.logger.Warn("failed to write stats snapshot", logx.Fields{
			"path":  w.cfg.Path,
			"error": err.Error(),
		})
	}
}

func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("stats: create directory %s: %w", dir, err)
	}

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("stats: write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("stats: rename %s to %s: %w", tmp, path, err)
	}
	return nil
}
