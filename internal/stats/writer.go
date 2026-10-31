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

// WriterConfig configures a stats file Writer.
type WriterConfig struct {
	// Path is the destination JSON file. Empty uses DefaultPath.
	Path string
	// Interval is the periodic publication interval. Zero uses 2s.
	Interval time.Duration
	// Version is the program version string. Empty uses "dev".
	Version string
	// PID is the process id reported in the file. Zero uses os.Getpid().
	PID int
	// StartedAt is the process start time. Zero uses Stats.StartedAt().
	StartedAt time.Time
	// Listeners contains the bound DNS and proxy addresses.
	Listeners Listeners
	// MappedPrefixes is the list of advertised mapped prefixes.
	MappedPrefixes []string
}

// FileSnapshot is the top-level JSON document written by Writer.
type FileSnapshot struct {
	Version        string        `json:"version"`
	PID            int           `json:"pid"`
	StartedAt      string        `json:"started_at"`
	UptimeSec      int64         `json:"uptime_sec"`
	Listeners      Listeners     `json:"listeners"`
	MappedPrefixes []string      `json:"mapped_prefixes"`
	DNS            DNSSnapshot   `json:"dns"`
	Proxy          ProxySnapshot `json:"proxy"`
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
	if strings.TrimSpace(cfg.Version) == "" {
		cfg.Version = DefaultVersion
	} else {
		cfg.Version = strings.TrimSpace(cfg.Version)
	}
	if cfg.PID <= 0 {
		cfg.PID = os.Getpid()
	}
	if cfg.StartedAt.IsZero() {
		cfg.StartedAt = st.StartedAt()
		if cfg.StartedAt.IsZero() {
			cfg.StartedAt = time.Now()
		}
	}
	cfg.MappedPrefixes = append([]string(nil), cfg.MappedPrefixes...)

	return &Writer{
		cfg:    cfg,
		stats:  st,
		logger: logger,
	}, nil
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

	document := FileSnapshot{
		Version:        w.cfg.Version,
		PID:            w.cfg.PID,
		StartedAt:      w.cfg.StartedAt.UTC().Format(time.RFC3339),
		UptimeSec:      uptime,
		Listeners:      w.cfg.Listeners,
		MappedPrefixes: append([]string{}, w.cfg.MappedPrefixes...),
		DNS:            snapshot.DNS,
		Proxy:          snapshot.Proxy,
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
