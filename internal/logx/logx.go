// Package logx provides small structured JSON loggers built on the standard
// library. It intentionally has no third-party dependencies.
package logx

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

// Level is a log severity. Lower values are more verbose.
type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
)

// String returns the lowercase name of the level.
func (l Level) String() string {
	switch l {
	case LevelDebug:
		return "debug"
	case LevelInfo:
		return "info"
	case LevelWarn:
		return "warn"
	case LevelError:
		return "error"
	default:
		return "unknown"
	}
}

// ParseLevel parses a configuration level name. An empty string means info.
func ParseLevel(s string) (Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "info":
		return LevelInfo, nil
	case "debug":
		return LevelDebug, nil
	case "warn", "warning":
		return LevelWarn, nil
	case "error":
		return LevelError, nil
	default:
		return LevelInfo, fmt.Errorf("logx: invalid log level %q", s)
	}
}

// Fields is a set of structured fields added to a log record.
type Fields map[string]any

// Config configures a Logger.
type Config struct {
	// Level is one of debug, info, warn, or error. Empty means info.
	Level string
	// Format is "json" or empty. Only JSON output is supported.
	Format string
	// Output defaults to os.Stderr.
	Output io.Writer
	// Module, when set, is added to every record as the "module" field.
	Module string
}

// Logger writes structured JSON records. A Logger is safe for concurrent use.
type Logger struct {
	core   *core
	fields Fields
}

type core struct {
	mu    sync.Mutex
	enc   *json.Encoder
	level Level
}

// New creates a JSON logger.
func New(cfg Config) (*Logger, error) {
	format := strings.ToLower(strings.TrimSpace(cfg.Format))
	if format != "" && format != "json" {
		return nil, fmt.Errorf("logx: unsupported log format %q (only json is supported)", cfg.Format)
	}

	level, err := ParseLevel(cfg.Level)
	if err != nil {
		return nil, err
	}

	out := cfg.Output
	if out == nil {
		out = os.Stderr
	}

	enc := json.NewEncoder(out)
	enc.SetEscapeHTML(false)

	l := &Logger{
		core: &core{
			enc:   enc,
			level: level,
		},
		fields: make(Fields),
	}
	if module := strings.TrimSpace(cfg.Module); module != "" {
		l.fields["module"] = module
	}
	return l, nil
}

// With returns a child logger whose records include fields in addition to the
// parent's fields. The child shares the parent's output and level.
func (l *Logger) With(fields Fields) *Logger {
	if l == nil {
		return nil
	}
	merged := make(Fields, len(l.fields)+len(fields))
	for k, v := range l.fields {
		merged[k] = v
	}
	for k, v := range fields {
		merged[k] = v
	}
	return &Logger{core: l.core, fields: merged}
}

// WithModule returns a child logger with the "module" field set.
func (l *Logger) WithModule(module string) *Logger {
	return l.With(Fields{"module": module})
}

// Debug logs at debug level.
func (l *Logger) Debug(msg string, fields Fields) { l.log(LevelDebug, msg, fields) }

// Info logs at info level.
func (l *Logger) Info(msg string, fields Fields) { l.log(LevelInfo, msg, fields) }

// Warn logs at warn level.
func (l *Logger) Warn(msg string, fields Fields) { l.log(LevelWarn, msg, fields) }

// Error logs at error level.
func (l *Logger) Error(msg string, fields Fields) { l.log(LevelError, msg, fields) }

func (l *Logger) log(level Level, msg string, fields Fields) {
	if l == nil || l.core == nil || level < l.core.level {
		return
	}

	record := make(map[string]any, len(l.fields)+len(fields)+3)
	for k, v := range l.fields {
		record[k] = v
	}
	for k, v := range fields {
		record[k] = v
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)
	record["time"] = now
	record["level"] = level.String()
	record["msg"] = msg

	l.core.mu.Lock()
	defer l.core.mu.Unlock()

	if err := l.core.enc.Encode(record); err != nil {
		// A field contained a value encoding/json cannot marshal. Emit a valid
		// fallback record so a logging call never breaks the caller.
		_ = l.core.enc.Encode(map[string]any{
			"time":  now,
			"level": LevelError.String(),
			"msg":   "failed to encode log record",
			"error": err.Error(),
		})
	}
}
