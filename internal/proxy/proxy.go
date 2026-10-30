// Package proxy implements the transparent L4 proxy used by Tesla Gateway.
//
// The proxy is deliberately byte-transparent: it never inspects or modifies
// TLS records or any other application payload. It only moves bytes between
// TCP connections.
package proxy

import (
	"context"
	"io"
	"net"
)

// Proxy is a transparent proxy service. Start binds and begins serving, then
// returns; Stop gracefully shuts the service down.
type Proxy interface {
	Start(ctx context.Context) error
	Stop() error
	Name() string
}

// relayFunc copies bytes from src to dst until src reaches EOF or an error
// occurs. onActivity, when non-nil, is called after progress is made and is
// used by the idle-timeout watchdog.
type relayFunc func(dst, src *net.TCPConn, onActivity func()) (int64, error)

type activityReader struct {
	r     io.Reader
	touch func()
}

func (r activityReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	if n > 0 && r.touch != nil {
		r.touch()
	}
	return n, err
}

type activityWriter struct {
	w     io.Writer
	touch func()
}

func (w activityWriter) Write(p []byte) (int, error) {
	n, err := w.w.Write(p)
	if n > 0 && w.touch != nil {
		w.touch()
	}
	return n, err
}

// copyFallback is the portable relay implementation. It is also used when the
// platform-specific splice path reports that splice is unsupported.
func copyFallback(dst, src *net.TCPConn, onActivity func()) (int64, error) {
	if onActivity == nil {
		return io.Copy(dst, src)
	}
	return io.Copy(
		activityWriter{w: dst, touch: onActivity},
		activityReader{r: src, touch: onActivity},
	)
}
