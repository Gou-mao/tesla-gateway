package proxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"tesla-gateway/internal/logx"
	"tesla-gateway/internal/mapping"
)

const (
	defaultKeepAlive   = 15 * time.Second
	defaultMaxConns    = 1024
	defaultDialTimeout = 10 * time.Second
	stopTimeout        = 5 * time.Second
	acceptRetryDelay   = 50 * time.Millisecond
)

// TCPConfig configures a TCPProxy.
type TCPConfig struct {
	// Listen is the transparent proxy listener, for example ":16464".
	Listen string
	// KeepAlive is applied to upstream TCP connections. Zero uses 15s.
	KeepAlive time.Duration
	// MaxConns limits concurrently proxied connections. Zero uses 1024.
	MaxConns int
	// IdleTimeout closes a connection when neither direction makes progress
	// for this long. Zero disables the idle timeout.
	IdleTimeout time.Duration
	// DialTimeout bounds upstream connection establishment. Zero uses 10s.
	DialTimeout time.Duration
}

// OriginalDstFunc resolves the pre-redirect destination of an accepted
// connection. It is injectable for tests because SO_ORIGINAL_DST requires a
// real NAT redirect and privileges.
type OriginalDstFunc func(*net.TCPConn) (netip.AddrPort, error)

// TCPProxy implements transparent TCP relaying. Every accepted connection is
// translated through mapping.Engine.Reverse and relayed byte-for-byte.
type TCPProxy struct {
	cfg       TCPConfig
	engine    *mapping.Engine
	logger    *logx.Logger
	origDstFn OriginalDstFunc
	relayFn   relayFunc

	mu       sync.Mutex
	ln       net.Listener
	conns    map[*net.TCPConn]struct{}
	started  bool
	stopping bool
	cancel   context.CancelFunc
	done     chan struct{}
	wg       sync.WaitGroup
}

var _ Proxy = (*TCPProxy)(nil)

// TCPOption customises a TCPProxy, primarily for tests.
type TCPOption func(*TCPProxy)

// WithOriginalDst replaces the platform original-destination lookup.
func WithOriginalDst(fn OriginalDstFunc) TCPOption {
	return func(p *TCPProxy) {
		if fn != nil {
			p.origDstFn = fn
		}
	}
}

// NewTCPProxy creates a TCP proxy. Call Start to bind the listener.
func NewTCPProxy(cfg TCPConfig, engine *mapping.Engine, logger *logx.Logger, opts ...TCPOption) (*TCPProxy, error) {
	if strings.TrimSpace(cfg.Listen) == "" {
		return nil, errors.New("proxy: tcp listen address is empty")
	}
	if engine == nil {
		return nil, errors.New("proxy: mapping engine is nil")
	}
	if cfg.KeepAlive <= 0 {
		cfg.KeepAlive = defaultKeepAlive
	}
	if cfg.MaxConns <= 0 {
		cfg.MaxConns = defaultMaxConns
	}
	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = defaultDialTimeout
	}

	if logger == nil {
		var err error
		logger, err = logx.New(logx.Config{Module: "proxy"})
		if err != nil {
			return nil, fmt.Errorf("proxy: create logger: %w", err)
		}
	} else {
		logger = logger.WithModule("proxy")
	}

	p := &TCPProxy{
		cfg:       cfg,
		engine:    engine,
		logger:    logger,
		origDstFn: OriginalDst,
		relayFn:   relayWith,
		conns:     make(map[*net.TCPConn]struct{}),
	}
	for _, opt := range opts {
		if opt != nil {
			opt(p)
		}
	}
	return p, nil
}

// Name implements Proxy.
func (p *TCPProxy) Name() string {
	return "tcp"
}

// Addr returns the bound listener address after Start.
func (p *TCPProxy) Addr() string {
	if p == nil {
		return ""
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.ln == nil {
		return ""
	}
	return p.ln.Addr().String()
}

// Start binds the listener and starts the accept loop. It returns once the
// listener is ready; the loop runs until ctx is cancelled or Stop is called.
func (p *TCPProxy) Start(ctx context.Context) error {
	if p == nil {
		return errors.New("proxy: nil tcp proxy")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if p.started {
		return errors.New("proxy: tcp proxy already started")
	}

	ln, err := net.Listen("tcp", p.cfg.Listen)
	if err != nil {
		return fmt.Errorf("proxy: listen %s: %w", p.cfg.Listen, err)
	}

	acceptCtx, cancel := context.WithCancel(ctx)
	p.ln = ln
	p.cancel = cancel
	p.done = make(chan struct{})
	p.started = true
	p.stopping = false

	go p.acceptLoop(acceptCtx, ln, p.done)
	return nil
}

func (p *TCPProxy) acceptLoop(ctx context.Context, ln net.Listener, done chan struct{}) {
	defer close(done)

	sem := make(chan struct{}, p.cfg.MaxConns)
	for {
		// Acquire capacity before accepting. When the proxy is saturated new
		// connections wait in the kernel backlog instead of piling up as
		// accepted-but-unserved sockets.
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			return
		}

		conn, err := ln.Accept()
		if err != nil {
			<-sem
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			p.logger.Warn("tcp proxy accept failed", logx.Fields{
				"error": err.Error(),
			})
			timer := time.NewTimer(acceptRetryDelay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
			continue
		}

		client, ok := conn.(*net.TCPConn)
		if !ok {
			_ = conn.Close()
			<-sem
			p.logger.Error("tcp proxy accepted non-TCP connection", logx.Fields{
				"remote": conn.RemoteAddr().String(),
			})
			continue
		}
		if !p.track(client) {
			_ = client.Close()
			<-sem
			continue
		}

		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			defer func() { <-sem }()
			defer p.untrack(client)
			p.handleConn(ctx, client)
		}()
	}
}

func (p *TCPProxy) track(c *net.TCPConn) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.stopping {
		return false
	}
	p.conns[c] = struct{}{}
	return true
}

func (p *TCPProxy) untrack(c *net.TCPConn) {
	p.mu.Lock()
	delete(p.conns, c)
	p.mu.Unlock()
}

func (p *TCPProxy) handleConn(ctx context.Context, client *net.TCPConn) {
	// Every path that returns early (bad original destination, no mapping,
	// dial failure) must still release the accepted socket.
	defer func() { _ = client.Close() }()

	start := time.Now()

	fields := logx.Fields{
		"remote": client.RemoteAddr().String(),
		"port":   0,
	}

	if err := ctx.Err(); err != nil {
		return
	}

	dst, err := p.origDstFn(client)
	if err != nil {
		if ctx.Err() != nil {
			return
		}
		fields["success"] = false
		fields["error"] = err.Error()
		p.logger.Warn("tcp proxy original destination lookup failed", fields)
		return
	}
	fields["dst"] = dst.Addr().String()
	fields["port"] = dst.Port()

	realIP, ok := p.engine.Reverse(dst.Addr())
	if !ok {
		fields["success"] = false
		p.logger.Warn("tcp proxy has no mapping for original destination", fields)
		return
	}
	target := netip.AddrPortFrom(realIP, dst.Port())
	fields["real"] = realIP.String()
	fields["target"] = target.String()

	dialStart := time.Now()
	dialer := net.Dialer{
		Timeout:   p.cfg.DialTimeout,
		KeepAlive: p.cfg.KeepAlive,
	}
	upstreamConn, err := dialer.DialContext(ctx, "tcp", target.String())
	fields["latency_ms"] = durationMillis(time.Since(dialStart))
	if err != nil {
		fields["success"] = false
		fields["error"] = err.Error()
		p.logger.Warn("tcp proxy upstream dial failed", fields)
		return
	}

	upstream, ok := upstreamConn.(*net.TCPConn)
	if !ok {
		_ = upstreamConn.Close()
		fields["success"] = false
		fields["error"] = "dial did not return a TCP connection"
		p.logger.Error("tcp proxy upstream dial returned non-TCP connection", fields)
		return
	}
	if !p.track(upstream) {
		_ = upstream.Close()
		return
	}
	defer p.untrack(upstream)

	idle := newIdleWatch(p.cfg.IdleTimeout, client, upstream)
	if idle != nil {
		defer idle.Stop()
	}

	relayFn := p.relayFn
	if relayFn == nil {
		relayFn = relayWith
	}

	var (
		wg        sync.WaitGroup
		upBytes   int64
		downBytes int64
		upErr     error
		downErr   error
	)

	closeBoth := func() {
		_ = client.Close()
		_ = upstream.Close()
	}

	wg.Add(2)
	go func() {
		defer wg.Done()
		upBytes, upErr = relayFn(upstream, client, idle.Touch)
		if upErr != nil {
			closeBoth()
			return
		}
		// The client finished sending. Propagate the half-close while the
		// other direction keeps flowing.
		_ = upstream.CloseWrite()
	}()
	go func() {
		defer wg.Done()
		downBytes, downErr = relayFn(client, upstream, idle.Touch)
		if downErr != nil {
			closeBoth()
			return
		}
		_ = client.CloseWrite()
	}()
	wg.Wait()

	_ = client.Close()
	_ = upstream.Close()

	fields["success"] = upErr == nil && downErr == nil
	fields["bytes_client_to_upstream"] = upBytes
	fields["bytes_upstream_to_client"] = downBytes
	fields["duration_ms"] = durationMillis(time.Since(start))
	if err := errors.Join(upErr, downErr); err != nil {
		fields["error"] = err.Error()
		p.logger.Warn("tcp proxy connection closed", fields)
		return
	}
	p.logger.Info("tcp proxy connection closed", fields)
}

// Stop closes the listener and every active connection, then waits for the
// accept loop and connection handlers to exit.
func (p *TCPProxy) Stop() error {
	if p == nil {
		return nil
	}

	p.mu.Lock()
	if !p.started || p.stopping {
		p.mu.Unlock()
		return nil
	}
	p.stopping = true

	cancel := p.cancel
	ln := p.ln
	done := p.done
	active := make([]*net.TCPConn, 0, len(p.conns))
	for c := range p.conns {
		active = append(active, c)
	}
	p.mu.Unlock()

	if cancel != nil {
		cancel()
	}

	var errs []error
	if ln != nil {
		if err := ln.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			errs = append(errs, fmt.Errorf("proxy: close listener: %w", err))
		}
	}
	for _, c := range active {
		_ = c.Close()
	}

	if done != nil {
		select {
		case <-done:
		case <-time.After(stopTimeout):
			errs = append(errs, errors.New("proxy: accept loop shutdown timed out"))
		}
	}

	handlersDone := make(chan struct{})
	go func() {
		p.wg.Wait()
		close(handlersDone)
	}()
	select {
	case <-handlersDone:
	case <-time.After(stopTimeout):
		errs = append(errs, errors.New("proxy: connection shutdown timed out"))
	}

	p.mu.Lock()
	p.started = false
	p.stopping = false
	p.ln = nil
	p.cancel = nil
	p.done = nil
	p.mu.Unlock()

	return errors.Join(errs...)
}

func durationMillis(d time.Duration) float64 {
	return float64(d.Microseconds()) / 1000
}

// idleWatch closes both connections when neither relay direction has made
// progress for timeout. A single clock per connection means an active download
// does not time out because the request direction is quiet.
type idleWatch struct {
	timeout time.Duration
	conns   []*net.TCPConn
	start   time.Time
	last    atomic.Int64
	done    chan struct{}
	once    sync.Once
}

func newIdleWatch(timeout time.Duration, conns ...*net.TCPConn) *idleWatch {
	if timeout <= 0 || len(conns) == 0 {
		return nil
	}
	w := &idleWatch{
		timeout: timeout,
		conns:   conns,
		start:   time.Now(),
		done:    make(chan struct{}),
	}
	w.last.Store(0)

	interval := timeout / 4
	if interval < 10*time.Millisecond {
		interval = 10 * time.Millisecond
	}
	if interval > time.Second {
		interval = time.Second
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-w.done:
				return
			case <-ticker.C:
				idle := time.Since(w.start) - time.Duration(w.last.Load())
				if idle < timeout {
					continue
				}
				// Closing unblocks both relay goroutines; they then return an
				// error and the connection is logged as unsuccessful.
				for _, c := range w.conns {
					_ = c.Close()
				}
				return
			}
		}
	}()
	return w
}

func (w *idleWatch) Touch() {
	if w == nil {
		return
	}
	w.last.Store(time.Since(w.start).Nanoseconds())
}

func (w *idleWatch) Stop() {
	if w == nil {
		return
	}
	w.once.Do(func() { close(w.done) })
}
