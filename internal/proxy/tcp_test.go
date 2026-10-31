package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"tesla-gateway/internal/logx"
	"tesla-gateway/internal/mapping"
	"tesla-gateway/internal/stats"
)

func newTestMapping(t *testing.T) (*mapping.Engine, netip.Addr) {
	t.Helper()
	strategy := mapping.NewPrefixMappingStrategy([]mapping.PrefixMapping{{
		From: netip.MustParsePrefix("127.0.0.1/32"),
		To:   netip.MustParsePrefix("100.64.9.1/32"),
	}})
	if err := strategy.Validate(); err != nil {
		t.Fatalf("validate mapping: %v", err)
	}
	return mapping.NewEngine(strategy), netip.MustParseAddr("100.64.9.1")
}

type testTCPServer struct {
	ln      net.Listener
	handler func(*net.TCPConn)

	mu     sync.Mutex
	closed bool
	conns  map[*net.TCPConn]struct{}
	wg     sync.WaitGroup
}

func startTCPServer(t *testing.T, handler func(*net.TCPConn)) *testTCPServer {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen test server: %v", err)
	}
	s := &testTCPServer{
		ln:      ln,
		handler: handler,
		conns:   make(map[*net.TCPConn]struct{}),
	}
	go s.acceptLoop()
	t.Cleanup(s.Close)
	return s
}

func (s *testTCPServer) Addr() netip.AddrPort {
	return netip.MustParseAddrPort(s.ln.Addr().String())
}

func (s *testTCPServer) acceptLoop() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		c := conn.(*net.TCPConn)
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			_ = c.Close()
			continue
		}
		s.conns[c] = struct{}{}
		s.wg.Add(1)
		s.mu.Unlock()

		go func() {
			defer s.wg.Done()
			defer func() {
				s.mu.Lock()
				delete(s.conns, c)
				s.mu.Unlock()
				_ = c.Close()
			}()
			s.handler(c)
		}()
	}
}

func (s *testTCPServer) Close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	_ = s.ln.Close()
	for c := range s.conns {
		_ = c.Close()
	}
	s.mu.Unlock()
	s.wg.Wait()
}

func startTestProxy(t *testing.T, engine *mapping.Engine, origDst OriginalDstFunc, relayFn relayFunc, idle time.Duration, runtimeStats ...*stats.Stats) (*TCPProxy, netip.AddrPort, *bytes.Buffer) {
	t.Helper()
	var logs bytes.Buffer
	logger, err := logx.New(logx.Config{
		Level:  "debug",
		Output: &logs,
	})
	if err != nil {
		t.Fatalf("create logger: %v", err)
	}

	var st *stats.Stats
	if len(runtimeStats) > 0 {
		st = runtimeStats[0]
	}
	p, err := NewTCPProxy(TCPConfig{
		Listen:      "127.0.0.1:0",
		KeepAlive:   time.Second,
		MaxConns:    16,
		IdleTimeout: idle,
		DialTimeout: 2 * time.Second,
		Stats:       st,
	}, engine, logger, WithOriginalDst(origDst))
	if err != nil {
		t.Fatalf("create proxy: %v", err)
	}
	if relayFn != nil {
		p.relayFn = relayFn
	}
	if err := p.Start(context.Background()); err != nil {
		t.Fatalf("start proxy: %v", err)
	}
	t.Cleanup(func() {
		if err := p.Stop(); err != nil {
			t.Errorf("stop proxy: %v", err)
		}
	})
	return p, netip.MustParseAddrPort(p.Addr()), &logs
}

func dialTestProxy(t *testing.T, addr netip.AddrPort) *net.TCPConn {
	t.Helper()
	dialer := net.Dialer{Timeout: 2 * time.Second}
	conn, err := dialer.Dial("tcp", addr.String())
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	c := conn.(*net.TCPConn)
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func lastLogRecord(t *testing.T, logs *bytes.Buffer) map[string]any {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(logs.String()), "\n")
	if len(lines) == 0 || lines[len(lines)-1] == "" {
		t.Fatalf("no log records: %q", logs.String())
	}
	var rec map[string]any
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &rec); err != nil {
		t.Fatalf("parse log record %q: %v", lines[len(lines)-1], err)
	}
	return rec
}

func echoHandler(c *net.TCPConn) {
	buf := make([]byte, 32*1024)
	for {
		n, err := c.Read(buf)
		if n > 0 {
			if _, werr := c.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			_ = c.CloseWrite()
			return
		}
	}
}

func TestTCPProxyEndToEnd(t *testing.T) {
	payload := bytes.Repeat([]byte("tesla-gateway-transparent-tcp-"), 4096)

	relays := []struct {
		name    string
		relayFn relayFunc
	}{
		{name: "platform_default", relayFn: nil},
		{name: "io_copy_fallback", relayFn: copyFallback},
	}

	for _, tc := range relays {
		t.Run(tc.name, func(t *testing.T) {
			server := startTCPServer(t, echoHandler)
			engine, mapped := newTestMapping(t)
			origDst := func(*net.TCPConn) (netip.AddrPort, error) {
				return netip.AddrPortFrom(mapped, server.Addr().Port()), nil
			}

			p, proxyAddr, logs := startTestProxy(t, engine, origDst, tc.relayFn, 0)
			conn := dialTestProxy(t, proxyAddr)

			writeDone := make(chan error, 1)
			go func() {
				_, err := conn.Write(payload)
				if err == nil {
					err = conn.CloseWrite()
				}
				writeDone <- err
			}()

			got, err := io.ReadAll(conn)
			if err != nil {
				t.Fatalf("read echoed payload: %v", err)
			}
			if err := <-writeDone; err != nil {
				t.Fatalf("write payload: %v", err)
			}
			if !bytes.Equal(got, payload) {
				t.Fatalf("echo mismatch: got %d bytes, want %d", len(got), len(payload))
			}

			// Stop waits for the connection handler, so the final log record is
			// complete and the buffer is safe to read.
			if err := p.Stop(); err != nil {
				t.Fatalf("stop proxy: %v", err)
			}

			rec := lastLogRecord(t, logs)
			if got := rec["module"]; got != "proxy" {
				t.Fatalf("module = %v, want proxy", got)
			}
			if got := rec["success"]; got != true {
				t.Fatalf("success = %v, want true (record %v)", got, rec)
			}
			if got := rec["dst"]; got != mapped.String() {
				t.Fatalf("dst = %v, want %s", got, mapped)
			}
			if got := rec["real"]; got != "127.0.0.1" {
				t.Fatalf("real = %v, want 127.0.0.1", got)
			}
			if got := rec["port"]; got != float64(server.Addr().Port()) {
				t.Fatalf("port = %v, want %d", got, server.Addr().Port())
			}
			if _, ok := rec["latency_ms"]; !ok {
				t.Fatalf("missing latency_ms in %v", rec)
			}
			if got := rec["bytes_client_to_upstream"]; got != float64(len(payload)) {
				t.Fatalf("bytes_client_to_upstream = %v, want %d", got, len(payload))
			}
			if got := rec["bytes_upstream_to_client"]; got != float64(len(payload)) {
				t.Fatalf("bytes_upstream_to_client = %v, want %d", got, len(payload))
			}
		})
	}
}

func TestTCPProxyPropagatesHalfClose(t *testing.T) {
	const request = "request-before-half-close"
	const response = "response-after-upstream-eof:"

	requestCh := make(chan []byte, 1)
	server := startTCPServer(t, func(c *net.TCPConn) {
		req, err := io.ReadAll(c)
		if err != nil {
			requestCh <- nil
			return
		}
		requestCh <- req
		_, _ = c.Write(append([]byte(response), req...))
		_ = c.CloseWrite()
	})

	engine, mapped := newTestMapping(t)
	origDst := func(*net.TCPConn) (netip.AddrPort, error) {
		return netip.AddrPortFrom(mapped, server.Addr().Port()), nil
	}
	_, proxyAddr, _ := startTestProxy(t, engine, origDst, nil, 0)
	conn := dialTestProxy(t, proxyAddr)

	if _, err := conn.Write([]byte(request)); err != nil {
		t.Fatalf("write request: %v", err)
	}
	// Half-close the client -> upstream direction. The proxy must forward this
	// EOF so the server's io.ReadAll returns, while the reverse direction stays
	// open for the response.
	if err := conn.CloseWrite(); err != nil {
		t.Fatalf("close client write side: %v", err)
	}

	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if want := response + request; string(got) != want {
		t.Fatalf("response = %q, want %q", got, want)
	}

	select {
	case req := <-requestCh:
		if string(req) != request {
			t.Fatalf("server received %q, want %q", req, request)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server did not observe the half-close")
	}
}

func TestTCPProxyUnmappedDestinationIsRejected(t *testing.T) {
	engine, _ := newTestMapping(t)
	unmapped := netip.MustParseAddr("100.64.9.2")
	origDst := func(*net.TCPConn) (netip.AddrPort, error) {
		return netip.AddrPortFrom(unmapped, 443), nil
	}
	p, proxyAddr, logs := startTestProxy(t, engine, origDst, nil, 0)
	conn := dialTestProxy(t, proxyAddr)

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	if n, err := conn.Read(buf); err == nil || n != 0 {
		t.Fatalf("expected closed connection for unmapped destination, got n=%d err=%v", n, err)
	}

	if err := p.Stop(); err != nil {
		t.Fatalf("stop proxy: %v", err)
	}
	rec := lastLogRecord(t, logs)
	if got := rec["success"]; got != false {
		t.Fatalf("success = %v, want false", got)
	}
	if got := rec["dst"]; got != unmapped.String() {
		t.Fatalf("dst = %v, want %s", got, unmapped)
	}
}

func TestTCPProxyIdleTimeout(t *testing.T) {
	server := startTCPServer(t, echoHandler)
	engine, mapped := newTestMapping(t)
	origDst := func(*net.TCPConn) (netip.AddrPort, error) {
		return netip.AddrPortFrom(mapped, server.Addr().Port()), nil
	}
	p, proxyAddr, logs := startTestProxy(t, engine, origDst, nil, 200*time.Millisecond)
	conn := dialTestProxy(t, proxyAddr)

	start := time.Now()
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err == nil {
		t.Fatal("idle connection was not closed")
	}
	if elapsed := time.Since(start); elapsed < 150*time.Millisecond {
		t.Fatalf("idle connection closed too early: %v", elapsed)
	}

	if err := p.Stop(); err != nil {
		t.Fatalf("stop proxy: %v", err)
	}
	rec := lastLogRecord(t, logs)
	if got := rec["success"]; got != false {
		t.Fatalf("success = %v, want false", got)
	}
}

func TestTCPProxyStopClosesActiveConnections(t *testing.T) {
	server := startTCPServer(t, echoHandler)
	engine, mapped := newTestMapping(t)
	origDst := func(*net.TCPConn) (netip.AddrPort, error) {
		return netip.AddrPortFrom(mapped, server.Addr().Port()), nil
	}
	p, proxyAddr, _ := startTestProxy(t, engine, origDst, nil, 0)
	conn := dialTestProxy(t, proxyAddr)

	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	reply := make([]byte, 4)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("read echo: %v", err)
	}

	if err := p.Stop(); err != nil {
		t.Fatalf("stop proxy: %v", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err == nil {
		t.Fatal("active connection remained open after Stop")
	}
}

func TestUDPProxyStub(t *testing.T) {
	var p Proxy = NewUDPProxy("127.0.0.1:0")
	if p.Name() != "udp" {
		t.Fatalf("Name = %q, want udp", p.Name())
	}
	if err := p.Start(context.Background()); err == nil || !strings.Contains(err.Error(), "not implemented") {
		t.Fatalf("Start error = %v, want not-implemented error", err)
	}
	if err := p.Stop(); err != nil {
		t.Fatalf("Stop = %v", err)
	}
}

func TestNewTCPProxyValidation(t *testing.T) {
	engine, _ := newTestMapping(t)
	if _, err := NewTCPProxy(TCPConfig{}, engine, nil); err == nil {
		t.Fatal("expected an error for an empty listen address")
	}
	if _, err := NewTCPProxy(TCPConfig{Listen: "127.0.0.1:0"}, nil, nil); err == nil {
		t.Fatal("expected an error for a nil mapping engine")
	}
}
