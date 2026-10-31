package proxy

import (
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"tesla-gateway/internal/stats"
)

func waitForProxyStatsCondition(t *testing.T, timeout time.Duration, condition func() bool, description string) {
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

func TestTCPProxyStats(t *testing.T) {
	payload := []byte("tesla-gateway-proxy-stats-payload")

	server := startTCPServer(t, echoHandler)
	engine, mapped := newTestMapping(t)
	origDst := func(*net.TCPConn) (netip.AddrPort, error) {
		return netip.AddrPortFrom(mapped, server.Addr().Port()), nil
	}

	st := stats.New()
	p, proxyAddr, _ := startTestProxy(t, engine, origDst, nil, 0, st)
	conn := dialTestProxy(t, proxyAddr)

	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	reply := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("read echoed payload: %v", err)
	}

	waitForProxyStatsCondition(t, 2*time.Second, func() bool {
		return st.Snapshot().Proxy.ActiveConns == 1
	}, "one active proxy connection")

	if err := p.Stop(); err != nil {
		t.Fatalf("stop proxy: %v", err)
	}

	snapshot := st.Snapshot()
	if got := snapshot.Proxy.ActiveConns; got != 0 {
		t.Errorf("Proxy.ActiveConns = %d, want 0 after Stop", got)
	}
	if got := snapshot.Proxy.TotalConns; got != 1 {
		t.Errorf("Proxy.TotalConns = %d, want 1", got)
	}
	if got := snapshot.Proxy.BytesClientToUpstream; got != uint64(len(payload)) {
		t.Errorf("Proxy.BytesClientToUpstream = %d, want %d", got, len(payload))
	}
	if got := snapshot.Proxy.BytesUpstreamToClient; got != uint64(len(payload)) {
		t.Errorf("Proxy.BytesUpstreamToClient = %d, want %d", got, len(payload))
	}
	if got := snapshot.Proxy.RejectedNoMapping; got != 0 {
		t.Errorf("Proxy.RejectedNoMapping = %d, want 0", got)
	}
}

func TestTCPProxyStatsRejectedNoMapping(t *testing.T) {
	engine, _ := newTestMapping(t)
	unmapped := netip.MustParseAddr("100.64.9.2")
	origDst := func(*net.TCPConn) (netip.AddrPort, error) {
		return netip.AddrPortFrom(unmapped, 443), nil
	}

	st := stats.New()
	p, proxyAddr, _ := startTestProxy(t, engine, origDst, nil, 0, st)
	conn := dialTestProxy(t, proxyAddr)

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	if n, err := conn.Read(buf); err == nil || n != 0 {
		t.Fatalf("expected closed connection for unmapped destination, got n=%d err=%v", n, err)
	}

	if err := p.Stop(); err != nil {
		t.Fatalf("stop proxy: %v", err)
	}

	snapshot := st.Snapshot()
	if got := snapshot.Proxy.RejectedNoMapping; got != 1 {
		t.Errorf("Proxy.RejectedNoMapping = %d, want 1", got)
	}
	if got := snapshot.Proxy.TotalConns; got != 0 {
		t.Errorf("Proxy.TotalConns = %d, want 0", got)
	}
	if got := snapshot.Proxy.ActiveConns; got != 0 {
		t.Errorf("Proxy.ActiveConns = %d, want 0", got)
	}
	if got := snapshot.Proxy.BytesClientToUpstream; got != 0 {
		t.Errorf("Proxy.BytesClientToUpstream = %d, want 0", got)
	}
	if got := snapshot.Proxy.BytesUpstreamToClient; got != 0 {
		t.Errorf("Proxy.BytesUpstreamToClient = %d, want 0", got)
	}
}
