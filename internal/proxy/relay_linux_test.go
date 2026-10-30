//go:build linux

package proxy

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// tcpPair returns the two ends of one loopback TCP connection.
func tcpPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	accepted := make(chan *net.TCPConn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- conn.(*net.TCPConn)
	}()

	dialer := net.Dialer{Timeout: 2 * time.Second}
	clientConn, err := dialer.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	var serverConn *net.TCPConn
	select {
	case serverConn = <-accepted:
	case err := <-acceptErr:
		_ = clientConn.Close()
		t.Fatalf("accept: %v", err)
	case <-time.After(2 * time.Second):
		_ = clientConn.Close()
		t.Fatal("accept timed out")
	}

	client := clientConn.(*net.TCPConn)
	deadline := time.Now().Add(10 * time.Second)
	_ = client.SetDeadline(deadline)
	_ = serverConn.SetDeadline(deadline)
	t.Cleanup(func() {
		_ = client.Close()
		_ = serverConn.Close()
	})
	return client, serverConn
}

// TestSpliceCopyTransfersAllBytes exercises the real splice(2) path (socket ->
// pipe -> socket) with a payload large enough to require many chunks. The relay
// joins one end of each of two independent TCP connections; the writer and
// reader use the opposite ends.
func TestSpliceCopyTransfersAllBytes(t *testing.T) {
	srcRelay, srcWriter := tcpPair(t)
	dstRelay, dstReader := tcpPair(t)
	payload := bytes.Repeat([]byte("0123456789abcdef-splice-"), 64*1024)

	gotCh := make(chan []byte, 1)
	readDone := make(chan error, 1)
	go func() {
		got, err := io.ReadAll(dstReader)
		gotCh <- got
		readDone <- err
	}()

	writeDone := make(chan error, 1)
	go func() {
		_, err := srcWriter.Write(payload)
		if err == nil {
			err = srcWriter.CloseWrite()
		}
		writeDone <- err
	}()

	n, err := spliceCopy(dstRelay, srcRelay, nil)
	if err != nil {
		t.Fatalf("spliceCopy: %v", err)
	}
	if n != int64(len(payload)) {
		t.Fatalf("spliced %d bytes, want %d", n, len(payload))
	}
	_ = dstRelay.CloseWrite()

	if err := <-writeDone; err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := <-readDone; err != nil {
		t.Fatalf("read: %v", err)
	}
	if got := <-gotCh; !bytes.Equal(got, payload) {
		t.Fatalf("spliced payload mismatch: got %d bytes, want %d", len(got), len(payload))
	}
}

func TestRelayFallsBackToIOCopyWhenSpliceUnsupported(t *testing.T) {
	srcRelay, srcWriter := tcpPair(t)
	dstRelay, dstReader := tcpPair(t)
	payload := bytes.Repeat([]byte("fallback-io-copy-"), 8192)

	gotCh := make(chan []byte, 1)
	readDone := make(chan error, 1)
	go func() {
		got, err := io.ReadAll(dstReader)
		gotCh <- got
		readDone <- err
	}()

	writeDone := make(chan error, 1)
	go func() {
		_, err := srcWriter.Write(payload)
		if err == nil {
			err = srcWriter.CloseWrite()
		}
		writeDone <- err
	}()

	unsupportedSplice := func(*net.TCPConn, *net.TCPConn, func()) (int64, error) {
		return 0, unix.EINVAL
	}
	// A non-nil activity callback also forces the user-space io.Copy path
	// instead of letting net.TCPConn use its internal splice optimisation.
	n, err := relayUsing(dstRelay, srcRelay, func() {}, unsupportedSplice)
	if err != nil {
		t.Fatalf("relayUsing fallback: %v", err)
	}
	if n != int64(len(payload)) {
		t.Fatalf("copied %d bytes, want %d", n, len(payload))
	}
	_ = dstRelay.CloseWrite()

	if err := <-writeDone; err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := <-readDone; err != nil {
		t.Fatalf("read: %v", err)
	}
	if got := <-gotCh; !bytes.Equal(got, payload) {
		t.Fatalf("fallback payload mismatch: got %d bytes, want %d", len(got), len(payload))
	}
}

func TestRelayDoesNotFallbackAfterPartialCopy(t *testing.T) {
	// A partial copy must not be followed by an io.Copy restart: that would
	// duplicate bytes. relayUsing should surface the splice error instead.
	n, err := relayUsing(nil, nil, nil, func(*net.TCPConn, *net.TCPConn, func()) (int64, error) {
		return 5, unix.EINVAL
	})
	if n != 5 {
		t.Fatalf("n = %d, want 5", n)
	}
	if !errors.Is(err, unix.EINVAL) {
		t.Fatalf("err = %v, want EINVAL", err)
	}
}

func TestIsSpliceUnsupported(t *testing.T) {
	for _, err := range []error{
		unix.EINVAL,
		unix.ENOSYS,
		unix.EOPNOTSUPP,
		unix.EPERM,
		errSpliceUnsupported,
	} {
		if !isSpliceUnsupported(err) {
			t.Fatalf("isSpliceUnsupported(%v) = false", err)
		}
	}
	if isSpliceUnsupported(unix.ECONNRESET) {
		t.Fatal("isSpliceUnsupported(ECONNRESET) = true")
	}
}
