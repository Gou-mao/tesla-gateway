//go:build !linux

package proxy

import "net"

// relay copies one direction of a TCP connection using io.Copy. The Linux
// build uses a splice(2) fast path instead.
func relay(dst, src *net.TCPConn) (int64, error) {
	return relayWith(dst, src, nil)
}

func relayWith(dst, src *net.TCPConn, onActivity func()) (int64, error) {
	return copyFallback(dst, src, onActivity)
}
