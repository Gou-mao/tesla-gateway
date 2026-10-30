//go:build linux

package proxy

import (
	"errors"
	"fmt"
	"io"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

const (
	// A splice chunk must fit comfortably in a pipe buffer. 32 KiB is below
	// the usual 64 KiB pipe capacity while still amortising syscall overhead.
	spliceChunkSize = 32 * 1024
	spliceFlags     = unix.SPLICE_F_MOVE | unix.SPLICE_F_NONBLOCK
)

// errSpliceUnsupported marks failures for which falling back to io.Copy is
// safe (and only safe when no bytes have been delivered yet).
var errSpliceUnsupported = errors.New("proxy: splice unsupported")

// relay copies one direction of a TCP connection, preferring splice(2) and
// falling back to io.Copy when the kernel or socket type does not support it.
func relay(dst, src *net.TCPConn) (int64, error) {
	return relayWith(dst, src, nil)
}

func relayWith(dst, src *net.TCPConn, onActivity func()) (int64, error) {
	return relayUsing(dst, src, onActivity, spliceCopy)
}

type spliceFunc func(dst, src *net.TCPConn, onActivity func()) (int64, error)

// relayUsing exists so tests can force the unsupported-splice fallback without
// relying on a particular kernel configuration.
func relayUsing(dst, src *net.TCPConn, onActivity func(), splice spliceFunc) (int64, error) {
	if splice == nil {
		return copyFallback(dst, src, onActivity)
	}
	n, err := splice(dst, src, onActivity)
	if err == nil {
		return n, nil
	}
	// Falling back after a partial copy would duplicate bytes, so only do it
	// when nothing has reached dst yet.
	if n == 0 && isSpliceUnsupported(err) {
		return copyFallback(dst, src, onActivity)
	}
	return n, err
}

// spliceCopy moves bytes with a kernel pipe: socket -> pipe -> socket. The TCP
// descriptors are driven through syscall.RawConn so Go's network poller, rather
// than a busy loop, waits for readiness.
func spliceCopy(dst, src *net.TCPConn, onActivity func()) (int64, error) {
	if dst == nil || src == nil {
		return 0, errors.New("proxy: splice: nil connection")
	}

	pipe, err := newSplicePipe()
	if err != nil {
		return 0, fmt.Errorf("%w: create pipe: %v", errSpliceUnsupported, err)
	}
	defer unix.Close(pipe[0])
	defer unix.Close(pipe[1])

	srcRaw, err := src.SyscallConn()
	if err != nil {
		return 0, fmt.Errorf("%w: source syscall conn: %v", errSpliceUnsupported, err)
	}
	dstRaw, err := dst.SyscallConn()
	if err != nil {
		return 0, fmt.Errorf("%w: destination syscall conn: %v", errSpliceUnsupported, err)
	}

	var total int64
	for {
		var n int64
		var opErr error

		if err := srcRaw.Read(func(fd uintptr) bool {
			got, err := unix.Splice(int(fd), nil, pipe[1], nil, spliceChunkSize, spliceFlags)
			n, opErr = int64(got), err
			// The socket is non-blocking; the poller calls us again when data
			// is available.
			return !errors.Is(opErr, unix.EAGAIN)
		}); err != nil {
			return total, fmt.Errorf("proxy: splice wait for source: %w", err)
		}
		if opErr != nil {
			if errors.Is(opErr, unix.EINTR) {
				continue
			}
			if isSpliceUnsupported(opErr) {
				return total, fmt.Errorf("%w: socket to pipe: %v", errSpliceUnsupported, opErr)
			}
			return total, fmt.Errorf("proxy: splice socket to pipe: %w", opErr)
		}
		if n == 0 {
			// Source reached EOF. The caller propagates the half-close with
			// CloseWrite on dst.
			return total, nil
		}

		drained, err := spliceDrain(dstRaw, pipe[0], n, onActivity)
		// Count partial progress before an error so relayUsing never falls
		// back after bytes have already reached dst (that would duplicate
		// them).
		total += drained
		if err != nil {
			// The remaining n-drained bytes are already in the pipe and have
			// been consumed from src. Report them as progress so relayUsing
			// does not fall back to io.Copy and read them a second time from a
			// source that no longer has them.
			return total + (n - drained), err
		}
	}
}

// spliceDrain writes exactly n bytes from pipeRead to dst.
func spliceDrain(dst syscall.RawConn, pipeRead int, n int64, onActivity func()) (int64, error) {
	remaining := n
	var drained int64
	for remaining > 0 {
		var written int64
		var opErr error

		if err := dst.Write(func(fd uintptr) bool {
			got, err := unix.Splice(pipeRead, nil, int(fd), nil, int(remaining), spliceFlags)
			written, opErr = int64(got), err
			// EAGAIN from the socket side means the poller should wait for
			// writability; EAGAIN from an empty pipe must not happen because
			// remaining is bounded by the bytes we just spliced in.
			return !errors.Is(opErr, unix.EAGAIN)
		}); err != nil {
			return drained, fmt.Errorf("proxy: splice wait for destination: %w", err)
		}
		if opErr != nil {
			if errors.Is(opErr, unix.EINTR) {
				continue
			}
			if isSpliceUnsupported(opErr) {
				return drained, fmt.Errorf("%w: pipe to socket: %v", errSpliceUnsupported, opErr)
			}
			return drained, fmt.Errorf("proxy: splice pipe to socket: %w", opErr)
		}
		if written == 0 {
			return drained, fmt.Errorf("proxy: splice pipe to socket: %w", io.ErrShortWrite)
		}
		remaining -= written
		drained += written
		if onActivity != nil {
			onActivity()
		}
	}
	return drained, nil
}

// newSplicePipe creates a close-on-exec, non-blocking pipe. Non-blocking ends
// are required because splice(2) runs on sockets owned by Go's poller: a
// blocking pipe fill could deadlock the goroutine before it gets a chance to
// drain the pipe.
func newSplicePipe() ([2]int, error) {
	var pipe [2]int
	if err := unix.Pipe2(pipe[:], unix.O_CLOEXEC|unix.O_NONBLOCK); err == nil {
		return pipe, nil
	} else if !errors.Is(err, unix.ENOSYS) {
		return pipe, err
	}

	// Very old kernels lack pipe2(2).
	if err := unix.Pipe(pipe[:]); err != nil {
		return pipe, err
	}
	for _, fd := range pipe {
		unix.CloseOnExec(fd)
		if err := unix.SetNonblock(fd, true); err != nil {
			unix.Close(pipe[0])
			unix.Close(pipe[1])
			return [2]int{}, err
		}
	}
	return pipe, nil
}

func isSpliceUnsupported(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, errSpliceUnsupported) {
		return true
	}
	for _, target := range []error{
		unix.EINVAL,
		unix.ENOSYS,
		unix.EOPNOTSUPP,
		unix.EPERM,
	} {
		if errors.Is(err, target) {
			return true
		}
	}
	return false
}
