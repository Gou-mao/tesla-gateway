//go:build linux

package proxy

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"unsafe"

	"golang.org/x/sys/unix"
)

// sockaddrInet is the Linux struct sockaddr_in layout. Port is kept as raw
// network-order bytes so the result does not depend on host endianness.
type sockaddrInet struct {
	Family uint16
	Port   [2]byte
	Addr   [4]byte
	Zero   [8]byte
}

// OriginalDst asks the kernel for the pre-redirect IPv4 destination of c via
// getsockopt(SOL_IP, SO_ORIGINAL_DST). It is intended for connections accepted
// by a NAT redirect rule.
func OriginalDst(c *net.TCPConn) (netip.AddrPort, error) {
	if c == nil {
		return netip.AddrPort{}, errors.New("proxy: original destination: nil connection")
	}

	raw, err := c.SyscallConn()
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("proxy: original destination: get syscall conn: %w", err)
	}

	var sa sockaddrInet
	size := uint32(unsafe.Sizeof(sa))
	var sockErr error

	if err := raw.Control(func(fd uintptr) {
		_, _, errno := unix.Syscall6(
			unix.SYS_GETSOCKOPT,
			fd,
			uintptr(unix.SOL_IP),
			uintptr(unix.SO_ORIGINAL_DST),
			uintptr(unsafe.Pointer(&sa)),
			uintptr(unsafe.Pointer(&size)),
			0,
		)
		if errno != 0 {
			sockErr = errno
		}
	}); err != nil {
		return netip.AddrPort{}, fmt.Errorf("proxy: original destination: control: %w", err)
	}
	if sockErr != nil {
		return netip.AddrPort{}, fmt.Errorf("proxy: getsockopt(SO_ORIGINAL_DST): %w", sockErr)
	}

	// sockaddr_in is 16 bytes, but some kernels only report the meaningful
	// family/port/address prefix. Anything shorter than 8 bytes is unusable.
	if size < 8 {
		return netip.AddrPort{}, fmt.Errorf("proxy: getsockopt(SO_ORIGINAL_DST): short address (%d bytes)", size)
	}
	if sa.Family != unix.AF_INET {
		return netip.AddrPort{}, fmt.Errorf("proxy: getsockopt(SO_ORIGINAL_DST): unsupported address family %d", sa.Family)
	}

	port := binary.BigEndian.Uint16(sa.Port[:])
	return netip.AddrPortFrom(netip.AddrFrom4(sa.Addr), port), nil
}
