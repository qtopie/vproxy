//go:build linux
// +build linux

package tproxy

import (
	"encoding/binary"
	"fmt"
	"net"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	soOriginalDst     = 80 // IPPROTO_IP level
	soOriginalDstIPv6 = 80 // IPPROTO_IPV6 level (IP6T_SO_ORIGINAL_DST)
)

// GetOriginalDst retrieves the original destination address of a connection
// that has been redirected via iptables REDIRECT or TPROXY.
func GetOriginalDst(conn net.Conn) (string, error) {
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return "", fmt.Errorf("not a tcp connection")
	}

	f, err := tcpConn.File()
	if err != nil {
		return "", err
	}
	defer f.Close()

	fd := int(f.Fd())

	// Determine if it's IPv4 or IPv6
	addr := conn.LocalAddr()
	tcpAddr, ok := addr.(*net.TCPAddr)
	if !ok {
		return "", fmt.Errorf("unknown address type")
	}

	if tcpAddr.IP.To4() != nil {
		// IPv4
		var raw unix.RawSockaddrInet4
		var addrlen uint32 = uint32(unsafe.Sizeof(raw))

		_, _, sysErr := unix.Syscall6(unix.SYS_GETSOCKOPT, uintptr(fd), unix.SOL_IP, soOriginalDst, uintptr(unsafe.Pointer(&raw)), uintptr(unsafe.Pointer(&addrlen)), 0)
		if sysErr != 0 {
			return "", fmt.Errorf("failed to get SO_ORIGINAL_DST (IPv4): %v", sysErr)
		}

		ip := net.IPv4(raw.Addr[0], raw.Addr[1], raw.Addr[2], raw.Addr[3])
		port := binary.BigEndian.Uint16((*[2]byte)(unsafe.Pointer(&raw.Port))[:])

		return fmt.Sprintf("%s:%d", ip.String(), port), nil
	} else {
		// IPv6
		var raw unix.RawSockaddrInet6
		var addrlen uint32 = uint32(unsafe.Sizeof(raw))

		_, _, sysErr := unix.Syscall6(unix.SYS_GETSOCKOPT, uintptr(fd), unix.SOL_IPV6, soOriginalDstIPv6, uintptr(unsafe.Pointer(&raw)), uintptr(unsafe.Pointer(&addrlen)), 0)
		if sysErr != 0 {
			return "", fmt.Errorf("failed to get IP6T_SO_ORIGINAL_DST (IPv6): %v", sysErr)
		}

		ip := make(net.IP, 16)
		copy(ip, raw.Addr[:])
		port := binary.BigEndian.Uint16((*[2]byte)(unsafe.Pointer(&raw.Port))[:])

		return fmt.Sprintf("[%s]:%d", ip.String(), port), nil
	}
}
