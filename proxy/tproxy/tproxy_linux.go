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
	soOriginalDst     = 80 // IP_ORIGINAL_DST (SOL_IP level)
	soOriginalDstIPv6 = 80 // IP6T_SO_ORIGINAL_DST (SOL_IPV6 level)
)

// GetOriginalDst retrieves the original destination address of a TCP connection
// that has been redirected via iptables REDIRECT or TPROXY.
// This is the iptables-mode path; use GetOriginalDstEBPF for eBPF mode.
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

	addr := conn.LocalAddr()
	tcpAddr, ok := addr.(*net.TCPAddr)
	if !ok {
		return "", fmt.Errorf("unknown address type")
	}

	if tcpAddr.IP.To4() != nil {
		// IPv4
		var raw unix.RawSockaddrInet4
		var addrlen uint32 = uint32(unsafe.Sizeof(raw))

		_, _, sysErr := unix.Syscall6(unix.SYS_GETSOCKOPT, uintptr(fd), unix.SOL_IP, soOriginalDst,
			uintptr(unsafe.Pointer(&raw)), uintptr(unsafe.Pointer(&addrlen)), 0)
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

		_, _, sysErr := unix.Syscall6(unix.SYS_GETSOCKOPT, uintptr(fd), unix.SOL_IPV6, soOriginalDstIPv6,
			uintptr(unsafe.Pointer(&raw)), uintptr(unsafe.Pointer(&addrlen)), 0)
		if sysErr != 0 {
			return "", fmt.Errorf("failed to get IP6T_SO_ORIGINAL_DST (IPv6): %v", sysErr)
		}

		ip := make(net.IP, 16)
		copy(ip, raw.Addr[:])
		port := binary.BigEndian.Uint16((*[2]byte)(unsafe.Pointer(&raw.Port))[:])
		return fmt.Sprintf("[%s]:%d", ip.String(), port), nil
	}
}

// GetOriginalDstEBPF retrieves the original TCP destination from the eBPF
// tcp_orig_dst map using the socket cookie of conn.
// Falls back to GetOriginalDst (SO_ORIGINAL_DST getsockopt) if the map lookup
// fails (e.g. during a short race between BPF hook and accept).
//

func GetOriginalDstEBPF(conn net.Conn, m TCPOrigDstMap) (string, error) {
	if m != nil {
		if addr, err := lookupTCPFromMap(conn, m); err == nil {
			return addr, nil
		}
	}
	// Fallback: works in iptables mode or when map lookup misses.
	return GetOriginalDst(conn)
}

func lookupTCPFromMap(conn net.Conn, m TCPOrigDstMap) (string, error) {
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return "", fmt.Errorf("not a TCPConn")
	}
	raw, err := tcpConn.SyscallConn()
	if err != nil {
		return "", err
	}

	var cookie uint64
	var sockErr error
	_ = raw.Control(func(fd uintptr) {
		v, e := unix.GetsockoptUint64(int(fd), unix.SOL_SOCKET, unix.SO_COOKIE)
		if e != nil {
			sockErr = e
			return
		}
		cookie = v
	})
	if sockErr != nil {
		return "", sockErr
	}

	// The value struct must match bpfOriginalDst from bpf_bpfel.go.
	type origDst struct {
		IP     [4]uint32
		Port   uint32
		Family uint32
	}
	var dst origDst
	if err := m.LookupAndDelete(cookie, &dst); err != nil {
		return "", err
	}

	port := binary.BigEndian.Uint16((*[2]byte)(unsafe.Pointer(&dst.Port))[:])
	if dst.Family == unix.AF_INET6 {
		b := make([]byte, 16)
		binary.BigEndian.PutUint32(b[0:4], dst.IP[0])
		binary.BigEndian.PutUint32(b[4:8], dst.IP[1])
		binary.BigEndian.PutUint32(b[8:12], dst.IP[2])
		binary.BigEndian.PutUint32(b[12:16], dst.IP[3])
		return fmt.Sprintf("[%s]:%d", net.IP(b).String(), port), nil
	}
	// AF_INET
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, dst.IP[0])
	return fmt.Sprintf("%s:%d", net.IP(b).String(), port), nil
}

func Cleanup() {}
