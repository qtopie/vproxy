//go:build linux
// +build linux

package tproxy

import (
	"context"
	"fmt"
	"net"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// ListenUDPTransparent opens an IPv4 UDP socket with IP_TRANSPARENT and
// IP_RECVORIGDSTADDR for capturing iptables TPROXY-redirected traffic.
// Used in iptables fallback mode.
func ListenUDPTransparent(port int) (*net.UDPConn, error) {
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var opErr error
			err := c.Control(func(fd uintptr) {
				if err := unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_TRANSPARENT, 1); err != nil {
					opErr = fmt.Errorf("failed to set IP_TRANSPARENT: %w", err)
					return
				}
				unix.SetsockoptInt(int(fd), unix.SOL_IPV6, unix.IPV6_TRANSPARENT, 1)

				if err := unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_RECVORIGDSTADDR, 1); err != nil {
					opErr = fmt.Errorf("failed to set IP_RECVORIGDSTADDR: %w", err)
					return
				}
				unix.SetsockoptInt(int(fd), unix.SOL_IPV6, unix.IPV6_RECVORIGDSTADDR, 1)
			})
			if err != nil {
				return err
			}
			return opErr
		},
	}
	conn, err := lc.ListenPacket(context.Background(), "udp", fmt.Sprintf("[::]:%d", port))
	if err != nil {
		// Fallback to 0.0.0.0 if IPv6 is disabled in the environment
		conn, err = lc.ListenPacket(context.Background(), "udp", fmt.Sprintf("0.0.0.0:%d", port))
		if err != nil {
			return nil, err
		}
	}
	return conn.(*net.UDPConn), nil
}

// ListenUDP4Direct opens a plain IPv4 UDP socket bound to 127.0.0.1:port.
// Used in eBPF mode where the BPF hook already rewrites the destination to
// 127.0.0.1:proxy_port; no IP_TRANSPARENT needed.
func ListenUDP4Direct(port int) (*net.UDPConn, error) {
	conn, err := net.ListenPacket("udp4", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return nil, err
	}
	return conn.(*net.UDPConn), nil
}

// ListenUDP6Direct opens a plain IPv6 UDP socket bound to [::1]:port.
// Used in eBPF mode for IPv6 UDP traffic redirected to ::1:proxy_port.
func ListenUDP6Direct(port int) (*net.UDPConn, error) {
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				// Ensure this socket is IPv6-only so it doesn't conflict
				// with the IPv4 listener on the same port.
				unix.SetsockoptInt(int(fd), unix.SOL_IPV6, unix.IPV6_V6ONLY, 1)
			})
		},
	}
	conn, err := lc.ListenPacket(context.Background(), "udp6", fmt.Sprintf("[::1]:%d", port))
	if err != nil {
		return nil, err
	}
	return conn.(*net.UDPConn), nil
}

// DialUDPTransparent creates a UDP socket bound to the specific IP:PORT
// (which can be a non-local address, i.e., the original destination of a packet).
// This allows sending replies to the client that appear to come from the
// destination it originally targeted.
// Used only in iptables TPROXY mode.
func DialUDPTransparent(origDst *net.UDPAddr) (*net.UDPConn, error) {
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var opErr error
			err := c.Control(func(fd uintptr) {
				if err := unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_TRANSPARENT, 1); err != nil {
					opErr = fmt.Errorf("failed to set IP_TRANSPARENT: %w", err)
					return
				}
				unix.SetsockoptInt(int(fd), unix.SOL_IPV6, unix.IPV6_TRANSPARENT, 1)
				unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
			})
			if err != nil {
				return err
			}
			return opErr
		},
	}
	network := "udp"
	if origDst.IP.To4() == nil {
		network = "udp6"
	} else {
		network = "udp4"
	}
	conn, err := lc.ListenPacket(context.Background(), network, origDst.String())
	if err != nil {
		return nil, err
	}
	return conn.(*net.UDPConn), nil
}

// ReadFromUDPWithOrigDst reads a UDP packet and extracts its original destination
// address from the OOB cmsg data (IP_RECVORIGDSTADDR / IPV6_RECVORIGDSTADDR).
// Used in iptables TPROXY mode.
func ReadFromUDPWithOrigDst(conn *net.UDPConn, b []byte, oob []byte) (n int, src *net.UDPAddr, dst *net.UDPAddr, err error) {
	n, oobn, _, srcAddr, err := conn.ReadMsgUDP(b, oob)
	if err != nil {
		return n, nil, nil, err
	}

	msgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return n, srcAddr, nil, nil
	}

	for _, msg := range msgs {
		if msg.Header.Level == unix.SOL_IP && msg.Header.Type == unix.IP_RECVORIGDSTADDR {
			orig := (*unix.RawSockaddrInet4)(unsafe.Pointer(&msg.Data[0]))
			ip := net.IPv4(orig.Addr[0], orig.Addr[1], orig.Addr[2], orig.Addr[3])
			port := int((orig.Port >> 8) | (orig.Port << 8))
			dst = &net.UDPAddr{IP: ip, Port: port}
			return n, srcAddr, dst, nil
		}
		if msg.Header.Level == unix.SOL_IPV6 && msg.Header.Type == unix.IPV6_RECVORIGDSTADDR {
			orig := (*unix.RawSockaddrInet6)(unsafe.Pointer(&msg.Data[0]))
			ip := make(net.IP, 16)
			copy(ip, orig.Addr[:])
			port := int((orig.Port >> 8) | (orig.Port << 8))
			dst = &net.UDPAddr{IP: ip, Port: port}
			return n, srcAddr, dst, nil
		}
	}

	return n, srcAddr, nil, nil
}
