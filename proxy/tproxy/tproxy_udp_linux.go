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

// ListenUDPTransparent opens a UDP socket with IP_TRANSPARENT and IP_RECVORIGDSTADDR
// bound to the given port for capturing TPROXY traffic.
func ListenUDPTransparent(port int) (*net.UDPConn, error) {
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var opErr error
			err := c.Control(func(fd uintptr) {
				// Set IP_TRANSPARENT to allow receiving intercepted traffic
				if err := unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_TRANSPARENT, 1); err != nil {
					opErr = fmt.Errorf("failed to set IP_TRANSPARENT: %w", err)
					return
				}
				unix.SetsockoptInt(int(fd), unix.SOL_IPV6, unix.IPV6_TRANSPARENT, 1)

				// Set IP_RECVORIGDSTADDR to get original destination address
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
	// Bind to 0.0.0.0 so we can receive packets redirected to local delivery by TPROXY
	conn, err := lc.ListenPacket(context.Background(), "udp", fmt.Sprintf("0.0.0.0:%d", port))
	if err != nil {
		return nil, err
	}
	return conn.(*net.UDPConn), nil
}

// DialUDPTransparent creates a UDP socket bound to the specific IP:PORT 
// (which can be a non-local address, i.e., the original destination of a packet).
// This allows us to send replies to the client that appear to come from the destination it originally targeted.
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
	conn, err := lc.ListenPacket(context.Background(), "udp", origDst.String())
	if err != nil {
		return nil, err
	}
	return conn.(*net.UDPConn), nil
}

// ReadFromUDPWithOrigDst reads a UDP packet and extracts its original destination address from the OOB data.
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
