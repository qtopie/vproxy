//go:build linux
// +build linux

package tproxy

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/fdbased"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	soOriginalDst     = 80 // IP_ORIGINAL_DST (SOL_IP level)
	soOriginalDstIPv6 = 80 // IP6T_SO_ORIGINAL_DST (SOL_IPV6 level)
)

var (
	tunDevice tun.Device
	ipStack   *stack.Stack
	mu        sync.Mutex
)

// GetOriginalDst retrieves the original destination address of a TCP connection.
func GetOriginalDst(conn net.Conn) (string, error) {
	if tc, ok := conn.(*gonet.TCPConn); ok {
		return tc.LocalAddr().String(), nil
	}

	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return "", fmt.Errorf("not a tcp connection")
	}

	f, err := tcpConn.File()
	if err != nil {
		return "", err
	}
	defer f.Close()

	return GetOriginalDstFromFile(f)
}

// IsTUNConn checks if the connection originated from the TUN/GVisor stack.
func IsTUNConn(conn net.Conn) bool {
	_, ok := conn.(*gonet.TCPConn)
	return ok
}

func GetOriginalDstFromFile(f *os.File) (string, error) {
	fd := f.Fd()

	addr, err := unix.Getsockname(int(fd))
	if err != nil {
		return "", err
	}

	switch addr.(type) {
	case *unix.SockaddrInet4:
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

	case *unix.SockaddrInet6:
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

	return "", fmt.Errorf("unknown address type")
}

// GetOriginalDstEBPF retrieves the original TCP destination from the eBPF map.
func GetOriginalDstEBPF(conn net.Conn, m TCPOrigDstMap) (string, error) {
	if m != nil {
		if addr, err := lookupTCPFromMap(conn, m); err == nil {
			return addr, nil
		}
	}
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
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, dst.IP[0])
	return fmt.Sprintf("%s:%d", net.IP(b).String(), port), nil
}

// StartLinuxTransparent sets up a TUN interface on Linux and redirects all TCP/UDP traffic to a userspace GVisor stack.
func StartLinuxTransparent(ctx context.Context, tcpHandler func(net.Conn), udpHandler func(context.Context, net.Conn, string)) error {
	mu.Lock()
	defer mu.Unlock()

	if tunDevice != nil {
		return nil // already running
	}

	// 1. Create TUN device
	dev, err := tun.CreateTUN("vproxy-tun", 1500)
	if err != nil {
		return fmt.Errorf("failed to create TUN device: %w (are you root?)", err)
	}
	tunDevice = dev
	name, _ := dev.Name()
	log.Printf("[TUN/L] Created TUN device: %s", name)

	// 2. Initialize GVisor stack
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	ipStack = s

	// Use fdbased LinkEndpoint with the TUN file descriptor for proper Layer 3 support
	linkEP, err := fdbased.New(&fdbased.Options{
		FDs:            []int{int(dev.File().Fd())},
		MTU:            1500,
		EthernetHeader: false, // This is a TUN device (Layer 3)
	})
	if err != nil {
		dev.Close()
		return fmt.Errorf("failed to create fdbased link endpoint: %v", err)
	}

	if tcpipErr := s.CreateNIC(1, &icmpInterceptor{LinkEndpoint: linkEP, dev: dev}); tcpipErr != nil {
		dev.Close()
		return fmt.Errorf("failed to create NIC: %v", tcpipErr)
	}

	// Enable promiscuous mode and forwarding to intercept all packets
	s.SetPromiscuousMode(1, true)
	s.SetSpoofing(1, true)
	s.SetForwardingDefaultAndAllNICs(ipv4.ProtocolNumber, true)
	s.SetForwardingDefaultAndAllNICs(ipv6.ProtocolNumber, true)

	// Assign standard non-routable IPs to GVisor stack to ensure NIC is enabled
	tunIP := [4]byte{198, 18, 0, 2}
	if tcpipErr := s.AddProtocolAddress(1, tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFrom4(tunIP),
			PrefixLen: 15,
		},
	}, stack.AddressProperties{}); tcpipErr != nil {
		log.Printf("[TUN/L] Warning: AddProtocolAddress IPv4: %v", tcpipErr)
	}

	// Add default routes to point everything to the NIC
	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: 1},
		{Destination: header.IPv6EmptySubnet, NIC: 1},
	})

	// 3. TCP forwarder
	tcpForwarder := tcp.NewForwarder(s, 0, 10000, func(r *tcp.ForwarderRequest) {
		var wq waiter.Queue
		ep, err := r.CreateEndpoint(&wq)
		if err != nil {
			r.Complete(true)
			return
		}
		r.Complete(false)
		go tcpHandler(gonet.NewTCPConn(&wq, ep))
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpForwarder.HandlePacket)

	// 4. UDP forwarder
	udpHandlerFunc := func(r *udp.ForwarderRequest) bool {
		var wq waiter.Queue
		ep, err := r.CreateEndpoint(&wq)
		if err != nil {
			return false
		}
		endpoint := r.ID()
		target := fmt.Sprintf("%s:%d", endpoint.LocalAddress, endpoint.LocalPort)
		go udpHandler(context.Background(), gonet.NewUDPConn(&wq, ep), target)
		return true
	}
	udpForwarder := udp.NewForwarder(s, udpHandlerFunc)
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpForwarder.HandlePacket)

	// 5. Configure Linux routing and routes
	if err := setupRoutingLinux(name); err != nil {
		Cleanup()
		return fmt.Errorf("failed to setup routing: %w", err)
	}

	return nil
}

func setupRoutingLinux(tunName string) error {
	// 1. Configure point-to-point IP address to the TUN interface (Host side)
	if err := exec.Command("ip", "addr", "add", "198.18.0.1/15", "dev", tunName).Run(); err != nil {
		return fmt.Errorf("failed to assign IPv4 to %s: %w", tunName, err)
	}
	exec.Command("ip", "-6", "addr", "add", "fc00:198:18::1/64", "dev", tunName).Run()

	if err := exec.Command("ip", "link", "set", "dev", tunName, "up").Run(); err != nil {
		return fmt.Errorf("failed to set %s link up: %w", tunName, err)
	}

	// 2. Set up split routes (/1 routing trick) to avoid default route collision
	cmds := [][]string{
		{"ip", "route", "add", "0.0.0.0/1", "dev", tunName},
		{"ip", "route", "add", "128.0.0.0/1", "dev", tunName},
		{"ip", "-6", "route", "add", "::/1", "dev", tunName},
		{"ip", "-6", "route", "add", "8000::/1", "dev", tunName},
	}
	for _, args := range cmds {
		exec.Command(args[0], args[1:]...).Run()
	}
	return nil
}

func Cleanup() {
	mu.Lock()
	defer mu.Unlock()

	if tunDevice != nil {
		name, _ := tunDevice.Name()
		cmds := [][]string{
			{"ip", "route", "del", "0.0.0.0/1", "dev", name},
			{"ip", "route", "del", "128.0.0.0/1", "dev", name},
			{"ip", "-6", "route", "del", "::/1", "dev", name},
			{"ip", "-6", "route", "del", "8000::/1", "dev", name},
		}
		for _, args := range cmds {
			exec.Command(args[0], args[1:]...).Run()
		}
		tunDevice.Close()
		tunDevice = nil
	}
}

func getDefaultInterface() (string, error) {
	data, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return "", err
	}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		if fields[1] == "00000000" {
			return fields[0], nil
		}
	}
	return "", fmt.Errorf("default route not found")
}

// GetDialerControl returns a dialer control function that binds upstream sockets to the physical default interface.
func GetDialerControl() func(network, address string, c syscall.RawConn) error {
	ifaceName, err := getDefaultInterface()
	if err != nil {
		return nil
	}
	return func(network, address string, c syscall.RawConn) error {
		var opErr error
		err := c.Control(func(fd uintptr) {
			opErr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, ifaceName)
		})
		if err != nil {
			return err
		}
		return opErr
	}
}

// StartDarwinTransparent is not supported on Linux.
func StartDarwinTransparent(_ context.Context, _, _, _ int, _ func(net.Conn), _ func(context.Context, net.Conn, string)) error {
	return fmt.Errorf("StartDarwinTransparent not supported on Linux")
}

// GetProcessNameByPort is not implemented on Linux.
func GetProcessNameByPort(_ int) (string, int, error) {
	return "", 0, fmt.Errorf("GetProcessNameByPort not implemented on Linux")
}

// GetProcessNameByConn is not implemented on Linux.
func GetProcessNameByConn(_ interface{}) (string, int, error) {
	return "", 0, fmt.Errorf("GetProcessNameByConn not implemented on Linux")
}

type icmpInterceptor struct {
	stack.LinkEndpoint
	dev tun.Device
}

func (i *icmpInterceptor) Attach(d stack.NetworkDispatcher) {
	i.LinkEndpoint.Attach(&icmpDispatcher{NetworkDispatcher: d, dev: i.dev})
}

type icmpDispatcher struct {
	stack.NetworkDispatcher
	dev tun.Device
}

func (d *icmpDispatcher) DeliverNetworkPacket(protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	// Gvisor calls this to deliver a packet from the link (TUN) to the stack.
	// We can intercept here to handle ICMP echo requests locally.
	view := pkt.ToView()
	pktBuf := view.AsSlice()
	if CheckAndWriteICMP(d.dev, pktBuf, 0) {
		view.Release()
		return
	}
	view.Release()
	d.NetworkDispatcher.DeliverNetworkPacket(protocol, pkt)
}
