//go:build windows
// +build windows

package tproxy

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"os/exec"
	"sync"
	"syscall"
	"unsafe"

	"github.com/qtopie/vproxy/internal/dns"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

var (
	winTunDevice tun.Device
	winIPStack   *stack.Stack
	winMu        sync.Mutex

	// iphlpapi.dll — routing and TCP table queries
	modIphlpapi             = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetBestInterface    = modIphlpapi.NewProc("GetBestInterface")
	procGetExtendedTcpTable = modIphlpapi.NewProc("GetExtendedTcpTable")

	// ws2_32.dll — raw setsockopt (Go's syscall doesn't expose SetsockoptInt on Windows)
	modWs2_32      = windows.NewLazySystemDLL("ws2_32.dll")
	procSetsockopt = modWs2_32.NewProc("setsockopt")
)

const (
	// IP_UNICAST_IF / IPV6_UNICAST_IF — bind a socket to a specific outgoing interface.
	ipUnicastIF   = 31
	ipv6UnicastIF = 31
)

// GetOriginalDst retrieves the original destination of a gvisor gonet TCP connection.
// On Windows with TUN, the destination is available from the gvisor endpoint's local address.
func GetOriginalDst(conn net.Conn) (string, error) {
	if tc, ok := conn.(*gonet.TCPConn); ok {
		return tc.LocalAddr().String(), nil
	}
	return "", fmt.Errorf("not a gvisor connection")
}

// IsTUNConn checks if the connection originated from the TUN/GVisor stack.
func IsTUNConn(conn net.Conn) bool {
	_, ok := conn.(*gonet.TCPConn)
	return ok
}

// GetOriginalDstEBPF is not supported on Windows.
func GetOriginalDstEBPF(conn net.Conn, m TCPOrigDstMap) (string, error) {
	return "", fmt.Errorf("eBPF not supported on Windows")
}

// ListenUDPTransparent returns nil on Windows; UDP is handled by the gvisor stack.
func ListenUDPTransparent(port int) (*net.UDPConn, error) { return nil, nil }

// ListenUDP4Direct is not implemented on Windows.
func ListenUDP4Direct(port int) (*net.UDPConn, error) {
	return nil, fmt.Errorf("not implemented on Windows")
}

// ListenUDP6Direct is not implemented on Windows.
func ListenUDP6Direct(port int) (*net.UDPConn, error) {
	return nil, fmt.Errorf("not implemented on Windows")
}

// DialUDPTransparent is not implemented on Windows.
func DialUDPTransparent(origDst *net.UDPAddr) (*net.UDPConn, error) {
	return nil, fmt.Errorf("not implemented on Windows")
}

// ReadFromUDPWithOrigDst is not implemented on Windows.
func ReadFromUDPWithOrigDst(conn *net.UDPConn, b, oob []byte) (int, *net.UDPAddr, *net.UDPAddr, error) {
	return 0, nil, nil, fmt.Errorf("not implemented on Windows")
}

// StartWindowsTransparent is the entry point for the Windows transparent proxy.
// It creates a Wintun TUN device, sets up a gvisor userspace TCP/IP stack,
// and configures split routing so all traffic is intercepted.
func StartWindowsTransparent(ctx context.Context, tcpHandler func(net.Conn), udpHandler func(context.Context, net.Conn, string)) error {
	winMu.Lock()
	defer winMu.Unlock()

	if winTunDevice != nil {
		return nil // already running
	}

	// 0. Initialize Fake-IP Pool
	if err := dns.InitGlobalPool("198.18.0.0/15"); err != nil {
		return fmt.Errorf("failed to init Fake-IP pool: %v", err)
	}

	// 1. Create TUN device backed by the Wintun kernel driver.
	dev, err := tun.CreateTUN("vproxy-tun", 1500)
	if err != nil {
		return fmt.Errorf("failed to create TUN device: %v (run as Administrator and ensure Wintun is installed)", err)
	}
	winTunDevice = dev
	name, _ := dev.Name()
	log.Printf("[TUN/W] Created TUN device: %s", name)

	// 2. Initialise gvisor userspace TCP/IP stack.
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	winIPStack = s

	linkMAC, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	chanEP := channel.New(256, 1500, tcpip.LinkAddress(linkMAC))
	if tcpipErr := s.CreateNIC(1, chanEP); tcpipErr != nil {
		return fmt.Errorf("CreateNIC: %v", tcpipErr)
	}

	s.SetPromiscuousMode(1, true)
	s.SetSpoofing(1, true)
	s.SetForwardingDefaultAndAllNICs(ipv4.ProtocolNumber, true)
	s.SetForwardingDefaultAndAllNICs(ipv6.ProtocolNumber, true)

	// Assign an IP address so gvisor accepts inbound packets.
	tunIP := [4]byte{198, 18, 0, 1}
	if tcpipErr := s.AddProtocolAddress(1, tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFrom4(tunIP),
			PrefixLen: 15, // 198.18.0.0/15 (RFC 5737 non-routable range)
		},
	}, stack.AddressProperties{}); tcpipErr != nil {
		log.Printf("[TUN/W] Warning: AddProtocolAddress: %v", tcpipErr)
	}

	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: 1},
		{Destination: header.IPv6EmptySubnet, NIC: 1},
	})

	// 3. Bridge Wintun ↔ gvisor channel endpoint.
	go bridgeTunWindows(dev, chanEP)

	// 4. TCP forwarder — intercepts all TCP connections entering the TUN.
	tcpFwd := tcp.NewForwarder(s, 0, 10000, func(r *tcp.ForwarderRequest) {
		ep := r.ID()
		target := fmt.Sprintf("%s:%d", ep.LocalAddress, ep.LocalPort)
		log.Printf("[TUN/W] TCP → %s", target)

		var wq waiter.Queue
		endpoint, tcpipErr := r.CreateEndpoint(&wq)
		if tcpipErr != nil {
			r.Complete(true)
			return
		}
		r.Complete(false)
		go tcpHandler(gonet.NewTCPConn(&wq, endpoint))
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)

	// 5. UDP forwarder — wraps the intercepted endpoint (not an outbound dial).
	udpFwd := udp.NewForwarder(s, func(r *udp.ForwarderRequest) bool {
		ep := r.ID()
		target := fmt.Sprintf("%s:%d", ep.LocalAddress, ep.LocalPort)

		// Intercept DNS (port 53)
		if ep.LocalPort == 53 {
			var wq waiter.Queue
			endpoint, tcpipErr := r.CreateEndpoint(&wq)
			if tcpipErr != nil {
				return false
			}
			go func() {
				conn := gonet.NewUDPConn(&wq, endpoint)
				defer conn.Close()
				for {
					buf := make([]byte, 1024)
					n, remoteAddr, err := conn.ReadFrom(buf)
					if err != nil {
						if err != io.EOF {
							log.Printf("[TUN/W] DNS Read error: %v", err)
						}
						return
					}
					resp, domain, err := dns.HandleDNSQuery(buf[:n])
					if err != nil {
						log.Printf("[TUN/W] DNS Handle error for %s: %v", domain, err)
						continue
					}
					log.Printf("[TUN/W] DNS Hijacked: %s -> Fake-IP", domain)
					conn.WriteTo(resp, remoteAddr)
				}
			}()
			return true
		}

		var wq waiter.Queue
		endpoint, tcpipErr := r.CreateEndpoint(&wq)
		if tcpipErr != nil {
			return false
		}
		go udpHandler(ctx, gonet.NewUDPConn(&wq, endpoint), target)
		return true
	})
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpFwd.HandlePacket)

	// 6. Configure OS routing to direct all traffic through the TUN.
	return setupRoutingWindows(name)
}

// bridgeTunWindows shuttles raw IP packets between the Wintun device and gvisor.
// Wintun does NOT use a 4-byte PI header (unlike Darwin utun), so offset = 0.
func bridgeTunWindows(dev tun.Device, ep *channel.Endpoint) {
	const offset = 0

	// Wintun → gvisor
	go func() {
		for {
			pkt := make([]byte, 1600)
			bufs := [][]byte{pkt}
			sizes := make([]int, 1)
			n, err := dev.Read(bufs, sizes, offset)
			if err != nil {
				return
			}
			for i := 0; i < n; i++ {
				if sizes[i] <= 0 {
					continue
				}

				pktBuf := pkt[offset : offset+sizes[i]]

				// Handle ICMP Echo Requests locally to prevent "network broken" feel
				if CheckAndWriteICMP(dev, pktBuf, offset) {
					continue
				}

				pb := stack.NewPacketBuffer(stack.PacketBufferOptions{
					Payload: buffer.MakeWithData(pktBuf),
				})
				proto := tcpip.NetworkProtocolNumber(ipv4.ProtocolNumber)
				if (pktBuf[0] >> 4) == 6 {
					proto = ipv6.ProtocolNumber
				}
				ep.InjectInbound(proto, pb)
			}
		}
	}()

	// gvisor → Wintun (no PI header needed for Wintun)
	for {
		pb := ep.ReadContext(context.Background())
		if pb == nil {
			return
		}
		view := pb.ToView()
		raw := view.AsSlice()
		out := make([]byte, len(raw))
		copy(out, raw)
		dev.Write([][]byte{out}, offset)
		view.Release()
	}
}

// setupRoutingWindows assigns an IP to the Wintun adapter and adds two /1 routes
// that capture all internet traffic through the TUN without replacing the default route.
func setupRoutingWindows(tunName string) error {
	// Assign a static IP to the TUN interface.
	if out, err := exec.Command("netsh", "interface", "ip", "set", "address",
		fmt.Sprintf("name=%s", tunName), "static", "198.18.0.1", "255.255.0.0",
	).CombinedOutput(); err != nil {
		log.Printf("[TUN/W] Warning: netsh set address: %v: %s", err, out)
	}

	// Two /1 routes have longer prefix than the default /0, capturing all traffic.
	routes := [][]string{
		{"route", "add", "0.0.0.0", "mask", "128.0.0.0", "198.18.0.1", "metric", "1"},
		{"route", "add", "128.0.0.0", "mask", "128.0.0.0", "198.18.0.1", "metric", "1"},
	}
	for _, args := range routes {
		if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
			log.Printf("[TUN/W] Warning: %v: %s", args, out)
		}
	}
	return nil
}

// Cleanup removes the TUN routes and closes the Wintun device.
func Cleanup() {
	winMu.Lock()
	defer winMu.Unlock()
	if winTunDevice != nil {
		exec.Command("route", "delete", "0.0.0.0", "mask", "128.0.0.0").Run()
		exec.Command("route", "delete", "128.0.0.0", "mask", "128.0.0.0").Run()
		winTunDevice.Close()
		winTunDevice = nil
	}
}

// setsockoptInt calls ws2_32!setsockopt directly because Go's syscall package does
// not expose SetsockoptInt on Windows.
func setsockoptInt(fd uintptr, level, opt, value int) error {
	v := int32(value)
	ret, _, err := procSetsockopt.Call(fd, uintptr(level), uintptr(opt), uintptr(unsafe.Pointer(&v)), 4)
	if ret != 0 {
		return err
	}
	return nil
}

// getDefaultInterfaceIndex uses iphlpapi!GetBestInterface to find the index of the
// network interface used to reach the internet (i.e. the physical uplink, not TUN).
func getDefaultInterfaceIndex() (int, error) {
	dst := [4]byte{8, 8, 8, 8}
	var idx uint32
	ret, _, err := procGetBestInterface.Call(
		uintptr(*(*uint32)(unsafe.Pointer(&dst[0]))),
		uintptr(unsafe.Pointer(&idx)),
	)
	if ret != 0 {
		return 0, fmt.Errorf("GetBestInterface: %w", err)
	}
	return int(idx), nil
}

// GetDialerControl returns a DialContext control function that binds outgoing sockets
// to the physical uplink interface via IP_UNICAST_IF, so vproxy's own connections
// bypass the TUN and go directly to the network.
func GetDialerControl() func(network, address string, c syscall.RawConn) error {
	ifIdx, err := getDefaultInterfaceIndex()
	if err != nil {
		log.Printf("[TUN/W] GetDialerControl: %v", err)
		return nil
	}
	return func(network, address string, c syscall.RawConn) error {
		var opErr error
		_ = c.Control(func(fd uintptr) {
			switch network {
			case "tcp4", "udp4":
				opErr = setsockoptInt(fd, syscall.IPPROTO_IP, ipUnicastIF, ifIdx)
			case "tcp6", "udp6":
				opErr = setsockoptInt(fd, syscall.IPPROTO_IPV6, ipv6UnicastIF, ifIdx)
			default:
				_ = setsockoptInt(fd, syscall.IPPROTO_IP, ipUnicastIF, ifIdx)
				_ = setsockoptInt(fd, syscall.IPPROTO_IPV6, ipv6UnicastIF, ifIdx)
			}
		})
		return opErr
	}
}

// StartDarwinTransparent is not supported on Windows.
func StartDarwinTransparent(_ context.Context, _ func(net.Conn), _ func(context.Context, net.Conn, string)) error {
	return fmt.Errorf("StartDarwinTransparent not supported on Windows")
}
