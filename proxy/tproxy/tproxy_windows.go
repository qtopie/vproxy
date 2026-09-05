//go:build windows
// +build windows

package tproxy

import (
	"context"
	"crypto/md5"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"net/url"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"github.com/qtopie/vproxy/internal/dns"
	"github.com/qtopie/vproxy/internal/winipcfg"
	"github.com/qtopie/vproxy/internal/wintunruntime"
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
	winTunLUID   winipcfg.LUID
	winTunDNS    []netip.Addr
	winTunBypassRoutes []winBypassRoute
	winIPStack   *stack.Stack
	winMu        sync.Mutex

	// iphlpapi.dll — routing and TCP/UDP table queries
	modIphlpapi             = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetBestInterface    = modIphlpapi.NewProc("GetBestInterface")
	procGetExtendedTcpTable = modIphlpapi.NewProc("GetExtendedTcpTable")
	procGetExtendedUdpTable = modIphlpapi.NewProc("GetExtendedUdpTable")

	// ws2_32.dll — raw setsockopt (Go's syscall doesn't expose SetsockoptInt on Windows)
	modWs2_32      = windows.NewLazySystemDLL("ws2_32.dll")
	procSetsockopt = modWs2_32.NewProc("setsockopt")
)

type winBypassRoute struct {
	luid    winipcfg.LUID
	prefix  netip.Prefix
	nextHop netip.Addr
}

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
func StartWindowsTransparent(ctx context.Context, upstreams []string, tcpHandler func(net.Conn), udpHandler func(context.Context, net.Conn, string)) (err error) {
	defer func() {
		if r := recover(); r != nil {
			cleanupWindowsState()
			err = fmt.Errorf("panic while initializing Wintun/TUN: %v", r)
		}
		if err != nil {
			cleanupWindowsState()
		}
	}()

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
	dllPath, err := wintunruntime.Ensure()
	if err != nil {
		return err
	}
	log.Printf("[TUN/W] Using bundled Wintun runtime: %s", dllPath)
	if h, err := windows.LoadLibrary("wintun.dll"); err != nil {
		return fmt.Errorf("bundled Wintun 0.14.1 could not be loaded: %w", err)
	} else {
		windows.FreeLibrary(h)
	}

	guid := generateGUIDByDeviceName("vproxy-tun")
	dev, err := tun.CreateTUNWithRequestedGUID("vproxy-tun", guid, 1500)
	if err != nil {
		log.Printf("[TUN/W] CreateTUNWithRequestedGUID failed (%v), retrying with default GUID", err)
		dev, err = tun.CreateTUN("vproxy-tun", 1500)
		if err != nil {
			return fmt.Errorf("failed to create TUN device: %v (run as Administrator and ensure Wintun is installed)", err)
		}
	}
	winTunDevice = dev
	name, _ := dev.Name()
	log.Printf("[TUN/W] Created TUN device: %s", name)

	type luidProvider interface {
		LUID() uint64
	}
	lp, ok := dev.(luidProvider)
	if !ok {
		return fmt.Errorf("TUN device does not provide LUID")
	}
	luid := winipcfg.LUID(lp.LUID())
	winTunLUID = luid
	log.Printf("[TUN/W] Acquired Wintun NET_LUID: %d", luid)

	// 2. Initialise gvisor userspace TCP/IP stack.
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	winIPStack = s

	chanEP := channel.New(256, 1500, "")
	chanEP.LinkEPCapabilities = stack.CapabilityRXChecksumOffload
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
	peerDNS := [4]byte{198, 18, 0, 2}
	if tcpipErr := s.AddProtocolAddress(1, tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFrom4(peerDNS),
			PrefixLen: 15,
		},
	}, stack.AddressProperties{}); tcpipErr != nil {
		return fmt.Errorf("add TUN peer DNS address: %v", tcpipErr)
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

	// 6. Configure OS routing directly via Windows IP Helper API (LUID) to direct all traffic through the TUN.
	return setupRoutingWindowsLUID(luid, upstreams)
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
				pb.RXChecksumValidated = true
				proto := tcpip.NetworkProtocolNumber(ipv4.ProtocolNumber)
				if (pktBuf[0] >> 4) == 6 {
					proto = ipv6.ProtocolNumber
				}
				ep.InjectInbound(proto, pb)
				pb.DecRef()
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
		if written, err := dev.Write([][]byte{out}, offset); err != nil {
			log.Printf("[TUN/W] Failed to write %d-byte packet to Wintun: %v", len(out), err)
		} else if written != 1 {
			log.Printf("[TUN/W] Wintun accepted %d/%d outbound packets", written, 1)
		}
		view.Release()
	}
}

func generateGUIDByDeviceName(name string) *windows.GUID {
	hash := md5.Sum([]byte("vproxy-wintun-" + name))
	return (*windows.GUID)(unsafe.Pointer(&hash[0]))
}

// setupRoutingWindowsLUID assigns an IP to the Wintun adapter and adds two /1 routes
// via the native Windows IP Helper API (iphlpapi.dll) directly using its NET_LUID.
func setupRoutingWindowsLUID(luid winipcfg.LUID, upstreams []string) error {
	// Assign static IPv4 198.18.0.1/15 to the Wintun adapter.
	prefix, err := netip.ParsePrefix("198.18.0.1/15")
	if err != nil {
		return fmt.Errorf("parse tun prefix: %w", err)
	}
	if err := luid.SetIPAddressesForFamily(winipcfg.AddressFamily(windows.AF_INET), []netip.Prefix{prefix}); err != nil {
		return fmt.Errorf("set ipv4 address on LUID %v: %w", luid, err)
	}
	previousDNS, err := luid.DNS()
	if err != nil {
		return fmt.Errorf("read DNS servers on LUID %v: %w", luid, err)
	}
	if err := luid.SetDNS(winipcfg.AddressFamily(windows.AF_INET), []netip.Addr{netip.MustParseAddr("198.18.0.2")}, nil); err != nil {
		return fmt.Errorf("set TUN DNS on LUID %v: %w", luid, err)
	}
	winTunDNS = previousDNS

	// Configure interface settings: enable IPv4 forwarding, disable router discovery.
	if inetIf, err := luid.IPInterface(winipcfg.AddressFamily(windows.AF_INET)); err == nil {
		inetIf.ForwardingEnabled = true
		inetIf.RouterDiscoveryBehavior = winipcfg.RouterDiscoveryDisabled
		inetIf.DadTransmits = 0
		inetIf.NLMTU = 1500
		inetIf.UseAutomaticMetric = false
		inetIf.Metric = 0
		_ = inetIf.Set()
	}

	// Two /1 routes have longer prefix than the default /0, capturing all traffic.
	routes := []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/1"),
		netip.MustParsePrefix("128.0.0.0/1"),
	}
	var installedRoutes []netip.Prefix
	for _, r := range routes {
		row := winipcfg.MibIPforwardRow2{}
		row.Init()
		row.InterfaceLUID = luid
		row.Metric = 1
		if err := row.DestinationPrefix.SetPrefix(r); err != nil {
			cleanupInstalledRoutes(luid, installedRoutes)
			return fmt.Errorf("set destination prefix %s: %w", r, err)
		}
		if err := row.Create(); err != nil {
			cleanupInstalledRoutes(luid, installedRoutes)
			return fmt.Errorf("create route %s on LUID %v: %w", r, luid, err)
		}
		installedRoutes = append(installedRoutes, r)
	}
	if err := setupUpstreamBypassRoutes(luid, upstreams); err != nil {
		cleanupInstalledRoutes(luid, installedRoutes)
		return err
	}
	return nil
}

func setupUpstreamBypassRoutes(tunLUID winipcfg.LUID, upstreams []string) error {
	routes, err := winipcfg.GetIPForwardTable2(windows.AF_INET)
	if err != nil {
		return fmt.Errorf("enumerate physical routes: %w", err)
	}
	var physical *winipcfg.MibIPforwardRow2
	for i := range routes {
		row := &routes[i]
		if row.InterfaceLUID == tunLUID || row.DestinationPrefix.PrefixLength != 0 {
			continue
		}
		if physical == nil || row.Metric < physical.Metric {
			physical = row
		}
	}
	if physical == nil {
		return nil
	}
	nextHop := physical.NextHop.Addr()
	if !nextHop.IsValid() || !nextHop.Is4() {
		return nil
	}

	seen := make(map[netip.Addr]struct{})
	for _, upstream := range upstreams {
		u, err := url.Parse(upstream)
		if err != nil || u.Hostname() == "" || isLocalBypassAddress(u.Hostname()) {
			continue
		}
		ips, err := net.LookupIP(u.Hostname())
		if err != nil {
			return fmt.Errorf("resolve upstream %s: %w", upstream, err)
		}
		for _, ip := range ips {
			addr, ok := netip.AddrFromSlice(ip)
			if !ok || !addr.Is4() {
				continue
			}
			if _, ok := seen[addr]; ok {
				continue
			}
			seen[addr] = struct{}{}
			prefix := netip.PrefixFrom(addr, 32)
			row := winipcfg.MibIPforwardRow2{}
			row.Init()
			row.InterfaceLUID = physical.InterfaceLUID
			row.Metric = 1
			if err := row.DestinationPrefix.SetPrefix(prefix); err != nil {
				return fmt.Errorf("set upstream bypass route %s: %w", addr, err)
			}
			if err := row.NextHop.SetAddr(nextHop); err != nil {
				return fmt.Errorf("set upstream bypass gateway %s: %w", nextHop, err)
			}
			if err := row.Create(); err != nil {
				return fmt.Errorf("create upstream bypass route %s: %w", addr, err)
			}
			winTunBypassRoutes = append(winTunBypassRoutes, winBypassRoute{
				luid: physical.InterfaceLUID, prefix: prefix, nextHop: nextHop,
			})
		}
	}
	return nil
}

func cleanupInstalledRoutes(luid winipcfg.LUID, routes []netip.Prefix) {
	for _, r := range routes {
		row := winipcfg.MibIPforwardRow2{}
		row.Init()
		row.InterfaceLUID = luid
		if err := row.DestinationPrefix.SetPrefix(r); err == nil {
			_ = row.Delete()
		}
	}
}

// Cleanup removes the TUN routes and closes the Wintun device.
func Cleanup() {
	winMu.Lock()
	defer winMu.Unlock()
	cleanupWindowsState()
}

func cleanupWindowsState() {
	if winTunLUID != 0 {
		for _, route := range winTunBypassRoutes {
			row := winipcfg.MibIPforwardRow2{}
			row.Init()
			row.InterfaceLUID = route.luid
			if err := row.DestinationPrefix.SetPrefix(route.prefix); err == nil {
				if err := row.NextHop.SetAddr(route.nextHop); err == nil {
					_ = row.Delete()
				}
			}
		}
		winTunBypassRoutes = nil
		if winTunDNS != nil {
			_ = winTunLUID.SetDNS(winipcfg.AddressFamily(windows.AF_INET), winTunDNS, nil)
			winTunDNS = nil
		} else {
			_ = winTunLUID.FlushDNS(winipcfg.AddressFamily(windows.AF_INET))
		}
		cleanupInstalledRoutes(winTunLUID, []netip.Prefix{
			netip.MustParsePrefix("0.0.0.0/1"),
			netip.MustParsePrefix("128.0.0.0/1"),
		})
		winTunLUID = 0
	}
	if winTunLUID == 0 {
		restoreDiscoveredTUNDNS()
	}
	// Fallback deletion to ensure routes are removed even if called from a separate CLI process
	// (e.g., 'vproxy clean' or 'vproxy stop') where winTunLUID is 0.
	_ = exec.Command("route", "delete", "0.0.0.0", "mask", "128.0.0.0").Run()
	_ = exec.Command("route", "delete", "128.0.0.0", "mask", "128.0.0.0").Run()

	if winTunDevice != nil {
		winTunDevice.Close()
		winTunDevice = nil
	}
}

func restoreDiscoveredTUNDNS() {
	adapters, err := winipcfg.GetAdaptersAddresses(windows.AF_UNSPEC, winipcfg.GAAFlagIncludeAll)
	if err != nil {
		return
	}
	for _, adapter := range adapters {
		if adapter == nil {
			continue
		}
		dnsServers, err := adapter.LUID.DNS()
		if err != nil {
			continue
		}
		for _, server := range dnsServers {
			if server == netip.MustParseAddr("198.18.0.1") || server == netip.MustParseAddr("198.18.0.2") {
				_ = adapter.LUID.FlushDNS(winipcfg.AddressFamily(windows.AF_INET))
				return
			}
		}
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
		host, _, splitErr := net.SplitHostPort(address)
		if splitErr == nil {
			if isLocalBypassAddress(host) {
				return nil
			}
		}
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

func isLocalBypassAddress(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()
}

// StartDarwinTransparent is not supported on Windows.
func StartDarwinTransparent(_ context.Context, _, _, _ int, _ func(net.Conn), _ func(context.Context, net.Conn, string)) error {
	return fmt.Errorf("StartDarwinTransparent not supported on Windows")
}
