//go:build darwin
// +build darwin

package tproxy

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os/exec"
	"strings"
	"sync"
	"syscall"

	"github.com/qtopie/vproxy/internal/dns"
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
	tunDevice  tun.Device
	ipStack    *stack.Stack
	origRoutes []string
	mu         sync.Mutex
)

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

func GetOriginalDstEBPF(conn net.Conn, m TCPOrigDstMap) (string, error) {
	return "", fmt.Errorf("EBPF not supported on macOS")
}

// These are used by the existing serveTransparentUDP in internal/handler.go
// but on macOS we might need a different approach.
// For now, we'll implement them as stubs or placeholders.

func ListenUDPTransparent(port int) (*net.UDPConn, error) {
	// On macOS with TUN, we don't listen on a standard UDP port for transparent traffic.
	// Instead, the gvisor stack handles it.
	// Returning nil, nil to indicate it's handled elsewhere or should be ignored.
	return nil, nil
}

func ListenUDP4Direct(port int) (*net.UDPConn, error) {
	return nil, fmt.Errorf("not implemented on macOS")
}

func ListenUDP6Direct(port int) (*net.UDPConn, error) {
	return nil, fmt.Errorf("not implemented on macOS")
}

func DialUDPTransparent(origDst *net.UDPAddr) (*net.UDPConn, error) {
	return nil, fmt.Errorf("not implemented on macOS")
}

func ReadFromUDPWithOrigDst(conn *net.UDPConn, b []byte, oob []byte) (n int, src *net.UDPAddr, dst *net.UDPAddr, err error) {
	return 0, nil, nil, fmt.Errorf("not implemented on macOS")
}

// StartDarwinTransparent is the entry point for macOS transparent proxy.
// It sets up the TUN device, gvisor stack, and routing.
func StartDarwinTransparent(ctx context.Context, tcpHandler func(net.Conn), udpHandler func(context.Context, net.Conn, string)) error {
	mu.Lock()
	defer mu.Unlock()

	// 0. Initialize Fake-IP Pool
	if err := dns.InitGlobalPool("198.18.0.0/15"); err != nil {
		return fmt.Errorf("failed to init Fake-IP pool: %v", err)
	}

	// 1. Create TUN device
	// We use utun as the prefix for macOS.
	dev, err := tun.CreateTUN("utun", 1500)
	if err != nil {
		return fmt.Errorf("failed to create TUN device: %v (are you root?)", err)
	}
	tunDevice = dev
	name, _ := dev.Name()
	log.Printf("Created TUN device: %s", name)

	// 2. Initialize gvisor stack
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	ipStack = s

	// Create a channel-based link endpoint
	linkAddr, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	channelEndpoint := channel.New(256, 1500, tcpip.LinkAddress(linkAddr))

	if tcpipErr := s.CreateNIC(1, channelEndpoint); tcpipErr != nil {
		return fmt.Errorf("failed to create NIC: %v", tcpipErr)
	}

	// Enable promiscuous mode and forwarding to intercept all packets
	s.SetPromiscuousMode(1, true)
	s.SetSpoofing(1, true)
	s.SetForwardingDefaultAndAllNICs(ipv4.ProtocolNumber, true)
	s.SetForwardingDefaultAndAllNICs(ipv6.ProtocolNumber, true)

	// Assign an IP address so gvisor accepts inbound packets.
	// We use .2 for gvisor, while the host side (utun) is .1
	tunIP := [4]byte{198, 18, 0, 2}
	if tcpipErr := s.AddProtocolAddress(1, tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFrom4(tunIP),
			PrefixLen: 15,
		},
	}, stack.AddressProperties{}); tcpipErr != nil {
		log.Printf("[TUN] Warning: AddProtocolAddress IPv4: %v", tcpipErr)
	}

	tunIPv6 := [16]byte{0xfc, 0x00, 0x01, 0x98, 0x00, 0x18, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02}
	if tcpipErr := s.AddProtocolAddress(1, tcpip.ProtocolAddress{
		Protocol: ipv6.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFrom16(tunIPv6),
			PrefixLen: 64,
		},
	}, stack.AddressProperties{}); tcpipErr != nil {
		log.Printf("[TUN] Warning: AddProtocolAddress IPv6: %v", tcpipErr)
	}

	s.SetRouteTable([]tcpip.Route{
		{
			Destination: header.IPv4EmptySubnet,
			NIC:         1,
		},
		{
			Destination: header.IPv6EmptySubnet,
			NIC:         1,
		},
	})

	// Bridge between tunDevice and channelEndpoint
	go bridgeTun(dev, channelEndpoint)

	// 3. Set up TCP/UDP forwarders
	tcpForwarder := tcp.NewForwarder(s, 0, 10000, func(r *tcp.ForwarderRequest) {
		endpoint := r.ID()
		target := fmt.Sprintf("%s:%d", endpoint.LocalAddress, endpoint.LocalPort)
		log.Printf("[TUN] Intercepted TCP connection to %s", target)

		var wq waiter.Queue
		ep, err := r.CreateEndpoint(&wq)
		if err != nil {
			log.Printf("[TUN] Failed to create endpoint for %s: %v", target, err)
			r.Complete(true)
			return
		}
		r.Complete(false)
		conn := gonet.NewTCPConn(&wq, ep)
		go tcpHandler(conn)
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpForwarder.HandlePacket)

	udpHandlerFunc := func(r *udp.ForwarderRequest) bool {
		endpoint := r.ID()
		target := fmt.Sprintf("%s:%d", endpoint.LocalAddress, endpoint.LocalPort)

		// Intercept DNS (port 53)
		if endpoint.LocalPort == 53 {
			var wq waiter.Queue
			ep, err := r.CreateEndpoint(&wq)
			if err != nil {
				return false
			}
			go func() {
				conn := gonet.NewUDPConn(&wq, ep)
				defer conn.Close()
				for {
					buf := make([]byte, 1024)
					n, remoteAddr, err := conn.ReadFrom(buf)
					if err != nil {
						if err != io.EOF {
							log.Printf("[TUN] DNS Read error: %v", err)
						}
						return
					}
					resp, domain, err := dns.HandleDNSQuery(buf[:n])
					if err != nil {
						log.Printf("[TUN] DNS Handle error for %s: %v", domain, err)
						continue
					}
					log.Printf("[TUN] DNS Hijacked: %s -> Fake-IP", domain)
					conn.WriteTo(resp, remoteAddr)
				}
			}()
			return true
		}

		log.Printf("[TUN] Intercepted UDP packet to %s", target)

		var wq waiter.Queue
		ep, err := r.CreateEndpoint(&wq)
		if err != nil {
			return false
		}
		go udpHandler(context.Background(), gonet.NewUDPConn(&wq, ep), target)
		return true
	}
	udpForwarder := udp.NewForwarder(s, udpHandlerFunc)
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpForwarder.HandlePacket)

	// 4. Configure Routing
	if err := setupRouting(name); err != nil {
		return fmt.Errorf("failed to setup routing: %v", err)
	}

	return nil
}

func bridgeTun(dev tun.Device, ep *channel.Endpoint) {
	const offset = 4
	// Read from TUN, write to GVisor
	go func() {
		for {
			packet := make([]byte, 1600)
			packets := [][]byte{packet}
			sizes := make([]int, 1)
			n, err := dev.Read(packets, sizes, offset)
			if err != nil {
				return
			}
			for i := 0; i < n; i++ {
				if sizes[i] <= 0 {
					continue
				}

				pktBuf := packet[offset : offset+sizes[i]]

				// Handle ICMP Echo Requests locally to prevent "network broken" feel
				if CheckAndWriteICMP(dev, pktBuf, offset) {
					continue
				}

				pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
					Payload: buffer.MakeWithData(pktBuf),
				})
				// Determine protocol from IP header
				proto := ipv4.ProtocolNumber
				if (pktBuf[0] >> 4) == 6 {
					proto = ipv6.ProtocolNumber
				}
				ep.InjectInbound(proto, pkt)
			}
		}
	}()

	// Read from GVisor, write to TUN
	for {
		pkt := ep.ReadContext(context.Background())
		if pkt == nil {
			return
		}
		// Write pkt to dev
		view := pkt.ToView()
		buf := view.AsSlice()

		// For Write, we also need to provide the offset space
		outPacket := make([]byte, len(buf)+offset)
		copy(outPacket[offset:], buf)

		// Set AF_INET (2) or AF_INET6 (30) in big-endian in first 4 bytes
		if len(buf) > 0 && (buf[0]>>4) == 6 {
			binary.BigEndian.PutUint32(outPacket[:4], syscall.AF_INET6) // 30
		} else {
			binary.BigEndian.PutUint32(outPacket[:4], syscall.AF_INET)  // 2
		}

		dev.Write([][]byte{outPacket}, offset)
		view.Release()
	}
}

func setupRouting(tunName string) error {
	// 0. Configure the TUN interface IP address
	// Assign a point-to-point address pair to the utun interface
	if err := exec.Command("ifconfig", tunName, "198.18.0.1", "198.18.0.2", "up").Run(); err != nil {
		return fmt.Errorf("failed to ifconfig %s: %v", tunName, err)
	}
	// Configure IPv6 address
	exec.Command("ifconfig", tunName, "inet6", "fc00:198:18::1", "prefixlen", "64", "up").Run()

	// 1. Get default interface
	iface, err := getDefaultInterface()
	if err != nil {
		return err
	}
	log.Printf("Default interface: %s", iface)

	// 2. Add routes
	// IPv4: route add -net 0.0.0.0/1 -interface utunX
	// IPv6: route add -inet6 ::/1 -interface utunX
	cmds := [][]string{
		{"route", "add", "-net", "0.0.0.0/1", "-interface", tunName},
		{"route", "add", "-net", "128.0.0.0/1", "-interface", tunName},
		{"route", "add", "-inet6", "::/1", "-interface", tunName},
		{"route", "add", "-inet6", "8000::/1", "-interface", tunName},
	}
	for _, args := range cmds {
		if err := exec.Command(args[0], args[1:]...).Run(); err != nil {
			log.Printf("Warning: failed to run %v: %v", args, err)
		}
	}

	return nil
}

func Cleanup() {
	mu.Lock()
	defer mu.Unlock()

	if tunDevice != nil {
		name, _ := tunDevice.Name()
		// Remove routes
		cmds := [][]string{
			{"route", "delete", "-net", "0.0.0.0/1", "-interface", name},
			{"route", "delete", "-net", "128.0.0.0/1", "-interface", name},
			{"route", "delete", "-inet6", "::/1", "-interface", name},
			{"route", "delete", "-inet6", "8000::/1", "-interface", name},
		}
		for _, args := range cmds {
			exec.Command(args[0], args[1:]...).Run()
		}
		tunDevice.Close()
		tunDevice = nil
	}
}

func getDefaultInterface() (string, error) {
	out, err := exec.Command("route", "get", "default").Output()
	if err != nil {
		return "", err
	}
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "interface:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "interface:")), nil
		}
	}
	return "", fmt.Errorf("could not find default interface")
}

// GetDialerControl returns a dialer control function that binds the socket to the physical interface.
func GetDialerControl() func(network, address string, c syscall.RawConn) error {
	ifaceName, err := getDefaultInterface()
	if err != nil {
		return nil
	}
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil
	}
	index := iface.Index

	return func(network, address string, c syscall.RawConn) error {
		var opErr error
		err := c.Control(func(fd uintptr) {
			// macOS: IP_BOUND_IF
			switch network {
			case "tcp4", "udp4":
				opErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, 0x19 /* IP_BOUND_IF */, index)
			case "tcp6", "udp6":
				opErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, 0x19 /* IPV6_BOUND_IF */, index)
			default:
				_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, 0x19, index)
				_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, 0x19, index)
			}
		})
		if err != nil {
			return err
		}
		return opErr
	}
}
