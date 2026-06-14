//go:build darwin
// +build darwin

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

	"github.com/qtopie/vproxy/internal/dns"
)

var (
	physIface  string // Cached physical interface name (e.g., en0)
	physIP     net.IP // Cached physical interface IPv4 address
	mu         sync.Mutex
	pfEnabled  bool
	localTransLn net.Listener
	localDNSLn   *net.UDPConn
)

const (
	PF_INOUT    = 0
	PF_IN       = 1
	PF_OUT      = 2
	DIOCNATLOOK = 0xc0544417
)

type pfiocNatlook struct {
	Saddr     [16]byte
	Daddr     [16]byte
	Rsaddr    [16]byte
	Rdaddr    [16]byte
	Sxport    [4]byte
	Dxport    [4]byte
	Rsxport   [4]byte
	Rdxport   [4]byte
	Af        uint8
	Proto     uint8
	ProtoVar  uint8
	Direction uint8
	_         [4]byte // Padding to match struct size 84 (observed via C)
}

func GetOriginalDst(conn net.Conn) (string, error) {
	tc, ok := conn.(*net.TCPConn)
	if !ok {
		return "", fmt.Errorf("not a TCP connection")
	}

	clientAddr := tc.RemoteAddr().(*net.TCPAddr)
	proxyAddr := tc.LocalAddr().(*net.TCPAddr)

	fd, err := os.OpenFile("/dev/pf", os.O_RDWR, 0)
	if err != nil {
		return "", fmt.Errorf("failed to open /dev/pf: %v", err)
	}
	defer fd.Close()

	nl := pfiocNatlook{
		Af:        syscall.AF_INET,
		Proto:     syscall.IPPROTO_TCP,
		Direction: PF_OUT,
	}

	if clientAddr.IP.To4() == nil {
		nl.Af = syscall.AF_INET6
		copy(nl.Saddr[:], clientAddr.IP.To16())
		copy(nl.Daddr[:], proxyAddr.IP.To16())
	} else {
		copy(nl.Saddr[:], clientAddr.IP.To4())
		copy(nl.Daddr[:], proxyAddr.IP.To4())
	}

	// Ports must be in network byte order (big endian)
	binary.BigEndian.PutUint16(nl.Sxport[:2], uint16(clientAddr.Port))
	binary.BigEndian.PutUint16(nl.Dxport[:2], uint16(proxyAddr.Port))

	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd.Fd(), DIOCNATLOOK, uintptr(unsafe.Pointer(&nl)))
	if errno != 0 {
		// Try other direction
		nl.Direction = PF_IN
		_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, fd.Fd(), DIOCNATLOOK, uintptr(unsafe.Pointer(&nl)))
		if errno != 0 {
			return "", fmt.Errorf("DIOCNATLOOK failed (errno %d) for %s:%d -> %s:%d", errno, clientAddr.IP, clientAddr.Port, proxyAddr.IP, proxyAddr.Port)
		}
	}

	var targetIP net.IP
	if nl.Af == syscall.AF_INET {
		targetIP = net.IPv4(nl.Rdaddr[0], nl.Rdaddr[1], nl.Rdaddr[2], nl.Rdaddr[3])
	} else {
		targetIP = net.IP(nl.Rdaddr[:])
	}
	targetPort := binary.BigEndian.Uint16(nl.Rdxport[:2])

	domain := dns.GlobalPool.GetDomain(targetIP)
	if domain != "" {
		return fmt.Sprintf("%s:%d", domain, targetPort), nil
	}
	return fmt.Sprintf("%s:%d", targetIP.String(), targetPort), nil
}

// IsTUNConn checks if the connection originated from transparent interception.
func IsTUNConn(conn net.Conn) bool {
	return true // We'll just assume yes for now as it's handled by our listener
}

func GetOriginalDstEBPF(conn net.Conn, m TCPOrigDstMap) (string, error) {
	return "", fmt.Errorf("EBPF not supported on macOS")
}

func ListenUDPTransparent(port int) (*net.UDPConn, error) {
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

func StartDarwinTransparent(ctx context.Context, httpPort, socksPort, webPort int, tcpHandler func(net.Conn), udpHandler func(context.Context, net.Conn, string)) error {
	mu.Lock()
	defer mu.Unlock()

	// 0. Cache default physical interface
	ifaceName, err := getDefaultInterface()
	if err == nil {
		physIface = ifaceName
		log.Printf("[PF] Detected and cached physical interface: %s", physIface)
	}

	// 1. Initialize Fake-IP Pool
	if err := dns.InitGlobalPool("198.18.0.0/15"); err != nil {
		return fmt.Errorf("failed to init Fake-IP pool: %v", err)
	}

	// 2. Start Local TCP Listener
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("failed to start local TCP listener: %v", err)
	}
	localTransLn = ln
	tcpPort := ln.Addr().(*net.TCPAddr).Port
	log.Printf("[PF] Started local TCP transparent listener on port %d", tcpPort)

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go tcpHandler(conn)
		}
	}()

	// 3. Start Local UDP Listener for DNS
	udpAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("failed to start local UDP DNS listener: %v", err)
	}
	localDNSLn = udpConn
	dnsPort := udpConn.LocalAddr().(*net.UDPAddr).Port
	log.Printf("[PF] Started local UDP DNS listener on port %d", dnsPort)

	go func() {
		buf := make([]byte, 2048)
		for {
			n, remoteAddr, err := udpConn.ReadFrom(buf)
			if err != nil {
				log.Printf("[PF] DNS Listener error: %v", err)
				return
			}
			log.Printf("[PF] Received DNS query from %v (%d bytes)", remoteAddr, n)
			resp, domain, err := dns.HandleDNSQuery(buf[:n])
			if err != nil {
				log.Printf("[PF] DNS Handle error for %s: %v", domain, err)
				// Forward to real DNS? For now just skip
				continue
			}
			log.Printf("[PF] DNS Hijacked: %s -> Fake-IP", domain)
			udpConn.WriteTo(resp, remoteAddr)
		}
	}()

	// 4. Setup PF Rules
	err = setupPF(tcpPort, dnsPort, httpPort, socksPort, webPort)
	if err != nil {
		return fmt.Errorf("failed to setup PF rules: %v", err)
	}

	return nil
}

func setupPF(tcpPort, dnsPort, httpPort, socksPort, webPort int) error {
	vproxyUser := "root"
	confPath := "/tmp/vproxy_pf.conf"
	
	excludePorts := []string{
		fmt.Sprintf("%d", tcpPort),
		fmt.Sprintf("%d", httpPort),
		fmt.Sprintf("%d", socksPort),
		fmt.Sprintf("%d", webPort),
	}
	portList := strings.Join(excludePorts, ", ")

	// 1. Generate the isolated ruleset for the vproxy anchor
	anchorRules := fmt.Sprintf(`
vproxy_user = "%s"
proxy_ports = "{ %s }"
lan_nets = "{ 127.0.0.0/8, 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, 169.254.0.0/16, 224.0.0.0/4, fe80::/10, fd00::/8, ff00::/8 }"

# --- BYPASS RULES (Highest Priority) ---
# Allow all loopback and LAN traffic without any redirection
pass in quick on lo0 all
pass out quick on lo0 all
pass out quick proto icmp all keep state
pass out quick proto icmp6 all keep state
pass out quick to $lan_nets keep state
pass in quick from $lan_nets to any keep state

# Prevent loops for vproxy itself (root)
pass out quick user $vproxy_user keep state

# Bypass for explicit proxy ports
pass out quick inet proto tcp from any to any port $proxy_ports keep state

# --- REDIRECTION (RDR) ---
# Redirect intercepted traffic arriving at lo0 (from route-to below)
rdr pass on lo0 inet proto udp from any to any port 53 -> 127.0.0.1 port %d
rdr pass on lo0 inet proto tcp from any to any -> 127.0.0.1 port %d

# --- INTERCEPTION (Steering) ---
# Steering non-local TCP/DNS traffic to lo0
# Note: we only route-to lo0 if the destination is NOT a LAN address
pass out on %s route-to lo0 inet proto tcp from any to ! $lan_nets user != $vproxy_user keep state
pass out on %s route-to lo0 inet proto udp from any to ! $lan_nets port 53 user != $vproxy_user keep state
`, vproxyUser, portList, dnsPort, tcpPort, physIface, physIface)

	if err := os.WriteFile(confPath, []byte(anchorRules), 0644); err != nil {
		return fmt.Errorf("failed to write pf conf: %v", err)
	}

	// 2. Enable PF
	exec.Command("pfctl", "-e").Run()
	
	// 3. Load rules into the anchor
	cmd := exec.Command("pfctl", "-a", "vproxy", "-f", confPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to load pf anchor: %v, output: %s", err, out)
	}

	// 4. Inject the anchor references into the main ruleset without flushing it
	// We use a temporary file to hold the main rule pointers
	mainConf := "rdr-anchor \"vproxy\"\nanchor \"vproxy\"\n"
	mainConfPath := "/tmp/vproxy_main.conf"
	os.WriteFile(mainConfPath, []byte(mainConf), 0644)
	
	exec.Command("pfctl", "-g", "-f", mainConfPath).Run()
	
	pfEnabled = true
	log.Printf("[PF] Anchor 'vproxy' loaded successfully")
	return nil
}

func Cleanup() {
	mu.Lock()
	defer mu.Unlock()

	if localTransLn != nil {
		localTransLn.Close()
		localTransLn = nil
	}
	if localDNSLn != nil {
		localDNSLn.Close()
		localDNSLn = nil
	}

	if pfEnabled {
		// Flush only our anchor and its references
		exec.Command("pfctl", "-a", "vproxy", "-F", "all").Run()
		// Try to restore system rules if possible, but at least clear our anchor
		exec.Command("pfctl", "-f", "/etc/pf.conf").Run()
		pfEnabled = false
		log.Printf("[PF] vproxy anchor cleared")
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

func GetDialerControl() func(network, address string, c syscall.RawConn) error {
	// With PF architecture + user exemption, we don't need IP_BOUND_IF
	// for loop prevention. The system's default routing table is clean.
	return nil
}
