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
	"os/user"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"github.com/qtopie/vproxy/internal/dns"
)

var (
	physIface    string // Cached physical interface name (e.g., en0)
	physIP       net.IP // Cached physical interface IPv4 address
	mu           sync.Mutex
	pfEnabled    bool
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

	// For Darwin transparent proxy, if we got a real IP and the port is 443, we will let SNI sniffing handle it in handler.go
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
	// Detect the actual effective user running vproxy for the PF bypass rule.
	// The PF "pass out quick user $vproxy_user" rule must match the effective
	// UID of the vproxy process itself (NOT the sudo caller), so that vproxy's
	// own upstream TCP connections are not re-redirected into the transparent
	// proxy listener (which would cause an infinite loop).
	//
	// When launched via "sudo vproxy init", the daemon process runs as root
	// (uid=0), so user.Current() correctly returns "root".
	// When launched without sudo (via capabilities), user.Current() returns
	// the logged-in user.
	vproxyUser := "root"
	if u, err := user.Current(); err == nil && u.Username != "" {
		vproxyUser = u.Username
	}
	confPath := "/tmp/vproxy_pf.conf"

	excludePorts := []string{
		fmt.Sprintf("%d", tcpPort),
		fmt.Sprintf("%d", httpPort),
		fmt.Sprintf("%d", socksPort),
		fmt.Sprintf("%d", webPort),
	}
	portList := strings.Join(excludePorts, ", ")
	routeIface := "! lo0"

	// PF rules to redirect traffic while preserving local/LAN access and avoiding self-loops.
	//
	// Loop prevention mechanism:
	//   macOS PF's `rdr` rules do NOT support the `user` filter option — only `pass/block`
	//   filter rules support it. Loop prevention is achieved entirely through the filter layer:
	//
	//   "pass out quick user $vproxy_user keep state"
	//
	//   Because this uses `quick`, it is evaluated BEFORE the `route-to lo0` steering rule
	//   below. vproxy's own outgoing connections match `user $vproxy_user` and are immediately
	//   passed directly to the network stack, bypassing `route-to lo0`. This means vproxy's
	//   upstream dials NEVER arrive on lo0, and are therefore NEVER caught by the lo0 rdr rule.
	rules := fmt.Sprintf(`
vproxy_user = "%s"
proxy_ports = "{ %s }"
table <private_ips> const { 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 224.0.0.0/4, 240.0.0.0/4 }

# --- REDIRECTION (RDR) ---
# Note: macOS PF rdr rules do NOT support the 'user' filter option; loop prevention is
# handled exclusively by the "pass out quick user $vproxy_user" filter rule below.
rdr pass on lo0 inet proto udp from any to any port 53 -> 127.0.0.1 port %d
rdr pass on ! lo0 inet proto udp from any to any port 53 -> 127.0.0.1 port %d
rdr pass on lo0 inet proto tcp from any to ! <private_ips> -> 127.0.0.1 port %d

# --- BYPASS RULES (Highest Priority, evaluated before route-to steering below) ---
pass in quick on lo0 all
pass out quick on lo0 all
pass out quick proto icmp all keep state
pass out quick proto icmp6 all keep state
pass out quick to <private_ips> keep state
pass in quick from <private_ips> to any keep state
# PRIMARY loop-prevention: match vproxy's own uid first (quick = first-match-wins),
# bypassing the route-to lo0 rule so vproxy's upstream dials go directly to the wire.
pass out quick user $vproxy_user keep state
pass out quick inet proto tcp from any to any port $proxy_ports keep state

# --- INTERCEPTION (Steering): redirect non-vproxy outbound TCP through the proxy ---
pass out on %s route-to lo0 inet proto tcp from any to ! <private_ips> user != $vproxy_user flags S/SA keep state
pass out on %s route-to lo0 inet proto udp from any to any port 53 user != $vproxy_user keep state
 `, vproxyUser, portList, dnsPort, dnsPort, tcpPort, routeIface, routeIface)

	if err := os.WriteFile(confPath, []byte(rules), 0644); err != nil {
		return fmt.Errorf("failed to write pf conf: %v", err)
	}

	// 2. Enable PF
	exec.Command("pfctl", "-e").Run()

	// Load rules into com.apple/vproxy anchor so we don't destroy system/third-party PF rules
	cmd := exec.Command("pfctl", "-a", "com.apple/vproxy", "-f", confPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("pfctl loading anchor failed: %v, output: %s", err, out)
	}

	// 4. Inject the anchor references into the main ruleset without flushing it.
	mainConf := "rdr-anchor \"com.apple/vproxy\"\nanchor \"com.apple/vproxy\"\n"
	mainConfPath := "/tmp/vproxy_main.conf"
	os.WriteFile(mainConfPath, []byte(mainConf), 0644)

	exec.Command("pfctl", "-g", "-f", mainConfPath).Run()

	pfEnabled = true
	log.Printf("[PF] Rules loaded successfully into com.apple/vproxy anchor via %s", confPath)
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
		// Clean up only our anchor com.apple/vproxy without touching system default rules
		exec.Command("pfctl", "-a", "com.apple/vproxy", "-F", "all").Run()
		pfEnabled = false
		log.Printf("[PF] Rules cleared from anchor com.apple/vproxy")
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
