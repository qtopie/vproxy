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
}

func GetOriginalDst(conn net.Conn) (string, error) {
	tc, ok := conn.(*net.TCPConn)
	if !ok {
		return "", fmt.Errorf("not a TCP connection")
	}

	clientAddr := tc.RemoteAddr().(*net.TCPAddr)
	proxyAddr := tc.LocalAddr().(*net.TCPAddr)

	fd, err := os.OpenFile("/dev/pf", os.O_RDWR, 0666)
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

	binary.BigEndian.PutUint16(nl.Sxport[:2], uint16(clientAddr.Port))
	binary.BigEndian.PutUint16(nl.Dxport[:2], uint16(proxyAddr.Port))

	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd.Fd(), DIOCNATLOOK, uintptr(unsafe.Pointer(&nl)))
	if errno != 0 {
		nl.Direction = PF_IN
		_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, fd.Fd(), DIOCNATLOOK, uintptr(unsafe.Pointer(&nl)))
		if errno != 0 {
			return "", fmt.Errorf("DIOCNATLOOK failed: %v", errno)
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

func StartDarwinTransparent(ctx context.Context, tcpHandler func(net.Conn), udpHandler func(context.Context, net.Conn, string)) error {
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
				return
			}
			resp, domain, err := dns.HandleDNSQuery(buf[:n])
			if err != nil {
				continue
			}
			log.Printf("[PF] DNS Hijacked: %s -> Fake-IP", domain)
			udpConn.WriteTo(resp, remoteAddr)
		}
	}()

	// 4. Setup PF Rules
	err = setupPF(tcpPort, dnsPort)
	if err != nil {
		return fmt.Errorf("failed to setup PF rules: %v", err)
	}

	return nil
}

func setupPF(tcpPort, dnsPort int) error {
	// The proxy daemon itself runs as root (due to sudo bin/vproxy init)
	// We want to intercept all traffic EXCEPT the proxy's own traffic.
	// So we exempt "root".
	vproxyUser := "root"

	confPath := "/tmp/vproxy_pf.conf"
	
	// PF rules to redirect traffic but skip vproxy's own traffic
	rules := fmt.Sprintf(`
vproxy_user = "%s"
ext_if = "%s"

# NORMALIZATION RULES
scrub-anchor "com.apple/*" all fragment reassemble

# TRANSLATION RULES
nat-anchor "com.apple/*" all
rdr-anchor "com.apple/*" all

# Redirect DNS (53) to vproxy
rdr pass on lo0 inet proto udp from any to any port 53 -> 127.0.0.1 port %d
rdr pass on $ext_if inet proto udp from any to any port 53 -> 127.0.0.1 port %d

# Redirect TCP traffic to vproxy
rdr pass on lo0 inet proto tcp from any to any -> 127.0.0.1 port %d
rdr pass on $ext_if inet proto tcp from any to any -> 127.0.0.1 port %d

# FILTER RULES
anchor "com.apple/*" all

# Explicitly pass vproxy's own traffic and keep state so return packets aren't hijacked
pass out inet proto tcp all user $vproxy_user flags S/SA keep state
pass out inet proto udp all user $vproxy_user keep state

# Route-to passes the local traffic to loopback for redirection, if it doesn't match the user
pass out route-to lo0 inet proto tcp all user != $vproxy_user flags S/SA keep state
pass out route-to lo0 inet proto udp from any to any port 53 user != $vproxy_user keep state
`, vproxyUser, physIface, dnsPort, dnsPort, tcpPort, tcpPort)


	if err := os.WriteFile(confPath, []byte(rules), 0644); err != nil {
		return fmt.Errorf("failed to write pf conf: %v", err)
	}

	// Enable PF if not already enabled
	exec.Command("pfctl", "-e").Run()
	
	// Load rules
	cmd := exec.Command("pfctl", "-f", confPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("pfctl -f failed: %v, output: %s", err, out)
	}
	
	pfEnabled = true
	log.Printf("[PF] Rules loaded successfully via %s", confPath)
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
		// Restore default rules
		exec.Command("pfctl", "-F", "all", "-f", "/etc/pf.conf").Run()
		pfEnabled = false
		log.Printf("[PF] Rules cleared and restored to system defaults")
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
