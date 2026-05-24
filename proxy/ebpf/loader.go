//go:build linux && !android
// +build linux,!android

package ebpf

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"runtime"
	"unsafe"

	ciliumebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -tags "linux,!android" -output-dir . bpf bpf/redirect.c

// LoadResult holds loaded BPF objects and cgroup attachment links.
// Call Unload() when done to release all kernel resources.
type LoadResult struct {
	// Maps for reading original destinations from the tproxy layer.
	TCPOrigDst   *ciliumebpf.Map
	UDPOrigDst   *ciliumebpf.Map
	CidrBypassMap *ciliumebpf.Map
	ConfigMap    *ciliumebpf.Map

	objs  bpfObjects
	links []link.Link
}

// IsKernelSupported returns true if the running kernel supports
// BPF_PROG_TYPE_CGROUP_SOCK_ADDR with connect4/sendmsg4/connect6/sendmsg6.
// This requires kernel >= 5.7 for the full set of hooks.
func IsKernelSupported() bool {
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		return false
	}
	// int8 array on some arches — convert to string safely
	var buf [65]byte
	for i, c := range u.Release {
		if c == 0 {
			break
		}
		buf[i] = byte(c)
	}
	release := string(buf[:])
	var major, minor int
	fmt.Sscanf(release, "%d.%d", &major, &minor)
	return major > 5 || (major == 5 && minor >= 7)
}

// Load compiles and attaches all BPF cgroup programs to cgroupPath,
// then initialises the config_map and writes default CIDR bypass entries.
// On error the caller should fall back to iptables.
func Load(cgroupPath string, proxyPort uint16, bypassMark uint32) (*LoadResult, error) {
	if runtime.GOARCH == "wasm" {
		return nil, fmt.Errorf("eBPF not supported on wasm")
	}

	spec, err := loadBpf()
	if err != nil {
		return nil, fmt.Errorf("loading bpf spec: %w", err)
	}

	var objs bpfObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		return nil, fmt.Errorf("loading bpf objects: %w", err)
	}

	// Open the cgroup directory FD for attachment.
	cgroupFD, err := os.Open(cgroupPath)
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("opening cgroup %s: %w", cgroupPath, err)
	}
	defer cgroupFD.Close()
	cgFD := int(cgroupFD.Fd())

	// Attach all four cgroup hooks.
	programs := []struct {
		prog    *ciliumebpf.Program
		attach  ciliumebpf.AttachType
		name    string
	}{
		{objs.Sock4Connect, ciliumebpf.AttachCGroupInet4Connect, "connect4"},
		{objs.Sock4Sendmsg, ciliumebpf.AttachCGroupUDP4Sendmsg, "sendmsg4"},
		{objs.Sock6Connect, ciliumebpf.AttachCGroupInet6Connect, "connect6"},
		{objs.Sock6Sendmsg, ciliumebpf.AttachCGroupUDP6Sendmsg, "sendmsg6"},
	}

	var links []link.Link
	for _, p := range programs {
		lnk, err := link.AttachCgroup(link.CgroupOptions{
			Path:    cgroupPath,
			Attach:  p.attach,
			Program: p.prog,
		})
		if err != nil {
			// Clean up already-attached links.
			for _, l := range links {
				l.Close()
			}
			objs.Close()
			return nil, fmt.Errorf("attaching %s: %w", p.name, err)
		}
		links = append(links, lnk)
	}
	_ = cgFD // cgroupFD was only needed for attachment path

	r := &LoadResult{
		TCPOrigDst:    objs.TcpOrigDst,
		UDPOrigDst:    objs.UdpOrigDst,
		CidrBypassMap: objs.CidrBypassMap,
		ConfigMap:     objs.ConfigMap,
		objs:          objs,
		links:         links,
	}

	// Write runtime configuration.
	if err := r.writeConfig(proxyPort, bypassMark, false); err != nil {
		r.Unload()
		return nil, fmt.Errorf("writing config_map: %w", err)
	}

	// Populate default CIDR bypass entries (private address ranges).
	cidr := NewCIDRManager(r.CidrBypassMap)
	if err := cidr.AddDefaults(); err != nil {
		r.Unload()
		return nil, fmt.Errorf("populating cidr_bypass_map: %w", err)
	}

	return r, nil
}

// UpdateConfig hot-updates proxy_port and bypass_mark without reloading BPF.
func (r *LoadResult) UpdateConfig(proxyPort uint16, bypassMark uint32, verbose bool) error {
	return r.writeConfig(proxyPort, bypassMark, verbose)
}

func (r *LoadResult) writeConfig(proxyPort uint16, bypassMark uint32, verbose bool) error {
	set := func(idx uint32, val uint64) error {
		return r.ConfigMap.Put(idx, val)
	}
	if err := set(cfgProxyPort, uint64(proxyPort)); err != nil {
		return err
	}
	if err := set(cfgBypassMark, uint64(bypassMark)); err != nil {
		return err
	}
	v := uint64(0)
	if verbose {
		v = 1
	}
	return set(cfgVerbose, v)
}

// Unload detaches all BPF programs and closes all map FDs.
func (r *LoadResult) Unload() error {
	var firstErr error
	for _, l := range r.links {
		if err := l.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	r.links = nil
	if err := r.objs.Close(); err != nil && firstErr == nil {
		firstErr = err
	}
	return firstErr
}

// config_map indices (must match redirect.c).
const (
	cfgProxyPort  uint32 = 0
	cfgBypassMark uint32 = 1
	cfgVerbose    uint32 = 2
)

// ── Map key/value types matching the C structs ────────────────────────────────

// UDPOrigKey mirrors struct udp_orig_key in redirect.c.
// src_port is in HOST byte order (matching bpf_sock.src_port).
type UDPOrigKey struct {
	SrcPort uint16
	Family  uint8
	Pad     uint8
}

// LPMCIDRKey mirrors struct lpm_cidr_key in redirect.c.
// Addr is in HOST byte order.
type LPMCIDRKey struct {
	Prefixlen uint32
	Addr      uint32
}

// OriginalDst mirrors struct original_dst in redirect.c.
type OriginalDst struct {
	IP     [4]uint32 // IPv4: IP[0] in network byte order; IPv6: all 4 words
	Port   uint32    // network byte order
	Family uint32    // AF_INET or AF_INET6
}

// ToTCPAddr converts an OriginalDst to a *net.TCPAddr.
func (d *OriginalDst) ToTCPAddr() *net.TCPAddr {
	return &net.TCPAddr{
		IP:   d.toNetIP(),
		Port: int(ntohs(uint16(d.Port))),
	}
}

// ToUDPAddr converts an OriginalDst to a *net.UDPAddr.
func (d *OriginalDst) ToUDPAddr() *net.UDPAddr {
	return &net.UDPAddr{
		IP:   d.toNetIP(),
		Port: int(ntohs(uint16(d.Port))),
	}
}

func (d *OriginalDst) toNetIP() net.IP {
	if d.Family == unix.AF_INET6 {
		b := make([]byte, 16)
		binary.BigEndian.PutUint32(b[0:4], d.IP[0])
		binary.BigEndian.PutUint32(b[4:8], d.IP[1])
		binary.BigEndian.PutUint32(b[8:12], d.IP[2])
		binary.BigEndian.PutUint32(b[12:16], d.IP[3])
		return net.IP(b)
	}
	// AF_INET: IP[0] is in network byte order
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, d.IP[0])
	return net.IP(b)
}

// ── TCP lookup/delete ─────────────────────────────────────────────────────────

// LookupTCPOrigDst retrieves the original destination for a TCP connection
// identified by its socket cookie. Deletes the entry on success to prevent leaks.
func LookupTCPOrigDst(m *ciliumebpf.Map, conn net.Conn) (*net.TCPAddr, error) {
	cookie, err := getSockCookie(conn)
	if err != nil {
		return nil, fmt.Errorf("getting socket cookie: %w", err)
	}

	var dst OriginalDst
	if err := m.LookupAndDelete(cookie, &dst); err != nil {
		return nil, fmt.Errorf("tcp_orig_dst lookup (cookie=%d): %w", cookie, err)
	}
	return dst.ToTCPAddr(), nil
}

// getSockCookie returns the SO_COOKIE value of conn (which must be a *net.TCPConn).
func getSockCookie(conn net.Conn) (uint64, error) {
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return 0, fmt.Errorf("not a *net.TCPConn")
	}
	raw, err := tcpConn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var cookie uint64
	var sockErr error
	_ = raw.Control(func(fd uintptr) {
		// SO_COOKIE = 57
		v, e := unix.GetsockoptUint64(int(fd), unix.SOL_SOCKET, unix.SO_COOKIE)
		if e != nil {
			sockErr = e
			return
		}
		cookie = v
	})
	if sockErr != nil {
		return 0, sockErr
	}
	return cookie, nil
}

// ── UDP lookup/delete ─────────────────────────────────────────────────────────

// LookupUDPOrigDst retrieves the original destination for a UDP packet
// identified by the sender's source port and address family.
// Deletes the entry on success.
func LookupUDPOrigDst(m *ciliumebpf.Map, srcAddr *net.UDPAddr) (*net.UDPAddr, error) {
	family := uint8(unix.AF_INET)
	if srcAddr.IP.To4() == nil {
		family = unix.AF_INET6
	}
	key := UDPOrigKey{
		SrcPort: uint16(srcAddr.Port),
		Family:  family,
	}

	var dst OriginalDst
	if err := m.LookupAndDelete(key, &dst); err != nil {
		return nil, fmt.Errorf("udp_orig_dst lookup (sport=%d family=%d): %w",
			key.SrcPort, family, err)
	}
	return dst.ToUDPAddr(), nil
}

// ── CIDR Bypass Manager ───────────────────────────────────────────────────────

// CIDRManager manages the cidr_bypass_map (LPM_TRIE).
type CIDRManager struct {
	m *ciliumebpf.Map
}

// NewCIDRManager wraps an existing cidr_bypass_map.
func NewCIDRManager(m *ciliumebpf.Map) *CIDRManager {
	return &CIDRManager{m: m}
}

// defaultCIDRs are the private/local IPv4 ranges always bypassed.
var defaultCIDRs = []string{
	"127.0.0.0/8",
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"169.254.0.0/16",
}

// AddDefaults writes the standard private address bypass entries.
func (c *CIDRManager) AddDefaults() error {
	for _, cidr := range defaultCIDRs {
		if err := c.Add(cidr); err != nil {
			return fmt.Errorf("adding default CIDR %s: %w", cidr, err)
		}
	}
	return nil
}

// Add inserts a CIDR into the bypass map. Only IPv4 CIDRs are supported
// (IPv6 bypass is handled by the inline is_local_ipv6 check in the BPF program).
func (c *CIDRManager) Add(cidr string) error {
	key, err := parseCIDRKey(cidr)
	if err != nil {
		return err
	}
	val := uint8(1)
	return c.m.Put(key, val)
}

// Remove deletes a CIDR from the bypass map.
func (c *CIDRManager) Remove(cidr string) error {
	key, err := parseCIDRKey(cidr)
	if err != nil {
		return err
	}
	return c.m.Delete(key)
}

// List returns all currently installed bypass CIDRs.
func (c *CIDRManager) List() ([]string, error) {
	var results []string
	var key, nextKey LPMCIDRKey
	var val uint8

	iter := c.m.Iterate()
	for iter.Next(&key, &val) {
		ones := key.Prefixlen
		addr := make(net.IP, 4)
		binary.BigEndian.PutUint32(addr, key.Addr)
		results = append(results, fmt.Sprintf("%s/%d", addr.String(), ones))
	}
	_ = nextKey
	return results, iter.Err()
}

func parseCIDRKey(cidr string) (LPMCIDRKey, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return LPMCIDRKey{}, fmt.Errorf("invalid CIDR %q: %w", cidr, err)
	}
	v4 := ipNet.IP.To4()
	if v4 == nil {
		return LPMCIDRKey{}, fmt.Errorf("only IPv4 CIDRs supported in cidr_bypass_map: %s", cidr)
	}
	ones, _ := ipNet.Mask.Size()
	return LPMCIDRKey{
		Prefixlen: uint32(ones),
		Addr:      binary.BigEndian.Uint32(v4), // host byte order
	}, nil
}

// ── Utilities ─────────────────────────────────────────────────────────────────

func ntohs(n uint16) uint16 {
	b := (*[2]byte)(unsafe.Pointer(&n))
	return uint16(b[0])<<8 | uint16(b[1])
}
