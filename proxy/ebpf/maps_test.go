//go:build linux && !android
// +build linux,!android

package ebpf

import (
	"encoding/binary"
	"net"
	"testing"

	"golang.org/x/sys/unix"
)

// ── parseCIDRKey ─────────────────────────────────────────────────────────────

func TestParseCIDRKey_Valid(t *testing.T) {
	tests := []struct {
		cidr           string
		wantPrefixlen  uint32
		wantAddrHost   uint32 // host byte order
	}{
		{"127.0.0.0/8", 8, 0x0000007F},
		{"10.0.0.0/8", 8, 0x0000000A},
		{"172.16.0.0/12", 12, 0x000010AC},
		{"192.168.0.0/16", 16, 0x0000A8C0},
		{"169.254.0.0/16", 16, 0x0000FEA9},
		{"0.0.0.0/0", 0, 0x00000000},
		{"8.8.8.8/32", 32, 0x08080808},
	}

	for _, tt := range tests {
		t.Run(tt.cidr, func(t *testing.T) {
			key, err := parseCIDRKey(tt.cidr)
			if err != nil {
				t.Fatalf("parseCIDRKey(%q) error: %v", tt.cidr, err)
			}
			if key.Prefixlen != tt.wantPrefixlen {
				t.Errorf("Prefixlen: got %d, want %d", key.Prefixlen, tt.wantPrefixlen)
			}
			gotAddr := binary.LittleEndian.Uint32(key.Addr[:])
			if gotAddr != tt.wantAddrHost {
				t.Errorf("Addr: got 0x%08X, want 0x%08X", gotAddr, tt.wantAddrHost)
			}
		})
	}
}

func TestParseCIDRKey_Invalid(t *testing.T) {
	cases := []string{
		"not-a-cidr",
		"256.0.0.0/8",
		"::1/128", // IPv6 not supported in cidr_bypass_map
	}
	for _, cidr := range cases {
		if _, err := parseCIDRKey(cidr); err == nil {
			t.Errorf("parseCIDRKey(%q): expected error, got nil", cidr)
		}
	}
}

// ── OriginalDst.ToTCPAddr / ToUDPAddr ────────────────────────────────────────

func TestOriginalDst_IPv4_ToTCPAddr(t *testing.T) {
	// Represent 1.2.3.4:8080
	dst := OriginalDst{
		IP:     [16]byte{1, 2, 3, 4},
		Port:   uint32(htons(8080)),
		Family: unix.AF_INET,
	}
	addr := dst.ToTCPAddr()
	if addr.Port != 8080 {
		t.Errorf("port: got %d, want 8080", addr.Port)
	}
	wantIP := net.IP{1, 2, 3, 4}
	if !addr.IP.Equal(wantIP) {
		t.Errorf("IP: got %v, want %v", addr.IP, wantIP)
	}
}

func TestOriginalDst_IPv6_ToUDPAddr(t *testing.T) {
	// Represent [2001:db8::1]:53
	// 2001:0db8:0000:0000:0000:0000:0000:0001
	var ipBytes [16]byte
	copy(ipBytes[:], net.ParseIP("2001:db8::1").To16())
	dst := OriginalDst{
		IP:     ipBytes,
		Family: unix.AF_INET6,
		Port:   uint32(htons(53)),
	}

	addr := dst.ToUDPAddr()
	if addr.Port != 53 {
		t.Errorf("port: got %d, want 53", addr.Port)
	}
	wantIP := net.ParseIP("2001:db8::1")
	if !addr.IP.Equal(wantIP) {
		t.Errorf("IP: got %v, want %v", addr.IP, wantIP)
	}
}

// ── ntohs helper ─────────────────────────────────────────────────────────────

func TestNtohs(t *testing.T) {
	// ntohs(0x1F90) == 8080 on little-endian (which is the typical host)
	// Network byte order 8080 = 0x1F90; in memory: [0x1F, 0x90]
	// As uint16 on little-endian host: 0x901F
	// ntohs should swap bytes back to 0x1F90 = 8080
	net8080 := htons(8080)
	got := ntohs(net8080)
	if got != 8080 {
		t.Errorf("ntohs(htons(8080)) = %d, want 8080", got)
	}
}

// ── UDPOrigKey layout ────────────────────────────────────────────────────────

func TestUDPOrigKey_Size(t *testing.T) {
	// Must be 4 bytes to match the C struct udp_orig_key exactly.
	var k UDPOrigKey
	if size := binary.Size(k); size != 4 {
		t.Errorf("UDPOrigKey size = %d, want 4", size)
	}
}

func TestLPMCIDRKey_Size(t *testing.T) {
	// Must be 8 bytes to match the C struct lpm_cidr_key exactly.
	var k LPMCIDRKey
	if size := binary.Size(k); size != 8 {
		t.Errorf("LPMCIDRKey size = %d, want 8", size)
	}
}

// ── IsKernelSupported ────────────────────────────────────────────────────────

func TestIsKernelSupported_NoPanic(t *testing.T) {
	// Just confirm it runs without panicking and returns a bool.
	_ = IsKernelSupported()
}

// ── helpers ──────────────────────────────────────────────────────────────────

// htons converts a uint16 from host to network byte order.
func htons(n uint16) uint16 {
	return (n>>8)&0xff | (n&0xff)<<8
}
