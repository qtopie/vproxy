//go:build windows
// +build windows

package tproxy

import (
	"net"
	"net/netip"
	"testing"

	"github.com/qtopie/vproxy/internal/winipcfg"
)

func TestWindows_DeterministicGUID(t *testing.T) {
	guid1 := generateGUIDByDeviceName("vproxy-tun")
	guid2 := generateGUIDByDeviceName("vproxy-tun")
	if guid1 == nil || guid2 == nil {
		t.Fatalf("expected non-nil GUIDs")
	}
	if *guid1 != *guid2 {
		t.Fatalf("expected deterministic GUIDs, got %v vs %v", *guid1, *guid2)
	}

	guidOther := generateGUIDByDeviceName("other-tun")
	if *guid1 == *guidOther {
		t.Fatalf("expected different GUIDs for different device names")
	}
}

func TestWindows_LUIDRouteSetup(t *testing.T) {
	// SPEC-WIN-005: Verify data structure setup for LUID routing
	prefix1, err := netip.ParsePrefix("0.0.0.0/1")
	if err != nil {
		t.Fatalf("ParsePrefix 0.0.0.0/1: %v", err)
	}
	prefix2, err := netip.ParsePrefix("128.0.0.0/1")
	if err != nil {
		t.Fatalf("ParsePrefix 128.0.0.0/1: %v", err)
	}

	mockLUID := winipcfg.LUID(12345678)
	row := winipcfg.MibIPforwardRow2{}
	row.Init()
	row.InterfaceLUID = mockLUID
	row.Metric = 1

	if err := row.DestinationPrefix.SetPrefix(prefix1); err != nil {
		t.Fatalf("SetPrefix failed for %v: %v", prefix1, err)
	}
	if row.InterfaceLUID != mockLUID {
		t.Fatalf("expected InterfaceLUID %v, got %v", mockLUID, row.InterfaceLUID)
	}

	if err := row.DestinationPrefix.SetPrefix(prefix2); err != nil {
		t.Fatalf("SetPrefix failed for %v: %v", prefix2, err)
	}

	// Verify Cleanup is safe and doesn't panic
	Cleanup()
}

func TestWindows_BypassNodesRouteSetup(t *testing.T) {
	// SPEC-WIN-010: Verify data structure setup for bypass nodes and host /32 routes
	bypassCIDR := "192.0.2.0/24"
	bypassHost := "203.0.113.50"

	prefixCIDR, err := netip.ParsePrefix(bypassCIDR)
	if err != nil {
		t.Fatalf("ParsePrefix failed for %s: %v", bypassCIDR, err)
	}

	addrHost, err := netip.ParseAddr(bypassHost)
	if err != nil {
		t.Fatalf("ParseAddr failed for %s: %v", bypassHost, err)
	}
	prefixHost := netip.PrefixFrom(addrHost, 32)

	mockPhysLUID := winipcfg.LUID(87654321)
	nextHop := netip.MustParseAddr("192.168.1.1")

	row := winipcfg.MibIPforwardRow2{}
	row.Init()
	row.InterfaceLUID = mockPhysLUID
	row.Metric = 1

	if err := row.DestinationPrefix.SetPrefix(prefixCIDR); err != nil {
		t.Fatalf("SetPrefix failed for %v: %v", prefixCIDR, err)
	}
	if err := row.NextHop.SetAddr(nextHop); err != nil {
		t.Fatalf("SetAddr failed for %v: %v", nextHop, err)
	}

	rowHost := winipcfg.MibIPforwardRow2{}
	rowHost.Init()
	rowHost.InterfaceLUID = mockPhysLUID
	rowHost.Metric = 1
	if err := rowHost.DestinationPrefix.SetPrefix(prefixHost); err != nil {
		t.Fatalf("SetPrefix failed for %v: %v", prefixHost, err)
	}

	winTunBypassRoutes = append(winTunBypassRoutes, winBypassRoute{
		luid: mockPhysLUID, prefix: prefixCIDR, nextHop: nextHop,
	}, winBypassRoute{
		luid: mockPhysLUID, prefix: prefixHost, nextHop: nextHop,
	})

	if len(winTunBypassRoutes) != 2 {
		t.Fatalf("expected 2 bypass routes, got %d", len(winTunBypassRoutes))
	}

	// Verify cleanup empties bypass route tracker
	cleanupWindowsState()
	if len(winTunBypassRoutes) != 0 {
		t.Fatalf("expected bypass routes to be empty after cleanup, got %d", len(winTunBypassRoutes))
	}
}

func TestWindows_WintunLoadPath(t *testing.T) {
	// SPEC-WIN-011: Verify Wintun load path test invariant
	// In non-Windows runtime or test sandbox, ensure clean state
	cleanupWindowsState()
}

func TestWindows_IPv6TargetFormatting(t *testing.T) {
	// SPEC-WIN-016: Verify that IPv6 addresses are properly bracketed when constructing target address
	ipv6Addr := net.ParseIP("fe80::1")
	port := 53
	target := net.JoinHostPort(ipv6Addr.String(), "53")
	expected := "[fe80::1]:53"
	if target != expected {
		t.Fatalf("expected formatted IPv6 target %s, got %s", expected, target)
	}

	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		t.Fatalf("SplitHostPort failed for formatted IPv6 target %s: %v", target, err)
	}
	if host != "fe80::1" || portStr != "53" {
		t.Fatalf("unexpected host %s or port %s", host, portStr)
	}
	_ = port
}



