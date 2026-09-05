//go:build windows
// +build windows

package tproxy

import (
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
