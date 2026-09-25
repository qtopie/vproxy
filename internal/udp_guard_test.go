package internal

import (
	"errors"
	"net"
	"testing"
	"time"
)

// SPEC-UDP-001
func TestResolveUDPTarget_EBPFHitPrefersMap(t *testing.T) {
	cmsgDst := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 10080}
	ebpfDst := &net.UDPAddr{IP: net.ParseIP("160.16.86.14"), Port: 443}

	dst, ok := resolveUDPTarget(true, cmsgDst, ebpfDst, nil)
	if !ok {
		t.Fatal("expected datagram to be accepted when the eBPF lookup hits")
	}
	if dst.String() != ebpfDst.String() {
		t.Fatalf("expected eBPF original destination %s, got %s", ebpfDst, dst)
	}
}

// SPEC-UDP-002: eBPF map miss falls back to cmsg; self-loop is caught downstream
// by isSelfProxyTarget(), not inside resolveUDPTarget.
func TestResolveUDPTarget_EBPFMissFallsBackToCmsg(t *testing.T) {
	cmsgDst := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 10080}

	// Lookup error: fall back to cmsg (127.0.0.1:10080 will be caught by isSelfProxyTarget).
	dst, ok := resolveUDPTarget(true, cmsgDst, nil, errors.New("lookup: key does not exist"))
	if !ok || dst == nil {
		t.Fatalf("expected cmsg fallback on eBPF lookup error, got dst=%v ok=%v", dst, ok)
	}
	if dst.String() != cmsgDst.String() {
		t.Fatalf("expected cmsg dst %s as fallback, got %s", cmsgDst, dst)
	}

	// ebpfDst==nil with no error: also fall back to cmsg.
	dst, ok = resolveUDPTarget(true, cmsgDst, nil, nil)
	if !ok || dst == nil {
		t.Fatalf("expected cmsg fallback when eBPF lookup yields no destination, got dst=%v ok=%v", dst, ok)
	}

	// Both cmsg and eBPF dst nil: drop.
	if dst, ok := resolveUDPTarget(true, nil, nil, errors.New("miss")); ok || dst != nil {
		t.Fatalf("expected drop when both eBPF and cmsg destinations are absent, got dst=%v ok=%v", dst, ok)
	}
}

// SPEC-UDP-003
func TestResolveUDPTarget_IPTablesMode(t *testing.T) {
	cmsgDst := &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 443}

	dst, ok := resolveUDPTarget(false, cmsgDst, nil, nil)
	if !ok || dst.String() != cmsgDst.String() {
		t.Fatalf("expected cmsg destination %s in TPROXY mode, got dst=%v ok=%v", cmsgDst, dst, ok)
	}

	if dst, ok := resolveUDPTarget(false, nil, nil, nil); ok || dst != nil {
		t.Fatalf("expected drop when cmsg destination is missing, got dst=%v ok=%v", dst, ok)
	}
}

// SPEC-UDP-004
func TestIsSelfProxyTarget_LoopbackListener(t *testing.T) {
	ph := &ProxyHandler{TransPort: 10080}

	for _, addr := range []*net.UDPAddr{
		{IP: net.ParseIP("127.0.0.1"), Port: 10080},
		{IP: net.ParseIP("::1"), Port: 10080},
	} {
		if !ph.isSelfProxyTarget(addr) {
			t.Fatalf("expected %s to be detected as vproxy's own listener", addr)
		}
	}
}

// SPEC-UDP-005
func TestIsSelfProxyTarget_AllowsNormalTargets(t *testing.T) {
	ph := &ProxyHandler{TransPort: 10080}

	for _, addr := range []*net.UDPAddr{
		nil,
		{IP: net.ParseIP("8.8.8.8"), Port: 10080},       // remote endpoint that happens to use the same port
		{IP: net.ParseIP("127.0.0.1"), Port: 8080},      // loopback on another port
		{IP: net.ParseIP("160.16.86.14"), Port: 443},    // typical QUIC target
		{IP: net.ParseIP("192.168.50.189"), Port: 1080}, // SOCKS5 upstream
	} {
		if ph.isSelfProxyTarget(addr) {
			t.Fatalf("expected %v to be forwarded, but it was flagged as self loop", addr)
		}
	}
}

// SPEC-UDP-006
func TestUDPDropLog_Throttles(t *testing.T) {
	var l udpDropLog
	start := time.Unix(1700000000, 0)

	if !l.allow(start, time.Second) {
		t.Fatal("expected the first diagnostic to be emitted")
	}
	for i := 1; i <= 4; i++ {
		if l.allow(start.Add(time.Duration(i)*10*time.Millisecond), time.Second) {
			t.Fatalf("expected diagnostic %d to be throttled", i)
		}
	}
	if !l.allow(start.Add(1500*time.Millisecond), time.Second) {
		t.Fatal("expected a diagnostic once the throttle window expired")
	}
}
