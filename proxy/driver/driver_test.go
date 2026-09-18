package driver

import (
	"encoding/binary"
	"net"
	"runtime"
	"testing"

	"github.com/qtopie/vproxy/internal/dns"
)

func TestDriver_FactoryAndLifecycle(t *testing.T) {
	cfg := DriverConfig{
		TransPort: 10080,
		HttpPort:  8118,
		SocksPort: 1080,
		WebPort:   8899,
		Servers:   []string{"socks5://127.0.0.1:1080"},
	}

	d := NewDriver(cfg)
	if d == nil {
		t.Fatal("expected non-nil driver from NewDriver")
	}

	name := d.Name()
	if name == "" {
		t.Fatal("expected non-empty driver name")
	}

	switch runtime.GOOS {
	case "linux":
		if name != "linux-redirect" && name != "linux-tun" {
			t.Fatalf("unexpected linux driver name: %s", name)
		}
	case "windows":
		if name != "windows-wintun" {
			t.Fatalf("unexpected windows driver name: %s", name)
		}
	case "darwin":
		if name != "darwin-pf" {
			t.Fatalf("unexpected darwin driver name: %s", name)
		}
	}
}

func TestProcessInspector_Contract(t *testing.T) {
	inspector := NewProcessInspector()
	if inspector == nil {
		t.Fatal("expected non-nil inspector")
	}

	name, pid, err := inspector.GetProcessNameByPort(12345)
	if runtime.GOOS == "linux" {
		if err == nil {
			t.Logf("unexpectedly found process for unused port 12345: %s:%d", name, pid)
		}
		if err == ErrProcessInspectionUnsupported {
			t.Fatal("Linux ProcessInspector should no longer return ErrProcessInspectionUnsupported")
		}
	}
}

func TestRelayDetector_Contract(t *testing.T) {
	detector := NewRelayDetector([]string{"socks5://127.0.0.1:1080"})
	if detector == nil {
		t.Fatal("expected non-nil relay detector")
	}

	// On non-Windows platforms, IsForwardedRelay should always safely return false
	if runtime.GOOS != "windows" {
		if detector.IsForwardedRelay(nil, false, 0) {
			t.Fatal("expected false on non-windows platform")
		}
	}
}

func TestDNSHijacker_Pipeline(t *testing.T) {
	_ = dns.InitGlobalPool("198.18.0.0/15")

	// Construct DNS query packet for www.google.com
	buf := make([]byte, 12)
	binary.BigEndian.PutUint16(buf[0:2], 0x9999)
	buf[2] = 0x01
	buf[3] = 0x00
	binary.BigEndian.PutUint16(buf[4:6], 1) // QDCOUNT = 1
	for _, part := range []string{"www", "google", "com"} {
		buf = append(buf, byte(len(part)))
		buf = append(buf, []byte(part)...)
	}
	buf = append(buf, 0) // root label
	buf = append(buf, 0x00, 0x01) // QTYPE = A
	buf = append(buf, 0x00, 0x01) // QCLASS = IN

	resp, domain, handled := dns.HijackPacket(buf)
	if !handled {
		t.Fatal("expected packet to be handled by DNS hijacker")
	}
	if domain != "www.google.com" {
		t.Fatalf("expected domain www.google.com, got %s", domain)
	}
	if len(resp) < 16 {
		t.Fatalf("response too short: %d", len(resp))
	}
	ansIP := net.IP(resp[len(resp)-4:])
	if !dns.GlobalPool.IsFakeIP(ansIP) {
		t.Fatalf("expected returned IP %s to be Fake-IP", ansIP)
	}
}
