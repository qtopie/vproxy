package dns

import (
	"encoding/binary"
	"net"
	"testing"
)

// TestFakeIPPool_InitAndLifecycle validates SPEC-FAKEIP-LINUX-001.
func TestFakeIPPool_InitAndLifecycle(t *testing.T) {
	pool, err := NewFakeIPPool("198.18.0.0/15")
	if err != nil {
		t.Fatalf("failed to create fake ip pool: %v", err)
	}

	ip1 := pool.GetIP("www.google.com")
	if ip1 == nil {
		t.Fatal("expected non-nil IP")
	}
	if !pool.IsFakeIP(ip1) {
		t.Fatalf("expected %s to be recognized as fake IP", ip1)
	}

	// Idempotency: same domain gets same IP
	ip2 := pool.GetIP("www.google.com")
	if !ip1.Equal(ip2) {
		t.Fatalf("expected same IP for same domain, got %s vs %s", ip1, ip2)
	}

	// Reverse lookup
	domain := pool.GetDomain(ip1)
	if domain != "www.google.com" {
		t.Fatalf("expected www.google.com, got %s", domain)
	}

	// Foreign IP check
	realIP := net.ParseIP("172.217.114.4")
	if pool.IsFakeIP(realIP) {
		t.Fatalf("expected %s to NOT be a fake IP", realIP)
	}
}

// buildDNSQuery creates a raw DNS query packet for testing.
func buildDNSQuery(txID uint16, domain string, qType uint16) []byte {
	buf := make([]byte, 12)
	binary.BigEndian.PutUint16(buf[0:2], txID)
	// Flags: Standard query (0x0100)
	buf[2] = 0x01
	buf[3] = 0x00
	// QDCOUNT = 1
	binary.BigEndian.PutUint16(buf[4:6], 1)

	// QNAME
	for _, part := range splitDomainLabels(domain) {
		buf = append(buf, byte(len(part)))
		buf = append(buf, []byte(part)...)
	}
	buf = append(buf, 0) // root label

	// QTYPE
	qtypeBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(qtypeBytes, qType)
	buf = append(buf, qtypeBytes...)

	// QCLASS = IN (1)
	qclassBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(qclassBytes, 1)
	buf = append(buf, qclassBytes...)

	return buf
}

func splitDomainLabels(domain string) []string {
	var parts []string
	curr := ""
	for i := 0; i < len(domain); i++ {
		if domain[i] == '.' {
			if curr != "" {
				parts = append(parts, curr)
				curr = ""
			}
		} else {
			curr += string(domain[i])
		}
	}
	if curr != "" {
		parts = append(parts, curr)
	}
	return parts
}

// TestHandleDNSQuery_TypeA validates SPEC-FAKEIP-LINUX-002.
func TestHandleDNSQuery_TypeA(t *testing.T) {
	_ = InitGlobalPool("198.18.0.0/15")

	rawQuery := buildDNSQuery(0x1234, "www.google.com", 1) // Type A = 1
	resp, domain, err := HandleDNSQuery(rawQuery)
	if err != nil {
		t.Fatalf("HandleDNSQuery failed: %v", err)
	}
	if domain != "www.google.com" {
		t.Fatalf("expected domain www.google.com, got %s", domain)
	}
	if len(resp) < 12 {
		t.Fatalf("response too short: %d", len(resp))
	}

	// Verify Transaction ID
	txID := binary.BigEndian.Uint16(resp[0:2])
	if txID != 0x1234 {
		t.Fatalf("expected txID 0x1234, got 0x%04x", txID)
	}

	// Verify ANCOUNT = 1
	anCount := binary.BigEndian.Uint16(resp[6:8])
	if anCount != 1 {
		t.Fatalf("expected 1 answer, got %d", anCount)
	}

	// Extract the returned IP from the end of the answer section (last 4 bytes)
	if len(resp) < 16 {
		t.Fatalf("response too short for answer IP: %d", len(resp))
	}
	ansIP := net.IP(resp[len(resp)-4:])
	if !GlobalPool.IsFakeIP(ansIP) {
		t.Fatalf("expected returned IP %s to be within Fake-IP pool", ansIP)
	}
	if GlobalPool.GetDomain(ansIP) != "www.google.com" {
		t.Fatalf("expected domain mapping for %s to be www.google.com, got %s", ansIP, GlobalPool.GetDomain(ansIP))
	}
}

// TestHandleDNSQuery_TypeAAAA validates SPEC-FAKEIP-LINUX-003.
func TestHandleDNSQuery_TypeAAAA(t *testing.T) {
	_ = InitGlobalPool("198.18.0.0/15")

	rawQuery := buildDNSQuery(0x5678, "www.google.com", 28) // Type AAAA = 28
	resp, domain, err := HandleDNSQuery(rawQuery)
	if err != nil {
		t.Fatalf("HandleDNSQuery failed: %v", err)
	}
	if domain != "www.google.com" {
		t.Fatalf("expected domain www.google.com, got %s", domain)
	}

	// Verify ANCOUNT = 0 (empty NOERROR response)
	anCount := binary.BigEndian.Uint16(resp[6:8])
	if anCount != 0 {
		t.Fatalf("expected 0 answer for AAAA, got %d", anCount)
	}

	// Verify Flags: Response bit set (0x8180)
	if resp[2] != 0x81 || resp[3] != 0x80 {
		t.Fatalf("expected flags 0x8180, got 0x%02x%02x", resp[2], resp[3])
	}
}
