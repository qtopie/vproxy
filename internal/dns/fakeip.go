package dns

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
)

// FakeIPPool manages allocation of fake IP addresses.
type FakeIPPool struct {
	subnet     *net.IPNet
	minIP      uint32
	maxIP      uint32
	current    uint32
	mu         sync.Mutex
	ipToDomain map[uint32]string
	domainToIP map[string]uint32
}

// NewFakeIPPool creates a new pool in the given CIDR (e.g. 198.18.0.0/16).
func NewFakeIPPool(cidr string) (*FakeIPPool, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	ones, bits := ipnet.Mask.Size()
	total := uint32(1 << uint(bits-ones))
	minIP := binary.BigEndian.Uint32(ipnet.IP)
	
	return &FakeIPPool{
		subnet:     ipnet,
		minIP:      minIP + 2, // Skip network and .1
		maxIP:      minIP + total - 2,
		current:    minIP + 2,
		ipToDomain: make(map[uint32]string),
		domainToIP: make(map[string]uint32),
	}, nil
}

func (p *FakeIPPool) GetIP(domain string) net.IP {
	p.mu.Lock()
	defer p.mu.Unlock()

	if ip, ok := p.domainToIP[domain]; ok {
		return uint32ToIP(ip)
	}

	ip := p.current
	p.current++
	if p.current > p.maxIP {
		p.current = p.minIP
	}

	p.domainToIP[domain] = ip
	p.ipToDomain[ip] = domain

	return uint32ToIP(ip)
}

func (p *FakeIPPool) GetDomain(ip net.IP) string {
	p.mu.Lock()
	defer p.mu.Unlock()

	v := binary.BigEndian.Uint32(ip.To4())
	return p.ipToDomain[v]
}

func (p *FakeIPPool) IsFakeIP(ip net.IP) bool {
	return p.subnet.Contains(ip)
}

func uint32ToIP(v uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, v)
	return ip
}

// Global pool for simplicity in this implementation
var (
	GlobalPool *FakeIPPool
	poolOnce   sync.Once
)

func InitGlobalPool(cidr string) error {
	var err error
	poolOnce.Do(func() {
		GlobalPool, err = NewFakeIPPool(cidr)
	})
	return err
}

// Simple DNS packet handling

func HandleDNSQuery(query []byte) ([]byte, string, error) {
	if len(query) < 12 {
		return nil, "", fmt.Errorf("packet too short")
	}

	// Transaction ID
	id := query[:2]
	// Flags: response, authoritative, recursion desired
	// We want to return a standard response: 0x8180 (Standard query response, No error)
	flags := []byte{0x81, 0x80}

	// Questions count
	qdCount := binary.BigEndian.Uint16(query[4:6])
	if qdCount != 1 {
		return nil, "", fmt.Errorf("only single question supported")
	}

	// Parse domain name
	domain, offset, err := parseDomain(query, 12)
	if err != nil {
		return nil, "", err
	}

	// Question type and class
	qType := binary.BigEndian.Uint16(query[offset : offset+2])
	// We only care about A records (Type 1)
	if qType != 1 {
		if qType == 28 { // AAAA
			// Return empty NOERROR response
			resp := make([]byte, 0, 12+len(query[12:offset+4]))
			resp = append(resp, id...)
			resp = append(resp, 0x81, 0x80)            // response, no error
			resp = append(resp, query[4:6]...)         // QDCOUNT
			resp = append(resp, 0, 0)                  // ANCOUNT = 0
			resp = append(resp, 0, 0)                  // NSCOUNT
			resp = append(resp, 0, 0)                  // ARCOUNT
			resp = append(resp, query[12:offset+4]...) // Question section
			return resp, domain, nil
		}
		return nil, domain, fmt.Errorf("only A and AAAA records supported")
	}

	fakeIP := GlobalPool.GetIP(domain)

	// Build response
	resp := make([]byte, 0, 512)
	resp = append(resp, id...)
	resp = append(resp, flags...)
	resp = append(resp, query[4:6]...) // QDCOUNT
	resp = append(resp, 0, 1)         // ANCOUNT = 1
	resp = append(resp, 0, 0)         // NSCOUNT
	resp = append(resp, 0, 0)         // ARCOUNT

	// Question section
	resp = append(resp, query[12:offset+4]...)

	// Answer section
	resp = append(resp, 0xc0, 0x0c)           // Name (pointer to domain in question)
	resp = append(resp, 0, 1)                 // Type A
	resp = append(resp, 0, 1)                 // Class IN
	resp = append(resp, 0, 0, 0, 60)          // TTL 60s
	resp = append(resp, 0, 4)                 // Data length 4
	resp = append(resp, fakeIP.To4()...)      // IP address

	return resp, domain, nil
}

func parseDomain(data []byte, offset int) (string, int, error) {
	var domain string
	curr := offset
	for {
		if curr >= len(data) {
			return "", 0, fmt.Errorf("out of bounds")
		}
		length := int(data[curr])
		if length == 0 {
			curr++
			break
		}
		if domain != "" {
			domain += "."
		}
		if curr+1+length > len(data) {
			return "", 0, fmt.Errorf("out of bounds")
		}
		domain += string(data[curr+1 : curr+1+length])
		curr += 1 + length
	}
	return domain, curr, nil
}
