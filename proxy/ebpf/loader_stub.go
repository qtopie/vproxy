//go:build !linux || android
// +build !linux android

package ebpf

import (
	"fmt"
	"net"

	ciliumebpf "github.com/cilium/ebpf"
)

// LoadResult is an empty stub on non-Linux platforms.
type LoadResult struct {
	TCPOrigDst    *ciliumebpf.Map
	UDPOrigDst    *ciliumebpf.Map
	CidrBypassMap *ciliumebpf.Map
	ConfigMap     *ciliumebpf.Map
}

// IsKernelSupported always returns false on non-Linux platforms.
func IsKernelSupported() bool { return false }

// Load always returns an error on non-Linux platforms.
func Load(_ string, _ uint16, _ uint32, _ bool, _ net.IP, _ uint16) (*LoadResult, error) {
	return nil, fmt.Errorf("eBPF not supported on this platform")
}

// Unload is a no-op on non-Linux platforms.
func (r *LoadResult) Unload() error { return nil }

// UpdateConfig is a no-op on non-Linux platforms.
func (r *LoadResult) UpdateConfig(_ uint16, _ uint32, _ bool, _ bool, _ net.IP, _ uint16) error { return nil }

// CIDRManager stub.
type CIDRManager struct{}

func NewCIDRManager(_ *ciliumebpf.Map) *CIDRManager { return &CIDRManager{} }
func (c *CIDRManager) Add(_ string) error           { return fmt.Errorf("not supported") }
func (c *CIDRManager) Remove(_ string) error        { return fmt.Errorf("not supported") }
func (c *CIDRManager) AddDefaults() error           { return fmt.Errorf("not supported") }
func (c *CIDRManager) List() ([]string, error)      { return nil, fmt.Errorf("not supported") }

// LookupTCPOrigDst stub.
func LookupTCPOrigDst(_ *ciliumebpf.Map, _ net.Conn) (*net.TCPAddr, error) {
	return nil, fmt.Errorf("not supported")
}

// LookupUDPOrigDst stub.
func LookupUDPOrigDst(_ *ciliumebpf.Map, _ *net.UDPAddr) (*net.UDPAddr, error) {
	return nil, fmt.Errorf("not supported")
}
