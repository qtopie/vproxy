package driver

import (
	"context"
	"errors"
	"net"
)

// ErrProcessInspectionUnsupported indicates that the current platform cannot inspect process attribution.
var ErrProcessInspectionUnsupported = errors.New("process inspection is not supported on this platform")

// ConnectionCallback defines the signature for transparently captured TCP/UDP connections.
type ConnectionCallback func(conn net.Conn, target string)

// InterceptDriver defines the unified lifecycle contract for platform transparent proxy drivers.
type InterceptDriver interface {
	// Name returns the driver identifier (e.g. "linux-ebpf", "linux-tun", "windows-wintun", "darwin-pf").
	Name() string
	// Start begins transparent interception and delegates accepted connections to the callbacks.
	Start(ctx context.Context, onTCP ConnectionCallback, onUDP ConnectionCallback) error
	// Cleanup restores routing tables, firewall rules, and virtual interfaces.
	Cleanup() error
}

// ProcessInspector defines the contract for identifying the process and PID owning a connection or port.
type ProcessInspector interface {
	// GetProcessNameByConn inspects a network connection to determine the owning process name and PID.
	GetProcessNameByConn(conn net.Conn) (string, int, error)
	// GetProcessNameByPort inspects a local port to determine the owning process name and PID.
	GetProcessNameByPort(port int) (string, int, error)
}

// RelayDetector defines the contract for identifying forwarded relays or loopback subnets (e.g. WSL2).
type RelayDetector interface {
	// IsForwardedRelay returns true if the connection originated from a virtual subsystem requiring direct routing.
	IsForwardedRelay(conn net.Conn, isFakeIP bool, pid int) bool
}

// DriverConfig contains parameters needed to initialize platform drivers.
type DriverConfig struct {
	TransPort      int
	HttpPort       int
	SocksPort      int
	WebPort        int
	Servers        []string
	BypassNodes    []string
	DirectDNS      bool
	IsTUN          bool
	FallbackTarget string
}
