//go:build windows
// +build windows

package driver

import (
	"context"
	"net"
	"net/url"

	"github.com/qtopie/vproxy/proxy/tproxy"
)

type windowsDriver struct {
	cfg DriverConfig
}

// NewDriver creates the Windows-specific InterceptDriver.
func NewDriver(cfg DriverConfig) InterceptDriver {
	return &windowsDriver{cfg: cfg}
}

func (d *windowsDriver) Name() string {
	return "windows-wintun"
}

func (d *windowsDriver) Start(ctx context.Context, onTCP ConnectionCallback, onUDP ConnectionCallback) error {
	return tproxy.StartWindowsTransparent(ctx, d.cfg.Servers, d.cfg.BypassNodes, func(conn net.Conn) {
		defer conn.Close()
		target, err := tproxy.GetOriginalDst(conn)
		if err != nil {
			return
		}
		onTCP(conn, target)
	}, func(ctx context.Context, local net.Conn, target string) {
		onUDP(local, target)
	})
}

func (d *windowsDriver) Cleanup() error {
	tproxy.Cleanup()
	return nil
}

// windowsProcessInspector implements ProcessInspector on Windows.
type windowsProcessInspector struct{}

func NewProcessInspector() ProcessInspector {
	return &windowsProcessInspector{}
}

func (i *windowsProcessInspector) GetProcessNameByConn(conn net.Conn) (string, int, error) {
	return tproxy.GetProcessNameByConn(conn)
}

func (i *windowsProcessInspector) GetProcessNameByPort(port int) (string, int, error) {
	return tproxy.GetProcessNameByPort(port)
}

// windowsRelayDetector implements RelayDetector on Windows for WSL2 / virtual relay loop detection.
type windowsRelayDetector struct {
	servers []string
}

func NewRelayDetector(servers []string) RelayDetector {
	return &windowsRelayDetector{servers: servers}
}

func (r *windowsRelayDetector) hasLocalUpstream() bool {
	for _, server := range r.servers {
		u, err := url.Parse(server)
		if err == nil && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1") {
			return true
		}
	}
	return false
}

func (r *windowsRelayDetector) IsForwardedRelay(conn net.Conn, isFakeIP bool, pid int) bool {
	if isFakeIP || pid > 0 || !r.hasLocalUpstream() {
		return false
	}
	type remoteAddrIface interface {
		RemoteAddr() net.Addr
	}
	c, ok := conn.(remoteAddrIface)
	if !ok || c.RemoteAddr() == nil {
		return false
	}
	var srcIP net.IP
	switch a := c.RemoteAddr().(type) {
	case *net.TCPAddr:
		srcIP = a.IP
	case *net.UDPAddr:
		srcIP = a.IP
	}
	if srcIP == nil {
		return false
	}
	if !srcIP.Equal(net.ParseIP("198.18.0.1")) && srcIP.IsPrivate() {
		return true
	}
	return pid == 0
}
