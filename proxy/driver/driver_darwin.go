//go:build darwin
// +build darwin

package driver

import (
	"context"
	"net"

	"github.com/qtopie/vproxy/proxy/tproxy"
)

type darwinDriver struct {
	cfg DriverConfig
}

// NewDriver creates the Darwin-specific InterceptDriver.
func NewDriver(cfg DriverConfig) InterceptDriver {
	return &darwinDriver{cfg: cfg}
}

func (d *darwinDriver) Name() string {
	return "darwin-pf"
}

func (d *darwinDriver) Start(ctx context.Context, onTCP ConnectionCallback, onUDP ConnectionCallback) error {
	return tproxy.StartDarwinTransparent(ctx, d.cfg.HttpPort, d.cfg.SocksPort, d.cfg.WebPort, func(conn net.Conn) {
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

func (d *darwinDriver) Cleanup() error {
	tproxy.Cleanup()
	return nil
}

// darwinProcessInspector implements ProcessInspector on macOS.
type darwinProcessInspector struct{}

func NewProcessInspector() ProcessInspector {
	return &darwinProcessInspector{}
}

func (i *darwinProcessInspector) GetProcessNameByConn(conn net.Conn) (string, int, error) {
	return tproxy.GetProcessNameByConn(conn)
}

func (i *darwinProcessInspector) GetProcessNameByPort(port int) (string, int, error) {
	return tproxy.GetProcessNameByPort(port)
}

// darwinRelayDetector implements RelayDetector on macOS.
type darwinRelayDetector struct{}

func NewRelayDetector(_ []string) RelayDetector {
	return &darwinRelayDetector{}
}

func (r *darwinRelayDetector) IsForwardedRelay(_ net.Conn, _ bool, _ int) bool {
	return false
}
