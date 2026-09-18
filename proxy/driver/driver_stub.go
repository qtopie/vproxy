//go:build !linux && !windows && !darwin
// +build !linux,!windows,!darwin

package driver

import (
	"context"
	"fmt"
	"net"
)

type stubDriver struct {
	cfg DriverConfig
}

func NewDriver(cfg DriverConfig) InterceptDriver {
	return &stubDriver{cfg: cfg}
}

func (d *stubDriver) Name() string {
	return "stub"
}

func (d *stubDriver) Start(_ context.Context, _ ConnectionCallback, _ ConnectionCallback) error {
	return fmt.Errorf("transparent proxying not supported on this platform")
}

func (d *stubDriver) Cleanup() error {
	return nil
}

type stubProcessInspector struct{}

func NewProcessInspector() ProcessInspector {
	return &stubProcessInspector{}
}

func (i *stubProcessInspector) GetProcessNameByConn(_ net.Conn) (string, int, error) {
	return "", 0, ErrProcessInspectionUnsupported
}

func (i *stubProcessInspector) GetProcessNameByPort(_ int) (string, int, error) {
	return "", 0, ErrProcessInspectionUnsupported
}

type stubRelayDetector struct{}

func NewRelayDetector(_ []string) RelayDetector {
	return &stubRelayDetector{}
}

func (r *stubRelayDetector) IsForwardedRelay(_ net.Conn, _ bool, _ int) bool {
	return false
}
