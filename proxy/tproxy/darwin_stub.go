//go:build !darwin && !windows && !linux
// +build !darwin,!windows,!linux

package tproxy

import (
	"context"
	"fmt"
	"net"
	"syscall"
)

// StartDarwinTransparent is a no-op on non-Darwin platforms.
func StartDarwinTransparent(_ context.Context, _ func(net.Conn), _ func(context.Context, net.Conn, string)) error {
	return fmt.Errorf("StartDarwinTransparent not supported on this platform")
}

// GetDialerControl returns nil on non-Darwin platforms (no interface binding needed).
func GetDialerControl() func(network, address string, c syscall.RawConn) error {
	return nil
}

// GetProcessNameByPort is not implemented on non-Darwin platforms.
func GetProcessNameByPort(_ int) (string, error) {
	return "", fmt.Errorf("GetProcessNameByPort not supported on this platform")
}

// GetProcessNameByConn is not implemented on non-Darwin platforms.
func GetProcessNameByConn(_ interface{}) (string, error) {
	return "", fmt.Errorf("GetProcessNameByConn not supported on this platform")
}
