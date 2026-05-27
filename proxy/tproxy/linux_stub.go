//go:build !linux
// +build !linux

package tproxy

import (
	"context"
	"fmt"
	"net"
)

// StartLinuxTransparent is a no-op stub for non-Linux platforms.
func StartLinuxTransparent(_ context.Context, _ func(net.Conn), _ func(context.Context, net.Conn, string)) error {
	return fmt.Errorf("StartLinuxTransparent not supported on this platform")
}
