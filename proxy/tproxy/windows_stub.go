//go:build !windows
// +build !windows

package tproxy

import (
	"context"
	"fmt"
	"net"
)

// StartWindowsTransparent is a no-op on non-Windows platforms.
func StartWindowsTransparent(_ context.Context, _ func(net.Conn), _ func(context.Context, net.Conn, string)) error {
	return fmt.Errorf("StartWindowsTransparent not supported on this platform")
}
