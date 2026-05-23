//go:build linux && !android
// +build linux,!android

package ebpf

import (
	"fmt"
	"sync/atomic"
	"syscall"
)

const (
	bypassMark = 0xff
)

var (
	enabled atomic.Bool
)

// CheckPermission attempts to set SO_MARK on a dummy socket to verify CAP_NET_ADMIN.
func CheckPermission() error {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	
	err = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_MARK, bypassMark)
	if err != nil {
		return fmt.Errorf("failed to set SO_MARK (requires CAP_NET_ADMIN): %v", err)
	}
	return nil
}

// SetEnabled marks the ebpf component as active/inactive.
func SetEnabled(e bool) {
	enabled.Store(e)
}

// GetDialerControl returns a function suitable for net.Dialer.Control that applies SO_MARK.
func GetDialerControl() func(network, address string, c syscall.RawConn) error {
	if !enabled.Load() {
		return nil
	}
	
	return func(network, address string, c syscall.RawConn) error {
		var opErr error
		err := c.Control(func(fd uintptr) {
			// Set SO_MARK to bypassMark
			err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, bypassMark)
			if err != nil {
				opErr = err
			}
		})
		if err != nil {
			return err
		}
		return opErr
	}
}
