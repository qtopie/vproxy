//go:build !linux && !android
// +build !linux,!android

package ebpf

import "syscall"

func CheckPermission() error {
	return nil
}

func SetEnabled(e bool) {
}

func GetDialerControl() func(network, address string, c syscall.RawConn) error {
	return nil
}
