//go:build !linux
// +build !linux

package tproxy

import (
	"fmt"
	"net"
)

func GetOriginalDst(conn net.Conn) (string, error) {
	return "", fmt.Errorf("tproxy not supported on this platform")
}
