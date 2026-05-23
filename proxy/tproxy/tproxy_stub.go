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

func ListenUDPTransparent(port int) (*net.UDPConn, error) {
	return nil, fmt.Errorf("udp transparent proxy not supported on this platform")
}

func DialUDPTransparent(origDst *net.UDPAddr) (*net.UDPConn, error) {
	return nil, fmt.Errorf("udp transparent proxy not supported on this platform")
}

func ReadFromUDPWithOrigDst(conn *net.UDPConn, b []byte, oob []byte) (n int, src *net.UDPAddr, dst *net.UDPAddr, err error) {
	return 0, nil, nil, fmt.Errorf("udp transparent proxy not supported on this platform")
}
