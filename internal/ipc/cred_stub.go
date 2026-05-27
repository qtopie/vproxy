//go:build !linux
// +build !linux

package ipc

import (
	"fmt"
	"net"
)

type peerCred struct {
	Pid int32
	Uid uint32
	Gid uint32
}

func getPeerCred(conn net.Conn) (*peerCred, error) {
	return nil, fmt.Errorf("SO_PEERCRED is only supported on Linux")
}
