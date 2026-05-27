//go:build linux
// +build linux

package ipc

import (
	"fmt"
	"net"
	"syscall"
)

type peerCred struct {
	Pid int32
	Uid uint32
	Gid uint32
}

func getPeerCred(conn net.Conn) (*peerCred, error) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return nil, fmt.Errorf("not a unix socket")
	}

	var ucred *syscall.Ucred
	var err error

	rawConn, sysErr := unixConn.SyscallConn()
	if sysErr != nil {
		return nil, sysErr
	}

	rawConn.Control(func(fd uintptr) {
		ucred, err = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	})

	if err != nil {
		return nil, err
	}

	return &peerCred{
		Pid: ucred.Pid,
		Uid: ucred.Uid,
		Gid: ucred.Gid,
	}, nil
}
