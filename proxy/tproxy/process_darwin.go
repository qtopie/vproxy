//go:build darwin
// +build darwin

package tproxy

import (
	"bytes"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

const (
	sysProcInfo = 336
	procInfoCallPidInfo = 2
	procPidPathInfo = 11
	procPidPathInfoMaxSize = 4 * 1024

	// Flavors for proc_pidinfo
	procPidAddrInfo = 4
)

// sockaddrStorage matches struct sockaddr_storage in C
type sockaddrStorage struct {
	Len    uint8
	Family uint8
	Data   [126]byte
}

// procPidAddrInfoStruct matches struct proc_addrinfo in C
type procPidAddrInfoStruct struct {
	PaiSaddr sockaddrStorage
	PaiDaddr sockaddrStorage
}

func GetProcessNameByConn(conn interface{}) (string, int, error) {
	type remoteAddrIface interface {
		RemoteAddr() net.Addr
	}
	c, ok := conn.(remoteAddrIface)
	if !ok {
		return "", 0, fmt.Errorf("connection does not implement RemoteAddr")
	}

	remote := c.RemoteAddr().(*net.TCPAddr)

	pid, err := getPidByPort(remote.Port)
	if err != nil {
		return "", 0, err
	}
	
	path, err := procPidPath(pid)
	return path, pid, err
}

func getPidByPort(port int) (int, error) {
	// Optimization: use -n (no DNS), -P (no port names), -i :port (specific port)
	out, err := exec.Command("lsof", "-nP", "-i", fmt.Sprintf(":%d", port), "-Fp").Output()
	if err != nil {
		return 0, err
	}
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		if len(line) > 1 && line[0] == 'p' {
			pid, err := strconv.Atoi(strings.TrimSpace(line[1:]))
			if err == nil {
				return pid, nil
			}
		}
	}
	return 0, fmt.Errorf("not found")
}

func procPidPath(pid int) (string, error) {
	buf := make([]byte, procPidPathInfoMaxSize)
	ret, _, errno := syscall.Syscall6(
		sysProcInfo,
		uintptr(procInfoCallPidInfo),
		uintptr(pid),
		uintptr(procPidPathInfo),
		0,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(procPidPathInfoMaxSize),
	)
	if int(ret) <= 0 {
		if errno != 0 {
			return "", errno
		}
		return "", fmt.Errorf("proc_pidpath: no result for pid %d", pid)
	}
	n := bytes.IndexByte(buf, 0)
	if n < 0 {
		n = int(ret)
	}
	return string(buf[:n]), nil
}

func GetProcessNameByPort(port int) (string, int, error) {
	pid, err := getPidByPort(port)
	if err != nil {
		return "", 0, err
	}
	path, err := procPidPath(pid)
	return path, pid, err
}
