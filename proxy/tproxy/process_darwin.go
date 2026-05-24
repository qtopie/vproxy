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
	// sysProcInfo is the macOS proc_info(2) syscall number (both arm64 and amd64).
	sysProcInfo = 336
	// procInfoCallPidInfo selects the PROC_INFO_CALL_PIDINFO sub-call.
	procInfoCallPidInfo = 2
	// procPidPathInfo is the PROC_PIDPATHINFO flavor — returns the full
	// executable path for a given pid.
	procPidPathInfo = 11
	// procPidPathInfoMaxSize is PROC_PIDPATHINFO_MAXSIZE (4 KB).
	procPidPathInfoMaxSize = 4 * 1024
)

// procPidPath calls the macOS proc_info(PROC_PIDPATHINFO) syscall to retrieve
// the absolute executable path of pid without spawning any child process.
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
	// Trim at the first null byte; ret is the number of bytes written.
	n := bytes.IndexByte(buf, 0)
	if n < 0 {
		n = int(ret)
	}
	return string(buf[:n]), nil
}

// getPidByPort uses lsof to find the PID that owns the given local port.
// Only the PID field is requested (-Fp), which is faster than parsing the
// full lsof output.
func getPidByPort(port int) (int, error) {
	out, err := exec.Command("lsof", "-nP", "-i", fmt.Sprintf(":%d", port), "-Fp").Output()
	if err != nil {
		return 0, fmt.Errorf("lsof: %w", err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		if len(line) > 1 && line[0] == 'p' {
			pid, err := strconv.Atoi(strings.TrimSpace(line[1:]))
			if err == nil && pid > 0 {
				return pid, nil
			}
		}
	}
	return 0, fmt.Errorf("process not found for port %d", port)
}

// GetProcessNameByPort returns the full executable path of the process bound
// to the given local port (e.g. "/Applications/Telegram.app/Contents/MacOS/Telegram").
//
// This path is used directly as the Process field in MatchContext. PROCESS rules
// match if the rule pattern appears anywhere (case-insensitive) in this path, so
// both short-name rules ("Telegram") and path-prefix rules
// ("/Applications/Telegram.app") work out of the box.
func GetProcessNameByPort(port int) (string, error) {
	pid, err := getPidByPort(port)
	if err != nil {
		return "", err
	}
	path, err := procPidPath(pid)
	if err != nil {
		return "", fmt.Errorf("proc_pidpath pid=%d: %w", pid, err)
	}
	return path, nil
}

// GetProcessNameByConn identifies the process associated with a net.Conn and
// returns its full executable path. Works with gvisor gonet connections where
// RemoteAddr() is the originating application's address.
func GetProcessNameByConn(conn interface{}) (string, error) {
	type remoteAddrIface interface {
		RemoteAddr() net.Addr
	}
	c, ok := conn.(remoteAddrIface)
	if !ok {
		return "", fmt.Errorf("could not determine source port from connection")
	}
	switch addr := c.RemoteAddr().(type) {
	case *net.TCPAddr:
		return GetProcessNameByPort(addr.Port)
	case *net.UDPAddr:
		return GetProcessNameByPort(addr.Port)
	}
	return "", fmt.Errorf("could not determine source port from connection")
}
