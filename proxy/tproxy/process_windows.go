//go:build windows
// +build windows

package tproxy

import (
	"fmt"
	"net"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modKernel32                    = windows.NewLazySystemDLL("kernel32.dll")
	procQueryFullProcessImageNameW = modKernel32.NewProc("QueryFullProcessImageNameW")
)

// mibTCPRowOwnerPID mirrors MIB_TCPROW_OWNER_PID from iphlpapi.h.
type mibTCPRowOwnerPID struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32 // big-endian uint16 stored in lower 16 bits of uint32
	RemoteAddr uint32
	RemotePort uint32
	OwningPID  uint32
}

const tcpTableOwnerPIDAll = 5

// getPidByPort calls GetExtendedTcpTable to find the PID that owns the given local port.
func getPidByPort(port int) (int, error) {
	// First call with nil buffer to obtain the required buffer size.
	var size uint32
	procGetExtendedTcpTable.Call(0, uintptr(unsafe.Pointer(&size)), 0, windows.AF_INET, tcpTableOwnerPIDAll, 0)

	buf := make([]byte, size+16) // add slack to handle TOCTOU growth
	ret, _, _ := procGetExtendedTcpTable.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		1, // bOrder: sort by local address
		windows.AF_INET,
		tcpTableOwnerPIDAll,
		0,
	)
	if ret != 0 {
		return 0, fmt.Errorf("GetExtendedTcpTable: error %d", ret)
	}

	numEntries := *(*uint32)(unsafe.Pointer(&buf[0]))
	rowSize := unsafe.Sizeof(mibTCPRowOwnerPID{})
	for i := uint32(0); i < numEntries; i++ {
		row := (*mibTCPRowOwnerPID)(unsafe.Pointer(&buf[4+uintptr(i)*rowSize]))
		// LocalPort is stored big-endian: swap the two low bytes to get host order.
		localPort := int(((row.LocalPort & 0xff) << 8) | ((row.LocalPort >> 8) & 0xff))
		if localPort == port {
			return int(row.OwningPID), nil
		}
	}
	return 0, fmt.Errorf("process not found for port %d", port)
}

// getProcessPath returns the full Win32 path of the executable for the given PID
// using kernel32!QueryFullProcessImageNameW.
func getProcessPath(pid int) (string, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return "", fmt.Errorf("OpenProcess pid=%d: %w", pid, err)
	}
	defer windows.CloseHandle(h)

	n := uint32(1024)
	buf := make([]uint16, n)
	ret, _, err := procQueryFullProcessImageNameW.Call(
		uintptr(h),
		0, // dwFlags=0 → Win32 path format (e.g. C:\Program Files\...)
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&n)),
	)
	if ret == 0 {
		return "", fmt.Errorf("QueryFullProcessImageNameW: %w", err)
	}
	return windows.UTF16ToString(buf[:n]), nil
}

// GetProcessNameByPort returns the full executable path of the process bound to
// the given local port (e.g. "C:\Program Files\Telegram Desktop\Telegram.exe").
//
// The path is stored in MatchContext.Process and matched case-insensitively as a
// substring, so PROCESS rules work with both short names ("Telegram") and full
// paths ("C:\Program Files\Telegram Desktop").
func GetProcessNameByPort(port int) (string, error) {
	pid, err := getPidByPort(port)
	if err != nil {
		return "", err
	}
	return getProcessPath(pid)
}

// GetProcessNameByConn returns the full executable path of the process that owns
// the connection's remote address (which is the app's local address in TUN mode).
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
	return "", fmt.Errorf("unsupported address type")
}
