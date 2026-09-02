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

// mibUDPRowOwnerPID mirrors MIB_UDPROW_OWNER_PID from iphlpapi.h.
type mibUDPRowOwnerPID struct {
	LocalAddr uint32
	LocalPort uint32 // big-endian uint16 stored in lower 16 bits of uint32
	OwningPID uint32
}

const (
	tcpTableOwnerPIDAll = 5
	udpTableOwnerPID    = 1
)

// getPidByTCPPort calls GetExtendedTcpTable to find the PID that owns the given local TCP port.
func getPidByTCPPort(port int) (int, error) {
	var size uint32
	// Retry loop to handle TOCTOU table growth
	for attempts := 0; attempts < 3; attempts++ {
		procGetExtendedTcpTable.Call(0, uintptr(unsafe.Pointer(&size)), 0, windows.AF_INET, tcpTableOwnerPIDAll, 0)
		if size == 0 {
			break
		}
		buf := make([]byte, size+128)
		ret, _, _ := procGetExtendedTcpTable.Call(
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&size)),
			1, // bOrder: sort by local address
			windows.AF_INET,
			tcpTableOwnerPIDAll,
			0,
		)
		if ret == 0 {
			numEntries := *(*uint32)(unsafe.Pointer(&buf[0]))
			rowSize := unsafe.Sizeof(mibTCPRowOwnerPID{})
			for i := uint32(0); i < numEntries; i++ {
				row := (*mibTCPRowOwnerPID)(unsafe.Pointer(&buf[4+uintptr(i)*rowSize]))
				localPort := int(((row.LocalPort & 0xff) << 8) | ((row.LocalPort >> 8) & 0xff))
				if localPort == port {
					return int(row.OwningPID), nil
				}
			}
			return 0, fmt.Errorf("process not found for TCP port %d", port)
		}
		if ret != uintptr(windows.ERROR_INSUFFICIENT_BUFFER) {
			return 0, fmt.Errorf("GetExtendedTcpTable: error %d", ret)
		}
	}
	return 0, fmt.Errorf("process not found for TCP port %d", port)
}

// getPidByUDPPort calls GetExtendedUdpTable to find the PID that owns the given local UDP port.
func getPidByUDPPort(port int) (int, error) {
	var size uint32
	// Retry loop to handle TOCTOU table growth
	for attempts := 0; attempts < 3; attempts++ {
		procGetExtendedUdpTable.Call(0, uintptr(unsafe.Pointer(&size)), 0, windows.AF_INET, udpTableOwnerPID, 0)
		if size == 0 {
			break
		}
		buf := make([]byte, size+128)
		ret, _, _ := procGetExtendedUdpTable.Call(
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&size)),
			1, // bOrder: sort by local address
			windows.AF_INET,
			udpTableOwnerPID,
			0,
		)
		if ret == 0 {
			numEntries := *(*uint32)(unsafe.Pointer(&buf[0]))
			rowSize := unsafe.Sizeof(mibUDPRowOwnerPID{})
			for i := uint32(0); i < numEntries; i++ {
				row := (*mibUDPRowOwnerPID)(unsafe.Pointer(&buf[4+uintptr(i)*rowSize]))
				localPort := int(((row.LocalPort & 0xff) << 8) | ((row.LocalPort >> 8) & 0xff))
				if localPort == port {
					return int(row.OwningPID), nil
				}
			}
			return 0, fmt.Errorf("process not found for UDP port %d", port)
		}
		if ret != uintptr(windows.ERROR_INSUFFICIENT_BUFFER) {
			return 0, fmt.Errorf("GetExtendedUdpTable: error %d", ret)
		}
	}
	return 0, fmt.Errorf("process not found for UDP port %d", port)
}

// getPidByPort is an alias for getPidByTCPPort for backwards compatibility.
func getPidByPort(port int) (int, error) {
	return getPidByTCPPort(port)
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
func GetProcessNameByPort(port int) (string, int, error) {
	pid, err := getPidByTCPPort(port)
	if err != nil {
		return "", 0, err
	}
	path, err := getProcessPath(pid)
	if err != nil {
		return "", 0, err
	}
	return path, pid, nil
}

// GetProcessNameByUDPPort returns the full executable path of the process bound to
// the given local UDP port.
func GetProcessNameByUDPPort(port int) (string, int, error) {
	pid, err := getPidByUDPPort(port)
	if err != nil {
		return "", 0, err
	}
	path, err := getProcessPath(pid)
	if err != nil {
		return "", 0, err
	}
	return path, pid, nil
}

// GetProcessNameByConn returns the full executable path of the process that owns
// the connection's remote address (which is the app's local address in TUN mode).
func GetProcessNameByConn(conn interface{}) (string, int, error) {
	type remoteAddrIface interface {
		RemoteAddr() net.Addr
	}
	c, ok := conn.(remoteAddrIface)
	if !ok {
		return "", 0, fmt.Errorf("could not determine source port from connection")
	}
	switch addr := c.RemoteAddr().(type) {
	case *net.TCPAddr:
		return GetProcessNameByPort(addr.Port)
	case *net.UDPAddr:
		return GetProcessNameByUDPPort(addr.Port)
	}
	return "", 0, fmt.Errorf("unsupported address type")
}
