//go:build darwin
// +build darwin

package tproxy

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	sysProcInfo            = 336
	procInfoCallPidInfo    = 2
	procPidPathInfo        = 11
	procPidPathInfoMaxSize = 4 * 1024

	// Flavors for proc_pidinfo
	procPidAddrInfo = 4

	// Sysctl record kinds for net.inet.tcp.pcblist_n (from XNU <sys/socketvar.h>)
	xsoSocket = 0x001 // xsocket_n record — contains the owning PID
	xsoInPCB  = 0x010 // xinpcb_n record  — contains the local/foreign port
	xsoTCPCB  = 0x100 // xtcpcb_n record
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

// xgenN is the common 8-byte header of every record returned by pcblist_n.
type xgenN struct {
	Len  uint32
	Kind uint32
}

// Byte offsets within each record type (derived from XNU source headers).
//
// xsocket_n layout (XSO_SOCKET, kind=0x001):
//   uint32 xso_len        @ 0
//   uint32 xso_kind       @ 4
//   uint64 xso_so         @ 8   (pointer)
//   int16  xso_type       @ 16
//   uint16 _pad0          @ 18
//   uint32 xso_options    @ 20
//   int16  xso_linger     @ 24
//   int16  xso_state      @ 26
//   int16  xso_family     @ 28
//   int16  _unused        @ 30
//   int32  xso_protocol   @ 32
//   int32  xso_family2    @ 36
//   int16  xso_error      @ 40
//   int16  _pad1          @ 42
//   int32  xso_pgid       @ 44
//   uint64 xso_oobmark    @ 48
//   xsockbuf_n xso_rcv    @ 56  (32 bytes)
//   xsockbuf_n xso_snd    @ 88  (32 bytes)
//   uint32 xso_uid        @ 120
//   int32  xso_e_pid      @ 124  ← EFFECTIVE PID we need
const xsocketEPidOffset = 124

// xinpcb_n layout (XSO_INPCB, kind=0x010):
//   uint32 xi_len         @ 0
//   uint32 xi_kind        @ 4
//   uint64 xi_inpp        @ 8   (pointer)
//   uint16 inp_vflag      @ 16
//   uint8  inp_ip_ttl     @ 18
//   uint8  inp_ip_p       @ 19
//   uint32 _pad           @ 20
//   [16]   inp_dep_faddr  @ 24  (foreign address union)
//   [16]   inp_dep_laddr  @ 40  (local address union)
//   uint16 inp_fport      @ 56  (network / big-endian byte order)
//   uint16 inp_lport      @ 58  (network / big-endian byte order) ← LOCAL PORT
const (
	xinpcbFPortOffset = 56
	xinpcbLPortOffset = 58
)

// getPidByPort finds the PID whose TCP socket is bound to the given local port.
// It first tries the fast sysctl path (single kernel call, no subprocess);
// on failure it falls back to lsof.
func getPidByPort(port int) (int, error) {
	pid, err := getPidByPortSysctl(port)
	if err == nil {
		log.Printf("[PF] getPidByPort(sysctl): port=%d pid=%d", port, pid)
		return pid, nil
	}
	log.Printf("[PF] getPidByPort(sysctl) miss for port=%d: %v, falling back to lsof", port, err)
	pid, err = getPidByPortLSOF(port)
	if err != nil {
		log.Printf("[PF] getPidByPort(lsof) miss for port=%d: %v", port, err)
	}
	return pid, err
}

// getPidByPortSysctl implements the fast path using sysctl net.inet.tcp.pcblist_n.
//
// The kernel returns a sequence of variable-length records. For each TCP socket
// the sequence is:
//
//	xsocket_n (kind=0x001)  – contains xso_e_pid
//	xsockbuf_n×2 (0x002/0x004)
//	xsockstat_n  (0x008)
//	xinpcb_n     (kind=0x010) – contains inp_lport
//	xtcpcb_n     (kind=0x100)
//
// We track the most recently seen PID (from xsocket_n) and match it when we
// find an xinpcb_n whose inp_lport equals targetPort.
func getPidByPortSysctl(targetPort int) (int, error) {
	buf, err := unix.SysctlRaw("net.inet.tcp.pcblist_n")
	if err != nil {
		return 0, fmt.Errorf("sysctl net.inet.tcp.pcblist_n: %w", err)
	}

	// The xinpgen header is self-describing: its first uint32 is its own byte length.
	// On macOS 26.5.1 the header is 24 bytes (not the 16 assumed in older XNU headers).
	if len(buf) < 4 {
		return 0, fmt.Errorf("pcblist_n buffer too small (%d bytes)", len(buf))
	}
	xinpgenSize := int(binary.LittleEndian.Uint32(buf[0:4]))
	if xinpgenSize < 8 || xinpgenSize > len(buf) {
		return 0, fmt.Errorf("pcblist_n xinpgen size %d out of range", xinpgenSize)
	}
	buf = buf[xinpgenSize:]

	var currentPID int32

	for len(buf) >= 8 {
		recLen := binary.LittleEndian.Uint32(buf[0:4])
		recKind := binary.LittleEndian.Uint32(buf[4:8])

		if recLen < 8 || int(recLen) > len(buf) {
			break
		}
		rec := buf[:recLen]
		buf = buf[recLen:]

		switch recKind {
		case xsoSocket:
			// Extract the effective PID at offset 124.
			if int(recLen) > xsocketEPidOffset+4 {
				currentPID = int32(binary.LittleEndian.Uint32(rec[xsocketEPidOffset : xsocketEPidOffset+4]))
			}

		case xsoInPCB:
			// Extract the local port at offset 58 (big-endian / network byte order).
			if int(recLen) > xinpcbLPortOffset+2 {
				lport := int(binary.BigEndian.Uint16(rec[xinpcbLPortOffset : xinpcbLPortOffset+2]))
				if lport == targetPort && currentPID > 0 {
					return int(currentPID), nil
				}
			}
		}
	}

	return 0, fmt.Errorf("no TCP socket found on local port %d", targetPort)
}

// getPidByPortLSOF is the fallback using the lsof utility.
// It returns the PID and also caches the process name to avoid a proc_pidpath call.
var lsofProcNameCache = struct {
	sync.Map
}{}

func getPidAndNameByPortLSOF(port int) (int, string, error) {
	// Use -Fp (pid) and -Fc (command) output fields
	out, err := exec.Command("lsof", "-nP", fmt.Sprintf("-iTCP:%d", port), "-Fp", "-Fc").Output()
	if err != nil {
		return 0, "", err
	}
	lines := strings.Split(string(out), "\n")
	var pid int
	var name string
	for _, line := range lines {
		if len(line) < 2 {
			continue
		}
		switch line[0] {
		case 'p':
			p, err := strconv.Atoi(strings.TrimSpace(line[1:]))
			if err == nil {
				pid = p
			}
		case 'c':
			name = strings.TrimSpace(line[1:])
		}
	}
	if pid > 0 {
		log.Printf("[PF] getPidByPort(lsof): port=%d pid=%d name=%q", port, pid, name)
		return pid, name, nil
	}
	return 0, "", fmt.Errorf("not found")
}

func getPidByPortLSOF(port int) (int, error) {
	pid, _, err := getPidAndNameByPortLSOF(port)
	return pid, err
}


var procPathCache sync.Map

func GetProcessNameByConn(conn interface{}) (string, int, error) {
	type remoteAddrIface interface {
		RemoteAddr() net.Addr
	}
	c, ok := conn.(remoteAddrIface)
	if !ok {
		return "", 0, fmt.Errorf("connection does not implement RemoteAddr")
	}

	remote, ok := c.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return "", 0, fmt.Errorf("remote address is not a TCP address")
	}

	pid, err := getPidByPort(remote.Port)
	if err != nil {
		log.Printf("[PF] GetProcessNameByConn: no pid for remote port=%d: %v", remote.Port, err)
		return "", 0, err
	}

	path, err := procPidPath(pid)
	log.Printf("[PF] GetProcessNameByConn: remote=%s pid=%d path=%q err=%v", remote, pid, path, err)
	return path, pid, err
}

func getProcessPathByPS(pid int) (string, error) {
	out, err := exec.Command("ps", "-p", strconv.Itoa(pid), "-o", "comm=").Output()
	if err != nil {
		return "", err
	}
	path := strings.TrimSpace(string(out))
	if path == "" {
		return "", fmt.Errorf("ps returned empty path for pid %d", pid)
	}
	return path, nil
}

func procPidPath(pid int) (string, error) {
	if val, ok := procPathCache.Load(pid); ok {
		return val.(string), nil
	}

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
	if int(ret) > 0 {
		n := bytes.IndexByte(buf, 0)
		if n < 0 {
			n = int(ret)
		}
		path := string(buf[:n])
		procPathCache.Store(pid, path)
		return path, nil
	}

	// Fallback to ps command
	path, err := getProcessPathByPS(pid)
	if err == nil {
		procPathCache.Store(pid, path)
		return path, nil
	}

	if errno != 0 {
		return "", errno
	}
	return "", fmt.Errorf("proc_pidpath: no result for pid %d", pid)
}

func GetProcessNameByPort(port int) (string, int, error) {
	pid, err := getPidByPort(port)
	if err != nil {
		return "", 0, err
	}
	path, err := procPidPath(pid)
	return path, pid, err
}

