//go:build darwin
// +build darwin

package tproxy

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
)

// GetProcessNameByPort finds the process name associated with a local TCP/UDP port.
// On macOS, it uses the 'lsof' command.
func GetProcessNameByPort(port int) (string, error) {
	// lsof -nP -i :<port> -Fpcn
	// -n: inhibits the conversion of network numbers to host names.
	// -P: inhibits the conversion of port numbers to port names.
	// -i :<port>: select the IP files with the specified port.
	// -Fpcn: output format (p: PID, c: command name, n: network address)
	
	cmd := exec.Command("lsof", "-nP", "-i", fmt.Sprintf(":%d", port), "-Fpcn")
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}

	lines := strings.Split(string(out), "\n")
	var command string
	for _, line := range lines {
		if len(line) == 0 {
			continue
		}
		switch line[0] {
		case 'p':
			// pid = line[1:]
		case 'c':
			command = line[1:]
		case 'n':
			// Verify this is the correct entry if multiple exist
			if strings.Contains(line, fmt.Sprintf(":%d", port)) {
				if command != "" {
					return command, nil
				}
			}
		}
	}

	if command != "" {
		return command, nil
	}

	return "", fmt.Errorf("process not found for port %d", port)
}

// GetProcessNameByConn identifies the process associated with a net.Conn.
// This works for connections intercepted via gvisor on macOS.
func GetProcessNameByConn(conn interface{}) (string, error) {
	// In gvisor (gonet), we can get the remote address (which is the local address of the real app)
	type addr interface {
		RemoteAddr() net.Addr
	}
	
	if c, ok := conn.(interface{ RemoteAddr() net.Addr }); ok {
		ra := c.RemoteAddr()
		if tcpAddr, ok := ra.(*net.TCPAddr); ok {
			return GetProcessNameByPort(tcpAddr.Port)
		}
		if udpAddr, ok := ra.(*net.UDPAddr); ok {
			return GetProcessNameByPort(udpAddr.Port)
		}
	}
	return "", fmt.Errorf("could not determine source port from connection")
}
