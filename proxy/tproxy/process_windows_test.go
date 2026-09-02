//go:build windows
// +build windows

package tproxy

import (
	"net"
	"os"
	"strings"
	"testing"
)

type mockUDPConn struct {
	remote *net.UDPAddr
}

func (m *mockUDPConn) RemoteAddr() net.Addr {
	return m.remote
}

func TestWindows_CleanupRoutes(t *testing.T) {
	// Calling Cleanup() when winTunDevice is nil (e.g. from a CLI process)
	// should not panic and should cleanly attempt route deletion.
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Cleanup() panicked: %v", r)
		}
	}()
	Cleanup()
}

func TestWindows_GetProcessNameByUDPPort(t *testing.T) {
	// Bind a local UDP socket; this process owns the port.
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket failed: %v", err)
	}
	defer pc.Close()

	localAddr := pc.LocalAddr().(*net.UDPAddr)
	port := localAddr.Port

	pid, err := getPidByUDPPort(port)
	if err != nil {
		t.Fatalf("getPidByUDPPort(%d) failed: %v", port, err)
	}

	expectedPid := os.Getpid()
	if pid != expectedPid {
		t.Errorf("expected PID %d, got %d", expectedPid, pid)
	}

	path, foundPid, err := GetProcessNameByUDPPort(port)
	if err != nil {
		t.Fatalf("GetProcessNameByUDPPort(%d) failed: %v", port, err)
	}
	if foundPid != expectedPid {
		t.Errorf("expected PID %d, got %d", expectedPid, foundPid)
	}
	if path == "" {
		t.Errorf("expected non-empty process path for PID %d", expectedPid)
	}

	// Test GetProcessNameByConn with mock UDP connection
	mock := &mockUDPConn{remote: localAddr}
	connPath, connPid, err := GetProcessNameByConn(mock)
	if err != nil {
		t.Fatalf("GetProcessNameByConn failed for UDP: %v", err)
	}
	if connPid != expectedPid {
		t.Errorf("expected PID %d, got %d", expectedPid, connPid)
	}
	if !strings.EqualFold(connPath, path) {
		t.Errorf("expected path %s, got %s", path, connPath)
	}
}
