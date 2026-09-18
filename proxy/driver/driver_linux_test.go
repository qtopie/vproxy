//go:build linux
// +build linux

package driver

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLinuxProcessInspector_DriverIntegration(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen on local TCP: %v", err)
	}
	defer ln.Close()

	port := ln.Addr().(*net.TCPAddr).Port

	inspector := NewProcessInspector()
	if inspector == nil {
		t.Fatal("expected non-nil inspector")
	}

	name, pid, err := inspector.GetProcessNameByPort(port)
	if err != nil {
		t.Logf("inspector.GetProcessNameByPort(%d) returned: %v", port, err)
		return
	}

	currentPID := os.Getpid()
	if pid != currentPID {
		t.Errorf("expected PID %d, got %d", currentPID, pid)
	}

	exePath, _ := os.Executable()
	expectedName := filepath.Base(exePath)
	if len(expectedName) > 15 {
		expectedName = expectedName[:15]
	}

	if !strings.HasPrefix(expectedName, name) && !strings.HasPrefix(name, expectedName) {
		t.Logf("Process comm '%s' (expected prefix of '%s')", name, expectedName)
	}
}
