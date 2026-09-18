//go:build linux
// +build linux

package tproxy

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLinuxProcessInspector_ResolveOwnSocket(t *testing.T) {
	// Start a local TCP listener to create a known socket owned by the current test process
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen on local TCP: %v", err)
	}
	defer ln.Close()

	port := ln.Addr().(*net.TCPAddr).Port

	// Resolve the process by port
	name, pid, err := GetProcessNameByPort(port)
	if err != nil {
		t.Logf("GetProcessNameByPort(%d) returned: %v (note: may require root or /proc access)", port, err)
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

func TestLinuxProcessInspector_Cache(t *testing.T) {
	cache := newProcCache(5 * time.Second)

	cache.Put(12345, 9999, "my-process")

	name, pid, ok := cache.Get(12345)
	if !ok {
		t.Fatal("expected cache hit")
	}
	if pid != 9999 || name != "my-process" {
		t.Fatalf("expected 9999 / my-process, got %d / %s", pid, name)
	}

	// Test non-existent entry
	_, _, ok = cache.Get(54321)
	if ok {
		t.Fatal("expected cache miss for non-existent port")
	}
}
