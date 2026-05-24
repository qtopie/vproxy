//go:build linux && !android && integration
// +build linux,!android,integration

package ebpf

import (
	"fmt"
	"net"
	"os"
	"testing"
)

const testCgroupPath = "/sys/fs/cgroup/vproxy_test"

func TestMain(m *testing.M) {
	// Create a throwaway cgroup for integration tests.
	if err := os.MkdirAll(testCgroupPath, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "SKIP: cannot create test cgroup %s: %v\n", testCgroupPath, err)
		os.Exit(0) // skip gracefully if no permission
	}
	code := m.Run()
	os.RemoveAll(testCgroupPath)
	os.Exit(code)
}

// TestLoad_AttachAndUnload verifies the full BPF load → attach → unload cycle.
func TestLoad_AttachAndUnload(t *testing.T) {
	if !IsKernelSupported() {
		t.Skip("kernel < 5.7, eBPF cgroup hooks not available")
	}

	r, err := Load(testCgroupPath, 10080, 0xff)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	// All maps must be non-nil.
	if r.TCPOrigDst == nil {
		t.Error("TCPOrigDst map is nil")
	}
	if r.UDPOrigDst == nil {
		t.Error("UDPOrigDst map is nil")
	}
	if r.CidrBypassMap == nil {
		t.Error("CidrBypassMap is nil")
	}
	if r.ConfigMap == nil {
		t.Error("ConfigMap is nil")
	}

	if err := r.Unload(); err != nil {
		t.Errorf("Unload() error: %v", err)
	}
}

// TestCIDRManager_AddListRemove verifies CRUD on the LPM_TRIE bypass map.
func TestCIDRManager_AddListRemove(t *testing.T) {
	if !IsKernelSupported() {
		t.Skip("kernel < 5.7")
	}

	r, err := Load(testCgroupPath, 10080, 0xff)
	if err != nil {
		t.Fatalf("Load(): %v", err)
	}
	defer r.Unload()

	mgr := NewCIDRManager(r.CidrBypassMap)

	// AddDefaults should succeed.
	if err := mgr.AddDefaults(); err != nil {
		t.Fatalf("AddDefaults(): %v", err)
	}

	// List should contain the default entries.
	list, err := mgr.List()
	if err != nil {
		t.Fatalf("List(): %v", err)
	}
	want := map[string]bool{
		"127.0.0.0/8":   false,
		"10.0.0.0/8":    false,
		"172.16.0.0/12": false,
		"192.168.0.0/16": false,
		"169.254.0.0/16": false,
	}
	for _, cidr := range list {
		delete(want, cidr)
	}
	for cidr := range want {
		t.Errorf("expected CIDR %q not found in List()", cidr)
	}

	// Add a custom CIDR.
	if err := mgr.Add("100.64.0.0/10"); err != nil {
		t.Fatalf("Add(100.64.0.0/10): %v", err)
	}

	// Remove it.
	if err := mgr.Remove("100.64.0.0/10"); err != nil {
		t.Fatalf("Remove(100.64.0.0/10): %v", err)
	}
}

// TestUpdateConfig verifies that UpdateConfig writes to config_map without error.
func TestUpdateConfig(t *testing.T) {
	if !IsKernelSupported() {
		t.Skip("kernel < 5.7")
	}

	r, err := Load(testCgroupPath, 10080, 0xff)
	if err != nil {
		t.Fatalf("Load(): %v", err)
	}
	defer r.Unload()

	// Hot-update proxy port and bypass mark.
	if err := r.UpdateConfig(20080, 0xfe, true); err != nil {
		t.Errorf("UpdateConfig(): %v", err)
	}
}

// TestLookupTCPOrigDst_Miss verifies that a lookup for a non-existent cookie
// returns an error (not a panic).
func TestLookupTCPOrigDst_Miss(t *testing.T) {
	if !IsKernelSupported() {
		t.Skip("kernel < 5.7")
	}

	r, err := Load(testCgroupPath, 10080, 0xff)
	if err != nil {
		t.Fatalf("Load(): %v", err)
	}
	defer r.Unload()

	// Build a fake TCP connection — we just need to prove the call path
	// handles a map miss cleanly. We'll use a self-connected loopback pair
	// so SyscallConn() works.
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer ln.Close()

	connCh := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		connCh <- c
	}()

	client, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer client.Close()
	server := <-connCh
	defer server.Close()

	// The BPF hook was NOT active for this loopback connection, so there
	// is no entry in tcp_orig_dst. LookupTCPOrigDst should return an error.
	_, err = LookupTCPOrigDst(r.TCPOrigDst, server)
	if err == nil {
		t.Error("expected error for unknown cookie, got nil")
	}
}

// TestLoad_BadCgroup verifies that Load() returns an error (not panic) for
// a non-existent cgroup path.
func TestLoad_BadCgroup(t *testing.T) {
	_, err := Load("/nonexistent/cgroup/path", 10080, 0xff)
	if err == nil {
		t.Error("expected error for bad cgroup path, got nil")
	}
}
