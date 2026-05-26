//go:build linux
// +build linux

package cgroup

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	defaultCgroupPath = "/sys/fs/cgroup/vproxy"
)

// EnsureVProxyCgroup ensures that the vproxy cgroup exists and is owned by the current user.
func EnsureVProxyCgroup() error {
	// Try checking if it already exists and is writable first
	fi, err := os.Stat(defaultCgroupPath)
	if err == nil && fi.IsDir() {
		testFile := filepath.Join(defaultCgroupPath, "cgroup.procs")
		f, err := os.OpenFile(testFile, os.O_WRONLY, 0)
		if err == nil {
			f.Close()
			return nil // Already exists and is writable!
		}
		return fmt.Errorf("cgroup directory exists but is not writable: %s. Run 'sudo vproxy init' to fix permissions", defaultCgroupPath)
	}

	return fmt.Errorf("cgroup directory does not exist: %s. Run 'sudo vproxy init' to initialize the environment", defaultCgroupPath)
}

// MoveProcessToVProxyCgroup moves the given PID into the vproxy cgroup.
func MoveProcessToVProxyCgroup(pid int) error {
	procsFile := filepath.Join(defaultCgroupPath, "cgroup.procs")
	
	// Direct write only
	err := os.WriteFile(procsFile, []byte(fmt.Sprintf("%d", pid)), 0644)
	if err != nil {
		return fmt.Errorf("failed to move pid %d to cgroup: %v. Ensure 'sudo vproxy init' was run", pid, err)
	}

	return nil
}

// IsProcessInVProxyCgroup checks if the current process is already in the vproxy cgroup.
func IsProcessInVProxyCgroup() bool {
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return false
	}
	return strings.Contains(string(data), "/vproxy")
}
