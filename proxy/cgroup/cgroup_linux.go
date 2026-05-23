//go:build linux
// +build linux

package cgroup

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	defaultCgroupPath = "/sys/fs/cgroup/vproxy"
)

// EnsureVProxyCgroup ensures that the vproxy cgroup exists and is owned by the current user.
func EnsureVProxyCgroup() error {
	// Try checking if it already exists and is writable first to avoid sudo
	fi, err := os.Stat(defaultCgroupPath)
	if err == nil && fi.IsDir() {
		testFile := filepath.Join(defaultCgroupPath, "cgroup.procs")
		f, err := os.OpenFile(testFile, os.O_WRONLY, 0)
		if err == nil {
			f.Close()
			return nil // Already exists and is writable by the current user! No sudo needed.
		}
	}

	user := os.Getenv("USER")
	if user == "" {
		user = "root"
	}

	cmds := []string{
		fmt.Sprintf("sudo mkdir -p %s", defaultCgroupPath),
		fmt.Sprintf("sudo chown -R %s %s", user, defaultCgroupPath),
	}

	for _, cmdStr := range cmds {
		if err := exec.Command("bash", "-c", cmdStr).Run(); err != nil {
			return fmt.Errorf("failed to run command '%s': %v", cmdStr, err)
		}
	}

	return nil
}

// MoveProcessToVProxyCgroup moves the given PID into the vproxy cgroup.
func MoveProcessToVProxyCgroup(pid int) error {
	procsFile := filepath.Join(defaultCgroupPath, "cgroup.procs")
	
	// Try direct write first
	err := os.WriteFile(procsFile, []byte(fmt.Sprintf("%d", pid)), 0644)
	if err == nil {
		return nil
	}

	// Fallback to sudo if permission denied
	cmd := fmt.Sprintf("echo %d | sudo tee %s > /dev/null", pid, procsFile)
	if err := exec.Command("bash", "-c", cmd).Run(); err != nil {
		return fmt.Errorf("failed to move pid %d to cgroup via sudo: %v", pid, err)
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
